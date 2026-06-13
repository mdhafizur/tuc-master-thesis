import * as vscode from 'vscode';
import { analyzeAndReportDiagnosticsFromText } from './diagnostic';
import { provideFixes, registerSecureFixCommands } from './actions';
import { getEnclosingFunction } from './functionExtractor';
import { showModelSelector, setSelectedModel, getCurrentModel, getAvailableModels } from './modelManager';
import { getContextualQnAWebviewContent } from './webview';
import {
    runSecurityAgent,
    runChat,
    applyProposedEdit,
    previewProposedEdit,
    AgentDiffContentProvider,
    ProposedEdit
} from './agent';
import { RAGManager } from './ragManager';
import { getAnalysisCache, disposeAnalysisCache } from './analysisCache';
import { WorkspaceScanner, WorkspaceSummary } from './workspaceScanner';
import { getDashboardHTML } from './dashboardWebview';
import { getKnowledgeBaseHTML, getVulnerabilityStatsHTML } from './knowledgeWebview';
import { getLogger } from './logger';

/**
 * Entry point: Called when the extension is activated.
 * Registers diagnostics, real-time and manual analysis commands, and quick fixes.
 *
 * @param context - The VS Code extension context.
 */
export function activate(context: vscode.ExtensionContext) {
    console.log('Code Guardian: activate() called');
    const logger = getLogger();
    logger.show(); // Force the output channel to be visible
    logger.success('Code Guardian Extension Activated');

    // Check if RAG is enabled in settings
    const config = vscode.workspace.getConfiguration('codeGuardian');
    const isRAGEnabled = config.get<boolean>('enableRAG', true);

    // Lazy initialization of RAG Manager - only created when first needed.
    // `ragInitPromise` lets command handlers await initialization so that the first
    // invocation uses RAG instead of silently falling back to undefined.
    let ragManager: RAGManager | undefined;
    let ragInitPromise: Promise<RAGManager | undefined> | undefined;

    /**
     * Initialize RAG Manager lazily. Returns a promise that resolves to the manager
     * once the vector store has loaded (or `undefined` if RAG is disabled or
     * initialization fails). Safe to call repeatedly — only the first call kicks
     * off construction; later calls return the in-flight or completed promise.
     */
    const initializeRAGIfNeeded = (): Promise<RAGManager | undefined> => {
        // Read the setting live so toggling at runtime takes effect without a reload.
        const enabled = vscode.workspace.getConfiguration('codeGuardian').get<boolean>('enableRAG', true);
        if (!enabled) {
            return Promise.resolve(undefined);
        }
        if (ragInitPromise) {
            return ragInitPromise;
        }

        logger.info('Lazy loading RAG Manager...');
        ragInitPromise = (async (): Promise<RAGManager | undefined> => {
            try {
                ragManager = new RAGManager(context);
                logger.success('RAG Manager initialized with security knowledge base');
                return ragManager;
            } catch (error) {
                logger.error('Failed to initialize RAG Manager', error);
                vscode.window.showWarningMessage('RAG Manager initialization failed. Using standard analysis mode.');
                return undefined;
            }
        })();
        return ragInitPromise;
    };

    if (isRAGEnabled) {
        logger.info('RAG enabled - initializing...');
        // Fire and forget at activation time. Command handlers that need RAG
        // await initializeRAGIfNeeded() to get the resolved manager.
        void initializeRAGIfNeeded();
    } else {
        logger.info('RAG disabled - using standard analysis mode');
    }

    // Create and manage diagnostics collection
    const diagnosticCollection = vscode.languages.createDiagnosticCollection('codeSecurity');
    context.subscriptions.push(diagnosticCollection);

    // Create status bar item to show RAG status
    const ragStatusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    ragStatusBar.command = 'codeSecurity.toggleRAG';
    ragStatusBar.tooltip = 'Click to toggle RAG (Retrieval-Augmented Generation) on/off';
    
    const updateStatusBar = () => {
        const currentRAGStatus = vscode.workspace.getConfiguration('codeGuardian').get<boolean>('enableRAG', true);
        ragStatusBar.text = currentRAGStatus ? '🧠 RAG: ON' : '📝 RAG: OFF';
        ragStatusBar.backgroundColor = currentRAGStatus ? undefined : new vscode.ThemeColor('statusBarItem.warningBackground');
    };
    
    updateStatusBar();
    ragStatusBar.show();
    context.subscriptions.push(ragStatusBar);

    /**
     * Applies a RAG enable/disable change live — no window reload needed. When
     * enabling, it (re)loads the knowledge base; when disabling, it drops the
     * manager so the analyzer falls back to standard mode immediately. All
     * analysis paths read the `ragManager` closure variable / initializeRAGIfNeeded
     * at call time, so updating them here is enough.
     */
    const applyRagSetting = async (enabled: boolean): Promise<void> => {
        if (enabled) {
            ragInitPromise = undefined; // allow re-initialization
            await vscode.window.withProgress(
                { location: vscode.ProgressLocation.Window, title: '🧠 Code Guardian: loading RAG knowledge base…' },
                () => initializeRAGIfNeeded()
            );
        } else {
            ragManager = undefined;
            ragInitPromise = undefined;
        }
        updateStatusBar();
    };

    /**
     * Real-time analysis: Analyze the function under cursor as the user types.
     * Uses debouncing AND per-document in-flight gating: while an Ollama call
     * is running for a given document, newer keystrokes only update the
     * "queued" snapshot. When the in-flight call completes, the latest queued
     * snapshot runs next. This prevents stacking parallel Ollama requests on
     * top of a serial GPU queue (which manifests as 30 s timeouts on later
     * passes).
     */
    let debounceTimer: NodeJS.Timeout | undefined;
    const DEBOUNCE_DELAY = 800; // milliseconds

    type QueuedSnapshot = { code: string; lineOffset: number };
    type DocAnalysisState = { inFlight: boolean; queued?: QueuedSnapshot };
    const docAnalysisStates = new Map<string, DocAnalysisState>();

    const runAnalysisLoop = async (doc: vscode.TextDocument, initial: QueuedSnapshot) => {
        const docKey = doc.uri.toString();
        let state = docAnalysisStates.get(docKey);
        if (!state) {
            state = { inFlight: false };
            docAnalysisStates.set(docKey, state);
        }
        if (state.inFlight) {
            // Coalesce: latest snapshot wins. The currently-running call will
            // pick this up when it finishes.
            state.queued = initial;
            return;
        }
        state.inFlight = true;
        try {
            let next: QueuedSnapshot | undefined = initial;
            while (next) {
                const current = next;
                await analyzeAndReportDiagnosticsFromText(
                    current.code,
                    doc,
                    diagnosticCollection,
                    current.lineOffset,
                    ragManager
                );
                next = state.queued;
                state.queued = undefined;
            }
        } finally {
            state.inFlight = false;
        }
    };

    const debouncedAnalysis = (doc: vscode.TextDocument, position: vscode.Position) => {
        if (debounceTimer) {
            clearTimeout(debounceTimer);
        }

        debounceTimer = setTimeout(() => {
            const funcCodeData = getEnclosingFunction(doc, position);

            if (funcCodeData && funcCodeData.code.length < 2000) {
                void runAnalysisLoop(doc, {
                    code: funcCodeData.code,
                    lineOffset: funcCodeData.startLine
                });
            } else {
                logger.warn('Skipping function analysis due to size or extraction failure.');
            }
        }, DEBOUNCE_DELAY);
    };

    const documentChangeListener = vscode.workspace.onDidChangeTextDocument(event => {
        const doc = event.document;

        if (!['javascript', 'typescript'].includes(doc.languageId)) { return; };

        const editor = vscode.window.activeTextEditor;
        if (!editor || editor.document !== doc) { return; };

        debouncedAnalysis(doc, editor.selection.active);
    });
    context.subscriptions.push(documentChangeListener);

    /**
     * Manual command: Analyze the full file from Command Palette.
     */
    const fullScanCommand = vscode.commands.registerCommand('codeSecurity.analyzeFullFile', async () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showWarningMessage('Open a file to analyze.');
            return;
        }

        const doc = editor.document;
        if (doc.languageId !== 'javascript' && doc.languageId !== 'typescript') {
            vscode.window.showWarningMessage('Code Guardian analyzes JavaScript and TypeScript files.');
            return;
        }

        const fullText = doc.getText();
        if (!fullText.trim()) {
            vscode.window.showWarningMessage('The file is empty.');
            return;
        }
        if (fullText.length > 20000) {
            vscode.window.showWarningMessage('File too large for full security analysis (limit 20,000 characters). Try analyzing a selection instead.');
            return;
        }

        await vscode.window.withProgress(
            {
                location: vscode.ProgressLocation.Notification,
                title: '🔍 Code Guardian: analyzing full file for security issues…',
                cancellable: false
            },
            async () => {
                try {
                    const count = await analyzeAndReportDiagnosticsFromText(
                        fullText, doc, diagnosticCollection, 0, ragManager, 'file'
                    );
                    if (count > 0) {
                        vscode.window.showWarningMessage(`🛡️ Code Guardian found ${count} potential security issue${count === 1 ? '' : 's'} in ${doc.fileName.split(/[/\\]/).pop()}.`);
                    } else {
                        vscode.window.showInformationMessage('✅ Code Guardian found no security issues in this file.');
                    }
                } catch (err) {
                    logger.error('Full-file analysis failed', err);
                    vscode.window.showErrorMessage(`Code Guardian analysis failed: ${err instanceof Error ? err.message : String(err)}`);
                }
            }
        );
    });
    context.subscriptions.push(fullScanCommand);

    /**
     * Code Actions: Register quick fixes for known issues.
     */
    const codeActionProvider = provideFixes();
    context.subscriptions.push(
        vscode.languages.registerCodeActionsProvider(
            ['javascript', 'typescript'],
            codeActionProvider,
            { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }
        )
    );

    // Phase 5: Register the secure-fix apply + preview commands and the
    // ephemeral diff content provider. The lazy repair path needs access to
    // the same lazily-initialized RAG manager the analyzer uses.
    registerSecureFixCommands(context, initializeRAGIfNeeded);

    /**
     * Manual command: Analyze selected text or current line using LLM (AI).
     */
    const selectionAnalysisCommand = vscode.commands.registerCommand('codeSecurity.analyzeSelectionWithAI', async () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor) { return; };

        const selection = editor.selection;
        let selectedText = editor.document.getText(selection).trim();

        // Fallback to current line if selection is empty
        if (selectedText === "") {
            selectedText = editor.document.lineAt(selection.active.line).text.trim();
        }

        if (!selectedText) {
            vscode.window.showWarningMessage('No code selected or found on current line.');
            return;
        }

        // Reuse the security chat: open the panel seeded with this file as context
        // and an initial question scoped to the selected lines, then auto-run it.
        const startLine = selection.start.line + 1;
        const endLine = (selectedText && !selection.isEmpty) ? selection.end.line + 1 : selection.active.line + 1;
        const filePath = editor.document.uri.fsPath;
        const question = `Analyze lines ${startLine}-${endLine} of ${editor.document.fileName.split(/[/\\]/).pop()} for security vulnerabilities and propose fixes:\n\n\`\`\`${editor.document.languageId}\n${selectedText}\n\`\`\``;

        openSecurityChat({
            initialContext: editor.document.uri.scheme === 'file' ? [filePath] : [],
            initialQuestion: question,
            autoSend: true
        });
    });
    context.subscriptions.push(selectionAnalysisCommand);

    /**
     * Manual command: Model selection interface
     */
    const modelSelectorCommand = vscode.commands.registerCommand('codeSecurity.selectModel', async () => {
        const currentModel = getCurrentModel();
        vscode.window.showInformationMessage(`Current model: ${currentModel}`);

        const modelSelection = await showModelSelector();
        if (modelSelection) {
            await setSelectedModel(modelSelection.model, modelSelection.isCustom);
            vscode.window.showInformationMessage(`Model changed to: ${modelSelection.model}`);
        }
    });
    context.subscriptions.push(modelSelectorCommand);

    /**
     * Manual command: Apply secure code fix from diagnostics
     */
    const applyFixCommand = vscode.commands.registerCommand('codeSecurity.applyFix', async (uri?: vscode.Uri, range?: vscode.Range, fix?: string) => {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showErrorMessage('No active editor found');
            return;
        }

        // If called from diagnostic, try to get the fix suggestion
        if (!fix) {
            // Try to find fix from diagnostics at current cursor position
            const diagnostics = vscode.languages.getDiagnostics(editor.document.uri);
            const position = editor.selection.active;

            const relevantDiagnostic = diagnostics.find(diag =>
                diag.source === 'CodeGuardian' &&
                diag.range.contains(position) &&
                diag.relatedInformation &&
                diag.relatedInformation.length > 0
            );

            if (relevantDiagnostic && relevantDiagnostic.relatedInformation) {
                fix = relevantDiagnostic.relatedInformation[0].message;
                range = relevantDiagnostic.range;
            }
        }

        if (!fix) {
            vscode.window.showErrorMessage('No fix suggestion available for this location');
            return;
        }

        // Show the fix to user and ask for confirmation
        const applyFix = await vscode.window.showInformationMessage(
            `Apply this fix?\n\n${fix}`,
            { modal: true },
            'Apply Fix',
            'Cancel'
        );

        if (applyFix === 'Apply Fix' && range) {
            // Apply the fix by replacing the problematic code
            const edit = new vscode.WorkspaceEdit();
            edit.replace(editor.document.uri, range, fix);

            const success = await vscode.workspace.applyEdit(edit);
            if (success) {
                vscode.window.showInformationMessage('✅ Security fix applied successfully!');
            } else {
                vscode.window.showErrorMessage('❌ Failed to apply fix');
            }
        }
    });
    context.subscriptions.push(applyFixCommand);

    /**
     * Manual command: Contextual Q&A webview for codebase/folder/file questions.
     */
    // Shared diff provider backing the agent's "Preview fix" previews (registered once).
    const agentDiffProvider = new AgentDiffContentProvider();
    context.subscriptions.push(
        vscode.workspace.registerTextDocumentContentProvider(AgentDiffContentProvider.scheme, agentDiffProvider)
    );

    /**
     * Opens the Code Guardian security chat (the agentic Contextual Q&A panel).
     * Shared by the "Contextual Q&A" and "Analyze Selection" commands. Optionally
     * seeds the panel with starting context and an initial question to auto-run.
     */
    function openSecurityChat(seed?: { initialContext?: string[]; initialQuestion?: string; autoSend?: boolean }) {
        const currentModel = getCurrentModel();

        const panel = vscode.window.createWebviewPanel(
            'codeSecurityContextualQnA',
            '🛡️ Code Guardian: Security Assistant',
            vscode.ViewColumn.Beside,
            {
                enableScripts: true,
                retainContextWhenHidden: true,
                localResourceRoots: [vscode.Uri.joinPath(context.extensionUri, 'media')]
            }
        );

        // Track active model for this session
        let activeModel = currentModel;

        // Edits the agent has proposed this session, keyed by id, so the webview's
        // Apply/Preview buttons can act on them.
        const sessionEdits = new Map<string, ProposedEdit>();

        // Running conversation so follow-up questions keep their context.
        const conversationHistory: { role: string; content: string }[] = [];
        let turnCounter = 0;

        // Initial HTML for the webview
        panel.webview.html = getContextualQnAWebviewContent(panel, context, activeModel);

        // Listen for messages from the webview (file/folder selection, questions)
        panel.webview.onDidReceiveMessage(async (message) => {
            logger.info('Received message from webview:', message);
            if (message.type === 'webviewReady') {
                // The webview is initialized; deliver any seed (context + question).
                if (seed && (seed.initialContext?.length || seed.initialQuestion)) {
                    panel.webview.postMessage({
                        type: 'seed',
                        context: seed.initialContext ?? [],
                        question: seed.initialQuestion ?? '',
                        autoSend: Boolean(seed.autoSend)
                    });
                }
            } else if (message.type === 'selectContext') {
                logger.info('Processing selectContext message');
                // Show file/folder picker and send result back
                let uris = await vscode.window.showOpenDialog({
                    canSelectFiles: true,
                    canSelectFolders: true,
                    canSelectMany: true,
                    openLabel: 'Add as Context'
                });
                logger.info('Selected URIs:', uris);
                if (uris) {
                    panel.webview.postMessage({ type: 'contextSelected', uris: uris.map(u => u.fsPath) });
                }
            } else if (message.type === 'modelChanged') {
                // Update the active model when user selects a different one
                activeModel = message.model;
            } else if (message.type === 'refreshModels') {
                // Refresh available models list
                try {
                    const availableModels = await getAvailableModels();
                    const modelOptions = availableModels.map(model => ({
                        name: model.name,
                        description: `Size: ${(model.size / (1024 * 1024 * 1024)).toFixed(1)} GB`
                    }));

                    panel.webview.postMessage({
                        type: 'modelsUpdated',
                        models: modelOptions
                    });
                } catch (error) {
                    vscode.window.showErrorMessage(`Failed to refresh models: ${error}`);
                }
            } else if (message.type === 'askQuestion') {
                // Drive the agentic loop: the model reads/searches the workspace on
                // demand and may propose fixes, instead of stuffing pre-read files
                // into a single prompt.
                const contextUris: string[] = message.context || [];
                const requestedModel = message.model || activeModel;
                if (requestedModel !== activeModel) {
                    activeModel = requestedModel;
                }

                const question = (message.question || '').trim()
                    || 'Perform a comprehensive security analysis of the selected context and propose fixes for the issues you find.';

                turnCounter++;

                // Route the turn by INTENT, not by whether context is attached:
                // a message asking for analysis/detection/review/fix runs the agentic
                // loop; anything else (e.g. "how are you") is a plain conversation.
                // The webview can force a mode via message.mode (chat | analyze).
                const analysisIntent = /\b(analy[sz]e?|analysis|scan|detect|inspect|audit|review|vulnerab|exploit|injection|xss|csrf|ssrf|insecure|sanitiz|hardcoded|secret|\bcwe\b|fix|patch|repair|remediat|harden|secure this)\b/i;
                const useAgent = message.mode === 'analyze'
                    || (message.mode !== 'chat' && analysisIntent.test(question));

                try {
                    const ragManager = await initializeRAGIfNeeded();

                    let answer: string;
                    let wireEdits: object[] = [];

                    if (useAgent) {
                        const result = await runSecurityAgent(
                            question,
                            contextUris,
                            activeModel,
                            ragManager,
                            (step) => panel.webview.postMessage({ type: 'agentStep', step }),
                            conversationHistory
                        );
                        answer = result.answer;
                        // Re-key edits with session-unique ids (the agent numbers them
                        // per-run, which would collide across turns) and store them.
                        wireEdits = result.edits.map((e, i) => {
                            e.id = `t${turnCounter}-e${i}`;
                            sessionEdits.set(e.id, e);
                            return {
                                id: e.id,
                                relativePath: e.relativePath,
                                startLine: e.startLine,
                                endLine: e.endLine,
                                description: e.description,
                                applicable: e.applicable,
                                notApplicableReason: e.notApplicableReason
                            };
                        });
                    } else {
                        // Plain conversational reply — no tools, no investigation.
                        answer = await runChat(question, activeModel, ragManager, conversationHistory);
                    }

                    // Keep the conversation context bounded to the last few turns.
                    conversationHistory.push({ role: 'user', content: question });
                    conversationHistory.push({ role: 'assistant', content: answer });
                    while (conversationHistory.length > 8) {
                        conversationHistory.shift();
                    }

                    panel.webview.postMessage({
                        type: 'answer',
                        answer,
                        edits: wireEdits
                    });
                } catch (err) {
                    logger.error('Contextual Q&A turn failed', err);
                    panel.webview.postMessage({
                        type: 'answer',
                        answer: `Error running the security assistant with model ${activeModel}: ${err instanceof Error ? err.message : String(err)}`,
                        edits: []
                    });
                }
            } else if (message.type === 'previewEdit') {
                const edit = sessionEdits.get(message.editId);
                if (!edit) {
                    vscode.window.showWarningMessage('That proposed edit is no longer available.');
                    return;
                }
                try {
                    await previewProposedEdit(edit, agentDiffProvider);
                } catch (err) {
                    vscode.window.showErrorMessage(`Could not preview the fix: ${err instanceof Error ? err.message : String(err)}`);
                }
            } else if (message.type === 'applyEdit') {
                const edit = sessionEdits.get(message.editId);
                if (!edit) {
                    vscode.window.showWarningMessage('That proposed edit is no longer available.');
                    return;
                }
                const confirm = await vscode.window.showWarningMessage(
                    `Apply fix to ${edit.relativePath} (lines ${edit.startLine}-${edit.endLine})?`,
                    { modal: true },
                    'Apply'
                );
                if (confirm !== 'Apply') {
                    return;
                }
                try {
                    const ok = await applyProposedEdit(edit);
                    panel.webview.postMessage({ type: 'editApplied', editId: edit.id, ok });
                    if (ok) {
                        vscode.window.showInformationMessage(`Applied fix to ${edit.relativePath}.`);
                    } else {
                        vscode.window.showWarningMessage('The workspace rejected the edit. Is the file writable?');
                    }
                } catch (err) {
                    vscode.window.showErrorMessage(`Could not apply the fix: ${err instanceof Error ? err.message : String(err)}`);
                }
            }
        });
    }

    context.subscriptions.push(
        vscode.commands.registerCommand('codeSecurity.contextualQnA', () => openSecurityChat())
    );

    /**
     * Manual command: RAG Knowledge Management
     */
    const ragManagementCommand = vscode.commands.registerCommand('codeSecurity.manageRAG', async () => {
        // Check if RAG is enabled
        if (!ragManager) {
            const enableRAG = await vscode.window.showInformationMessage(
                'RAG (Retrieval-Augmented Generation) is currently disabled. Would you like to enable it?',
                'Enable RAG',
                'Open Settings',
                'Cancel'
            );
            
            if (enableRAG === 'Enable RAG') {
                await vscode.workspace.getConfiguration('codeGuardian').update('enableRAG', true, vscode.ConfigurationTarget.Global);
                vscode.window.showInformationMessage('🧠 RAG enabled. Loading the knowledge base…');
                return;
            } else if (enableRAG === 'Open Settings') {
                vscode.commands.executeCommand('workbench.action.openSettings', 'codeGuardian.enableRAG');
                return;
            }
            return;
        }

        const entryCount = ragManager.getKnowledgeBase().length;
        const ragOn = vscode.workspace.getConfiguration('codeGuardian').get<boolean>('enableRAG', true);

        interface RagMenuItem extends vscode.QuickPickItem { id: string; }
        const menuItems: RagMenuItem[] = [
            { id: 'view', label: '$(book) View Knowledge Base', description: `${entryCount} entries`, detail: 'Browse and search the security knowledge corpus' },
            { id: 'search', label: '$(search) Search Knowledge', detail: 'Semantic vector search across the knowledge base' },
            { id: 'add', label: '$(add) Add Security Knowledge', detail: 'Add a custom entry to the knowledge base' },
            { id: 'rebuild', label: '$(sync) Rebuild Vector Store', detail: 'Re-embed and rebuild the HNSW index' },
            { id: 'update', label: '$(cloud-download) Update Vulnerability Data', detail: 'Refresh from CWE, OWASP, CVE, and npm sources' },
            { id: 'stats', label: '$(graph) View Vulnerability Stats', detail: 'Corpus size, last update, and cache status' },
            { id: 'clear', label: '$(trash) Clear Vulnerability Cache', detail: 'Delete cached vulnerability data' },
            { id: 'toggle', label: `$(circle-${ragOn ? 'large-filled' : 'large-outline'}) Toggle RAG ${ragOn ? 'Off' : 'On'}`, description: ragOn ? 'currently ON' : 'currently OFF', detail: 'Enable or disable retrieval-augmented analysis' }
        ];

        const picked = await vscode.window.showQuickPick(menuItems, {
            title: '🧠 Manage RAG Knowledge Base',
            placeHolder: 'Select a knowledge-base action'
        });

        switch (picked?.id) {
            case 'toggle': {
                const liveStatus = vscode.workspace.getConfiguration('codeGuardian').get<boolean>('enableRAG', true);
                const currentStatus = liveStatus ? 'enabled' : 'disabled';
                const newStatus = !liveStatus;
                const action = newStatus ? 'enable' : 'disable';

                const confirm = await vscode.window.showInformationMessage(
                    `RAG is currently ${currentStatus}. Do you want to ${action} it?`,
                    `${action.charAt(0).toUpperCase() + action.slice(1)} RAG`,
                    'Cancel'
                );

                if (confirm?.includes('RAG')) {
                    // The configuration listener applies this live — no reload needed.
                    await vscode.workspace.getConfiguration('codeGuardian').update('enableRAG', newStatus, vscode.ConfigurationTarget.Global);
                    vscode.window.showInformationMessage(`🧠 RAG ${action}d.`);
                }
                break;
            }

            case 'view': {
                const knowledge = ragManager.getKnowledgeBase();
                const kbPanel = vscode.window.createWebviewPanel(
                    'codeGuardianKnowledgeBase',
                    '🧠 RAG Knowledge Base',
                    vscode.ViewColumn.Active,
                    { enableScripts: true, retainContextWhenHidden: true }
                );
                kbPanel.webview.html = getKnowledgeBaseHTML(knowledge);
                break;
            }

            case 'add':
                const addTitle = 'Add Security Knowledge';
                const title = await vscode.window.showInputBox({
                    title: `${addTitle} (1/5) — Title`,
                    prompt: 'Enter security knowledge title',
                    placeHolder: 'e.g., "CSRF Prevention Techniques"',
                    ignoreFocusOut: true
                });

                if (!title) {
                    return;
                }

                const content = await vscode.window.showInputBox({
                    title: `${addTitle} (2/5) — Content`,
                    prompt: 'Enter security knowledge content',
                    placeHolder: 'Detailed explanation and prevention techniques...',
                    ignoreFocusOut: true
                });

                if (!content) {
                    return;
                }

                const category = await vscode.window.showQuickPick([
                    'injection', 'cryptography', 'authentication', 'authorization',
                    'path-traversal', 'configuration', 'business-logic', 'other'
                ], { title: `${addTitle} (3/5) — Category`, placeHolder: 'Select category', ignoreFocusOut: true });

                if (!category) {
                    return;
                }

                const severity = await vscode.window.showQuickPick([
                    'high', 'medium', 'low'
                ], { title: `${addTitle} (4/5) — Severity`, placeHolder: 'Select severity level', ignoreFocusOut: true });

                if (!severity) {
                    return;
                }

                const tags = await vscode.window.showInputBox({
                    title: `${addTitle} (5/5) — Tags`,
                    prompt: 'Enter tags (comma-separated)',
                    placeHolder: 'csrf, web-security, token',
                    ignoreFocusOut: true
                });

                try {
                    await ragManager.addSecurityKnowledge({
                        id: `custom-${Date.now()}`,
                        title,
                        content,
                        category,
                        severity: severity as 'high' | 'medium' | 'low',
                        tags: tags ? tags.split(',').map(t => t.trim()) : []
                    });
                    
                    vscode.window.showInformationMessage('✅ Security knowledge added successfully!');
                } catch (error) {
                    vscode.window.showErrorMessage(`❌ Failed to add knowledge: ${error}`);
                }
                break;

            case 'rebuild': {
                const rag = ragManager;
                await vscode.window.withProgress(
                    { location: vscode.ProgressLocation.Notification, title: '🧠 Code Guardian: rebuilding vector store…', cancellable: false },
                    async () => {
                        try {
                            await rag.rebuildVectorStore();
                            vscode.window.showInformationMessage('✅ Vector store rebuilt.');
                        } catch (error) {
                            vscode.window.showErrorMessage(`❌ Failed to rebuild vector store: ${error}`);
                        }
                    }
                );
                break;
            }

            case 'search': {
                const searchQuery = await vscode.window.showInputBox({
                    title: 'Search Knowledge Base',
                    prompt: 'Enter a search query',
                    placeHolder: 'e.g., "XSS prevention", "SQL injection", "crypto"',
                    ignoreFocusOut: true
                });

                if (!searchQuery) {
                    return;
                }

                try {
                    const rag = ragManager;
                    const results = await vscode.window.withProgress(
                        { location: vscode.ProgressLocation.Window, title: '🔎 Searching knowledge base…' },
                        () => rag.searchRelevantKnowledge(searchQuery, 10)
                    );

                    if (results.length === 0) {
                        vscode.window.showInformationMessage(`No relevant knowledge found for "${searchQuery}".`);
                        return;
                    }

                    // Map the retrieved chunks into the knowledge-card shape and reuse
                    // the scrollable webview used by "View Knowledge Base".
                    const mapped = results.map((doc, i) => {
                        const m = doc.metadata || {};
                        const tags = Array.isArray(m.tags) ? m.tags : (typeof m.tags === 'string' ? m.tags.split(',').map((t: string) => t.trim()) : []);
                        return {
                            id: String(m.id || `result-${i + 1}`),
                            title: String(m.title || 'Untitled'),
                            content: doc.pageContent || '',
                            category: String(m.category || 'general'),
                            severity: (m.severity === 'high' || m.severity === 'medium' || m.severity === 'low') ? m.severity : 'low',
                            cwe: m.cwe ? String(m.cwe) : undefined,
                            owasp: m.owasp ? String(m.owasp) : undefined,
                            tags
                        };
                    });

                    const searchPanel = vscode.window.createWebviewPanel(
                        'codeGuardianKnowledgeSearch',
                        '🔎 Knowledge Search',
                        vscode.ViewColumn.Active,
                        { enableScripts: true, retainContextWhenHidden: true }
                    );
                    searchPanel.webview.html = getKnowledgeBaseHTML(mapped, {
                        heading: 'Search Results',
                        icon: '🔎',
                        noun: 'results',
                        note: `for "${searchQuery}"`
                    });
                } catch (error) {
                    vscode.window.showErrorMessage(`❌ Search failed: ${error}`);
                }
                break;
            }

            case 'update':
                const updateChoice = await vscode.window.showQuickPick([
                    'Update All Sources',
                    'Update CWE Data Only',
                    'Update OWASP Top 10 Only',
                    'Update Latest CVEs Only',
                    'Update JavaScript Vulnerabilities Only'
                ], { title: 'Update Vulnerability Data', placeHolder: 'Select data source to update', ignoreFocusOut: true });

                if (!updateChoice) {
                    return;
                }

                const progress = await vscode.window.withProgress({
                    location: vscode.ProgressLocation.Notification,
                    title: 'Updating vulnerability data...',
                    cancellable: false
                }, async (progress) => {
                    try {
                        if (!ragManager) {
                            vscode.window.showErrorMessage('RAG Manager not initialized');
                            return;
                        }

                        progress.report({ message: 'Fetching latest vulnerability data...' });

                        const result = await ragManager.updateKnowledgeBaseWithLatestVulnerabilities();
                        
                        const successMsg = `✅ Vulnerability data updated!\n` +
                            `Added: ${result.added} new entries\n` +
                            `Updated: ${result.updated} existing entries`;
                            
                        if (result.errors.length > 0) {
                            const errorMsg = `⚠️ Some errors occurred:\n${result.errors.slice(0, 3).join('\n')}`;
                            vscode.window.showWarningMessage(`${successMsg}\n\n${errorMsg}`);
                        } else {
                            vscode.window.showInformationMessage(successMsg);
                        }
                    } catch (error) {
                        vscode.window.showErrorMessage(`❌ Failed to update vulnerability data: ${error}`);
                    }
                });
                break;

            case 'stats':
                try {
                    const stats = await ragManager.getVulnerabilityDataStats();
                    const statsPanel = vscode.window.createWebviewPanel(
                        'codeGuardianVulnStats',
                        '📊 Vulnerability Data Statistics',
                        vscode.ViewColumn.Active,
                        { enableScripts: true, retainContextWhenHidden: true }
                    );
                    statsPanel.webview.html = getVulnerabilityStatsHTML(stats);
                } catch (error) {
                    vscode.window.showErrorMessage(`❌ Failed to get vulnerability stats: ${error}`);
                }
                break;

            case 'clear':
                const confirmClear = await vscode.window.showWarningMessage(
                    'This will clear all cached vulnerability data. Fresh data will be downloaded on next update.',
                    { modal: true },
                    'Clear Cache'
                );

                if (confirmClear === 'Clear Cache') {
                    try {
                        await ragManager.clearVulnerabilityCache();
                        vscode.window.showInformationMessage('✅ Vulnerability cache cleared.');
                    } catch (error) {
                        vscode.window.showErrorMessage(`❌ Failed to clear cache: ${error}`);
                    }
                }
                break;
        }
    });
    context.subscriptions.push(ragManagementCommand);

    /**
     * Manual command: Quick RAG Toggle
     */
    const ragToggleCommand = vscode.commands.registerCommand('codeSecurity.toggleRAG', async () => {
        const currentConfig = vscode.workspace.getConfiguration('codeGuardian');
        const currentRAGStatus = currentConfig.get<boolean>('enableRAG', true);
        const newStatus = !currentRAGStatus;
        const action = newStatus ? 'enabled' : 'disabled';
        
        // Updating the setting fires the configuration listener below, which
        // applies the change live (loads/drops the RAG manager). No reload needed.
        await currentConfig.update('enableRAG', newStatus, vscode.ConfigurationTarget.Global);
        vscode.window.showInformationMessage(`🧠 RAG ${action}.`);
    });
    context.subscriptions.push(ragToggleCommand);

    /**
     * Manual command: Update Vulnerability Data
     */
    const updateVulnDataCommand = vscode.commands.registerCommand('codeSecurity.updateVulnerabilityData', async () => {
        if (!ragManager) {
            vscode.window.showWarningMessage('RAG is disabled. Enable RAG to use vulnerability data features.');
            return;
        }

        await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: 'Syncing from dynamic sources...',
            cancellable: false
        }, async (progress) => {
            try {
                if (!ragManager) {
                    vscode.window.showErrorMessage('RAG Manager not initialized. Please enable RAG in settings.');
                    return;
                }

                progress.report({ message: 'Fetching from NVD, OWASP, CWE, GitHub, and npm sources...' });

                // Use the new syncFromDynamicSources method
                const result = await ragManager.syncFromDynamicSources();

                progress.report({ message: 'Rebuilding vector store...' });

                if (result.success) {
                    const successMsg = `✅ Vulnerability Knowledge Base Synced!\n\n` +
                        `📊 Source Breakdown:\n` +
                        `   • CWE: ${result.sources.cwe} entries\n` +
                        `   • OWASP Top 10: ${result.sources.owasp} entries\n` +
                        `   • CVEs (NVD): ${result.sources.cves} entries\n` +
                        `   • JavaScript/npm: ${result.sources.javascript} entries\n` +
                        `   • OWASP Cheat Sheets: ${result.sources.cheatsheets} entries\n` +
                        `   • CAPEC Attack Patterns: ${result.sources.capec} entries\n` +
                        `   • Node.js/Express: ${result.sources.nodejs} entries\n\n` +
                        `📈 Changes:\n` +
                        `   • Added: ${result.added} new entries\n` +
                        `   • Updated: ${result.updated} existing entries\n` +
                        `   • Total: ${result.total} entries in knowledge base`;

                    vscode.window.showInformationMessage(successMsg, { modal: true });

                    // Show follow-up actions
                    const action = await vscode.window.showInformationMessage(
                        'Vulnerability data synced successfully! What would you like to do next?',
                        'View Stats',
                        'Analyze Code',
                        'Done'
                    );

                    if (action === 'View Stats') {
                        vscode.commands.executeCommand('codeSecurity.manageRAG');
                    } else if (action === 'Analyze Code') {
                        vscode.commands.executeCommand('codeSecurity.analyzeSelectionWithAI');
                    }
                } else {
                    const errorMsg = `❌ Sync Failed!\n\n` +
                        `Error: ${result.error}\n\n` +
                        `Current knowledge base has ${result.total} entries (no changes made).`;

                    vscode.window.showErrorMessage(errorMsg, { modal: true });
                }

            } catch (error) {
                vscode.window.showErrorMessage(`❌ Failed to sync vulnerability data: ${error}`);
                logger.error('Vulnerability data sync failed:', error);
            }
        });
    });
    context.subscriptions.push(updateVulnDataCommand);

    /**
     * Configuration change listener to handle RAG enable/disable
     */
    const configChangeListener = vscode.workspace.onDidChangeConfiguration(event => {
        if (event.affectsConfiguration('codeGuardian.enableRAG')) {
            const newRAGStatus = vscode.workspace.getConfiguration('codeGuardian').get<boolean>('enableRAG', true);
            // Apply live — loads or drops the RAG manager without a window reload.
            void applyRagSetting(newRAGStatus);
        }
    });
    context.subscriptions.push(configChangeListener);

    /**
     * Command: View cache statistics
     */
    const viewCacheStatsCommand = vscode.commands.registerCommand('codeSecurity.viewCacheStats', () => {
        const cache = getAnalysisCache();
        const stats = cache.getStats();

        const message = `📊 Analysis Cache Statistics\n\n` +
            `Cache Size: ${stats.size}/${stats.maxSize}\n` +
            `Utilization: ${stats.utilizationRate}\n` +
            `Cache Hits: ${stats.hits}\n` +
            `Cache Misses: ${stats.misses}\n` +
            `Hit Rate: ${stats.hitRate}\n` +
            `Evictions: ${stats.evictions}\n\n` +
            `💡 Cache reduces redundant LLM calls for unchanged code.`;

        vscode.window.showInformationMessage(message, { modal: true }, 'Clear Cache', 'Reset Stats').then(selection => {
            if (selection === 'Clear Cache') {
                cache.clear();
                vscode.window.showInformationMessage('✅ Cache cleared successfully!');
            } else if (selection === 'Reset Stats') {
                cache.resetStats();
                vscode.window.showInformationMessage('✅ Cache statistics reset!');
            }
        });
    });
    context.subscriptions.push(viewCacheStatsCommand);

    /**
     * Command: Workspace Security Dashboard
     */
    const workspaceDashboardCommand = vscode.commands.registerCommand('codeSecurity.workspaceDashboard', async () => {
        const scanner = new WorkspaceScanner(context, ragManager);

        // Show progress
        await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: 'Scanning workspace for security issues...',
            cancellable: true
        }, async (progress, token) => {
            token.onCancellationRequested(() => {
                scanner.abortScan();
            });

            const summary = await scanner.scanWorkspace((current, total, message) => {
                progress.report({
                    message: `${current}/${total} files`,
                    increment: (1 / total) * 100
                });
            });

            if (!summary) {
                return;
            }

            // Calculate security score
            const securityScore = scanner.calculateSecurityScore(summary);
            const securityGrade = scanner.getSecurityGrade(securityScore);

            // Create dashboard webview
            const panel = vscode.window.createWebviewPanel(
                'securityDashboard',
                '🔐 Security Dashboard',
                vscode.ViewColumn.One,
                {
                    enableScripts: true,
                    retainContextWhenHidden: true
                }
            );

            panel.webview.html = getDashboardHTML(panel, context, summary, securityScore, securityGrade);

            // Handle messages from webview
            panel.webview.onDidReceiveMessage(async (message) => {
                switch (message.type) {
                    case 'rescan':
                        vscode.commands.executeCommand('codeSecurity.workspaceDashboard');
                        panel.dispose();
                        break;
                    case 'export':
                        await exportDashboardReport(summary, securityScore, securityGrade);
                        break;
                    case 'openFile':
                        const doc = await vscode.workspace.openTextDocument(message.filePath);
                        await vscode.window.showTextDocument(doc);
                        break;
                }
            });
        });
    });
    context.subscriptions.push(workspaceDashboardCommand);
}

/**
 * Exports the workspace security scan as a Markdown or JSON report.
 * Lets the user pick a format, choose a destination via the save dialog,
 * writes the file, and offers to open it.
 */
async function exportDashboardReport(
    summary: WorkspaceSummary,
    securityScore: number,
    securityGrade: string
): Promise<void> {
    const logger = getLogger();

    const format = await vscode.window.showQuickPick(
        [
            { label: '$(markdown) Markdown (.md)', value: 'md' as const, description: 'Human-readable report' },
            { label: '$(json) JSON (.json)', value: 'json' as const, description: 'Machine-readable, full finding data' }
        ],
        { placeHolder: 'Choose the export format for the security report' }
    );

    if (!format) {
        return; // user cancelled
    }

    const timestamp = new Date();
    const fileStamp = timestamp.toISOString().slice(0, 19).replace(/[:T]/g, '-');
    const defaultName = `code-guardian-report-${fileStamp}.${format.value}`;
    const workspaceFolder = vscode.workspace.workspaceFolders?.[0]?.uri;
    const defaultUri = workspaceFolder
        ? vscode.Uri.joinPath(workspaceFolder, defaultName)
        : vscode.Uri.file(defaultName);

    const targetUri = await vscode.window.showSaveDialog({
        defaultUri,
        filters: format.value === 'md'
            ? { 'Markdown': ['md'] }
            : { 'JSON': ['json'] },
        saveLabel: 'Export Report'
    });

    if (!targetUri) {
        return; // user cancelled
    }

    const content = format.value === 'md'
        ? buildMarkdownReport(summary, securityScore, securityGrade, timestamp)
        : buildJsonReport(summary, securityScore, securityGrade, timestamp);

    try {
        await vscode.workspace.fs.writeFile(targetUri, Buffer.from(content, 'utf8'));
        logger.success(`Exported security report to ${targetUri.fsPath}`);

        const action = await vscode.window.showInformationMessage(
            `Security report exported to ${vscode.workspace.asRelativePath(targetUri)}`,
            'Open Report'
        );
        if (action === 'Open Report') {
            const doc = await vscode.workspace.openTextDocument(targetUri);
            await vscode.window.showTextDocument(doc);
        }
    } catch (error) {
        const reason = error instanceof Error ? error.message : String(error);
        logger.error('Failed to export security report', error);
        vscode.window.showErrorMessage(`Failed to export security report: ${reason}`);
    }
}

/**
 * Builds a JSON report from the workspace summary (full finding data).
 */
function buildJsonReport(
    summary: WorkspaceSummary,
    securityScore: number,
    securityGrade: string,
    generatedAt: Date
): string {
    const report = {
        tool: 'Code Guardian',
        generatedAt: generatedAt.toISOString(),
        securityScore,
        securityGrade,
        summary: {
            totalFiles: summary.totalFiles,
            scannedFiles: summary.scannedFiles,
            totalIssues: summary.totalIssues,
            criticalIssues: summary.criticalIssues,
            highIssues: summary.highIssues,
            mediumIssues: summary.mediumIssues,
            lowIssues: summary.lowIssues,
            totalLinesOfCode: summary.totalLinesOfCode,
            scanDurationMs: summary.scanDuration
        },
        files: summary.fileResults
            .filter(file => file.issues.length > 0)
            .map(file => ({
                path: file.relativePath,
                linesOfCode: file.linesOfCode,
                issues: file.issues.map(issue => ({
                    message: issue.message,
                    startLine: issue.startLine,
                    endLine: issue.endLine,
                    confidence: issue.confidence,
                    detectionSource: issue.detectionSource,
                    suggestedFix: issue.suggestedFix
                }))
            }))
    };
    return JSON.stringify(report, null, 2);
}

/**
 * Builds a human-readable Markdown report from the workspace summary.
 */
function buildMarkdownReport(
    summary: WorkspaceSummary,
    securityScore: number,
    securityGrade: string,
    generatedAt: Date
): string {
    const lines: string[] = [];
    lines.push('# Code Guardian — Security Report');
    lines.push('');
    lines.push(`- **Generated:** ${generatedAt.toISOString()}`);
    lines.push(`- **Security score:** ${securityScore}/100 (Grade ${securityGrade})`);
    lines.push(`- **Files scanned:** ${summary.scannedFiles} / ${summary.totalFiles}`);
    lines.push(`- **Lines of code:** ${summary.totalLinesOfCode}`);
    lines.push(`- **Scan duration:** ${(summary.scanDuration / 1000).toFixed(1)}s`);
    lines.push('');
    lines.push('## Summary');
    lines.push('');
    lines.push('| Severity | Count |');
    lines.push('| --- | --- |');
    lines.push(`| 🔴 Critical | ${summary.criticalIssues} |`);
    lines.push(`| 🟠 High | ${summary.highIssues} |`);
    lines.push(`| 🟡 Medium | ${summary.mediumIssues} |`);
    lines.push(`| 🔵 Low | ${summary.lowIssues} |`);
    lines.push(`| **Total** | **${summary.totalIssues}** |`);
    lines.push('');

    const filesWithIssues = summary.fileResults
        .filter(file => file.issues.length > 0)
        .sort((a, b) => b.issues.length - a.issues.length);

    lines.push('## Findings');
    lines.push('');
    if (filesWithIssues.length === 0) {
        lines.push('No security issues detected. 🎉');
        return lines.join('\n') + '\n';
    }

    for (const file of filesWithIssues) {
        lines.push(`### ${file.relativePath} (${file.issues.length})`);
        lines.push('');
        for (const issue of file.issues) {
            const range = issue.startLine === issue.endLine
                ? `L${issue.startLine}`
                : `L${issue.startLine}-${issue.endLine}`;
            const meta: string[] = [];
            if (typeof issue.confidence === 'number') {
                meta.push(`confidence ${(issue.confidence * 100).toFixed(0)}%`);
            }
            if (issue.detectionSource) {
                meta.push(`source: ${issue.detectionSource}`);
            }
            const suffix = meta.length > 0 ? ` _(${meta.join(', ')})_` : '';
            lines.push(`- **${range}** — ${issue.message}${suffix}`);
        }
        lines.push('');
    }

    return lines.join('\n') + '\n';
}

/**
 * Called when the extension is deactivated.
 */
export function deactivate() {
    const logger = getLogger();
    logger.info('Code Guardian Extension Deactivated');

    // Cleanup cache
    disposeAnalysisCache();

    // Dispose logger
    logger.dispose();
}
