import * as vscode from 'vscode';
import { analyzeAndReportDiagnosticsFromText } from './diagnostic';
import { provideFixes } from './actions';
import { getEnclosingFunction } from './functionExtractor';
import { analyzeCode } from './analyzer';
import { showModelSelector, setSelectedModel, getCurrentModel, getAvailableModels } from './modelManager';
import { getContextualQnAWebviewContent } from './webview';
import { RAGManager } from './ragManager';
import { getAnalysisCache, disposeAnalysisCache } from './analysisCache';
import { WorkspaceScanner } from './workspaceScanner';
import { getDashboardHTML } from './dashboardWebview';
import { getLogger } from './logger';

/**
 * Entry point: Called when the extension is activated.
 * Registers diagnostics, real-time and manual analysis commands, and quick fixes.
 *
 * @param context - The VS Code extension context.
 */
export function activate(context: vscode.ExtensionContext) {
    const logger = getLogger();
    logger.success('Code Guardian Extension Activated');

    // Check if RAG is enabled in settings
    const config = vscode.workspace.getConfiguration('codeGuardian');
    const isRAGEnabled = config.get<boolean>('enableRAG', true);

    // Lazy initialization of RAG Manager - only created when first needed
    let ragManager: RAGManager | undefined;
    let isInitializing = false;

    /**
     * Initialize RAG Manager lazily on first access
     * This defers the expensive vector store loading until actually needed
     */
    const initializeRAGIfNeeded = () => {
        if (!isRAGEnabled || ragManager || isInitializing) {
            return;
        }

        isInitializing = true;
        logger.info('Lazy loading RAG Manager...');

        // Initialize in background
        setTimeout(async () => {
            try {
                ragManager = new RAGManager(context);
                logger.success('RAG Manager initialized with security knowledge base');
            } catch (error) {
                logger.error('Failed to initialize RAG Manager', error);
                vscode.window.showWarningMessage('RAG Manager initialization failed. Using standard analysis mode.');
            } finally {
                isInitializing = false;
            }
        }, 100); // Small delay to not block activation
    };

    if (isRAGEnabled) {
        logger.info('RAG enabled - will initialize on first use');
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
     * Real-time analysis: Analyze the function under cursor as the user types.
     * Uses debouncing to avoid excessive analysis calls during rapid typing.
     */
    let debounceTimer: NodeJS.Timeout | undefined;
    const DEBOUNCE_DELAY = 800; // milliseconds

    const debouncedAnalysis = (doc: vscode.TextDocument, position: vscode.Position) => {
        if (debounceTimer) {
            clearTimeout(debounceTimer);
        }

        debounceTimer = setTimeout(() => {
            const funcCodeData = getEnclosingFunction(doc, position);

            if (funcCodeData && funcCodeData.code.length < 2000) {
                analyzeAndReportDiagnosticsFromText(
                    funcCodeData.code,
                    doc,
                    diagnosticCollection,
                    funcCodeData.startLine
                );
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
    const fullScanCommand = vscode.commands.registerCommand('codeSecurity.analyzeFullFile', () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor) { return; };

        const doc = editor.document;
        const fullText = doc.getText();

        if (fullText.length > 20000) {
            vscode.window.showWarningMessage('File too large for full security analysis.');
            return;
        }

        analyzeAndReportDiagnosticsFromText(fullText, doc, diagnosticCollection);
        vscode.window.showInformationMessage('🔍 Analyzing full file for security issues...');
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

    /**
     * Manual command: Analyze selected text or current line using LLM (AI).
     */
    const selectionAnalysisCommand = vscode.commands.registerCommand('codeSecurity.analyzeSelectionWithAI', () => {
        // Trigger lazy initialization on first analysis
        initializeRAGIfNeeded();

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

        const analysisMode = ragManager ? '🧠 RAG-enhanced' : '🤖 standard';
        vscode.window.showInformationMessage(`🤖 Analyzing selected code with AI (${analysisMode})...`);
        analyzeCode(selectedText, context, ragManager);
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
    const contextualQnACommand = vscode.commands.registerCommand('codeSecurity.contextualQnA', async () => {
        const currentModel = getCurrentModel();

        // Create a webview panel for context-based Q&A
        const panel = vscode.window.createWebviewPanel(
            'codeSecurityContextualQnA',
            '💬 Code Guardian: Contextual Q&A',
            vscode.ViewColumn.Beside,
            {
                enableScripts: true,
                retainContextWhenHidden: true,
                localResourceRoots: [vscode.Uri.joinPath(context.extensionUri, 'media')]
            }
        );

        // Track active model for this session
        let activeModel = currentModel;

        // Initial HTML for the webview
        panel.webview.html = getContextualQnAWebviewContent(panel, context, activeModel);

        // Listen for messages from the webview (file/folder selection, questions)
        panel.webview.onDidReceiveMessage(async (message) => {
            logger.info('Received message from webview:', message);
            if (message.type === 'selectContext') {
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
                // Gather the selected context (files/folders), read their contents,
                // and send to your LLM backend for analysis/answering.
                const contextUris: string[] = message.context || [];
                const requestedModel = message.model || activeModel;

                // Update active model if user selected a different one
                if (requestedModel !== activeModel) {
                    activeModel = requestedModel;
                }

                let contextContents: { path: string, content: string }[] = [];

                // Helper: Check if file should be analyzed for security
                function isSecurityRelevantFile(filePath: string): boolean {
                    const securityRelevantExtensions = [
                        '.js', '.ts', '.jsx', '.tsx', '.py', '.java', '.php', '.rb', '.go', '.rs', '.cpp', '.c', '.cs', '.swift',
                        '.sql', '.json', '.yaml', '.yml', '.xml', '.env', '.config', '.conf', '.ini', '.properties',
                        '.html', '.htm', '.jsp', '.asp', '.aspx', '.php', '.ejs', '.hbs', '.handlebars'
                    ];
                    const fileName = filePath.toLowerCase();
                    return securityRelevantExtensions.some(ext => fileName.endsWith(ext)) ||
                        fileName.includes('dockerfile') ||
                        fileName.includes('docker-compose') ||
                        fileName.includes('package.json') ||
                        fileName.includes('requirements.txt') ||
                        fileName.includes('pom.xml') ||
                        fileName.includes('build.gradle') ||
                        fileName.includes('makefile') ||
                        fileName.includes('.gitignore') ||
                        fileName.includes('readme');
                }

                // Helper: Recursively collect all files in a directory
                async function collectFilesRecursively(dir: string): Promise<string[]> {
                    let files: string[] = [];
                    try {
                        const entries = await vscode.workspace.fs.readDirectory(vscode.Uri.file(dir));
                        for (const [name, type] of entries) {
                            const fullPath = dir.endsWith('/') ? dir + name : dir + '/' + name;
                            if (type & vscode.FileType.File) {
                                if (isSecurityRelevantFile(fullPath)) {
                                    files.push(fullPath);
                                }
                            } else if (type & vscode.FileType.Directory) {
                                // Skip common non-security relevant directories
                                if (!name.startsWith('.') && !['node_modules', 'dist', 'build', 'target', '__pycache__', '.git'].includes(name)) {
                                    files = files.concat(await collectFilesRecursively(fullPath));
                                }
                            }
                        }
                    } catch (e) {
                        logger.error(`Error reading directory ${dir}:`, e);
                        files.push(`${dir} (Error reading: ${e})`);
                    }
                    return files;
                }
                for (const uri of contextUris) {
                    logger.info(`Processing URI: ${uri}`);
                    try {
                        const fileStat = await vscode.workspace.fs.stat(vscode.Uri.file(uri));
                        if (fileStat.type & vscode.FileType.File) {
                            // Read file content
                            if (isSecurityRelevantFile(uri)) {
                                const fileData = await vscode.workspace.fs.readFile(vscode.Uri.file(uri));
                                const content = Buffer.from(fileData).toString('utf8');
                                contextContents.push({ path: uri, content: content });
                                logger.info(`Added file: ${uri} (${content.length} chars)`);
                            } else {
                                logger.info(`Skipped non-security file: ${uri}`);
                            }
                        } else if (fileStat.type & vscode.FileType.Directory) {
                            // Recursively read all files in the directory
                            logger.info(`Scanning directory: ${uri}`);
                            const allFiles = await collectFilesRecursively(uri);
                            logger.info(`Found ${allFiles.length} security-relevant files in directory`);
                            for (const filePath of allFiles) {
                                if (filePath.includes('(Error reading:')) {
                                    contextContents.push({ path: filePath, content: '' });
                                    continue;
                                }
                                try {
                                    const fileData = await vscode.workspace.fs.readFile(vscode.Uri.file(filePath));
                                    const content = Buffer.from(fileData).toString('utf8');
                                    contextContents.push({ path: filePath, content: content });
                                    logger.info(`Added file: ${filePath} (${content.length} chars)`);
                                } catch (e) {
                                    contextContents.push({ path: filePath, content: `Error reading: ${e}` });
                                    logger.error(`Error reading file ${filePath}:`, e);
                                }
                            }
                        }
                    } catch (e) {
                        contextContents.push({ path: uri, content: `Error reading: ${e}` });
                        logger.error(`Error processing URI ${uri}:`, e);
                    }
                }

                logger.info(`Collected ${contextContents.length} files for analysis`);

                // If no files were collected, inform the user
                if (contextContents.length === 0) {
                    panel.webview.postMessage({
                        type: 'answer',
                        answer: 'No security-relevant files found in the selected context. Please select folders/files containing code files (.js, .ts, .py, .java, .php, etc.) for security analysis.'
                    });
                    return;
                }

                // Compose a security-focused prompt for the LLM
                const contextSummary = contextContents.map(f => {
                    const truncatedContent = f.content.substring(0, 3000); // Increased limit for better context
                    return `File: ${f.path}\n---\n${truncatedContent}${f.content.length > 3000 ? '\n... (truncated)' : ''}\n`;
                }).join('\n');

                const securityQuestion = message.question.trim() || 'Perform a comprehensive security analysis';
                const prompt = `${contextSummary}\n\nSECURITY ANALYSIS REQUEST: ${securityQuestion}`;

                // Call the LLM with the selected model
                try {
                    const ollama = await import('ollama');

                    const response = await ollama.default.chat({
                        model: activeModel,
                        messages: [
                            {
                                role: 'system',
                                content: `You are an expert cybersecurity analyst specializing in secure code review. Your task is to analyze the provided codebase for security vulnerabilities and weaknesses.

FOCUS AREAS:
- SQL Injection vulnerabilities
- Cross-Site Scripting (XSS) attacks  
- Authentication and authorization flaws
- Input validation issues
- Cryptographic weaknesses
- Insecure file operations
- API security issues
- Configuration vulnerabilities
- Dependency security issues
- Business logic flaws

ANALYSIS FORMAT:
1. **CRITICAL VULNERABILITIES** - High-risk security issues that need immediate attention
2. **MEDIUM RISK ISSUES** - Important security concerns that should be addressed
3. **LOW RISK ISSUES** - Minor security improvements
4. **SECURITY RECOMMENDATIONS** - Best practices and preventive measures

For each issue found:
- Specify the exact file and line number (if applicable)
- Explain the security risk and potential impact
- Provide concrete code examples for fixes
- Rate the severity (Critical/High/Medium/Low)

Be thorough, specific, and provide actionable recommendations.`
                            },
                            {
                                role: 'user',
                                content: prompt
                            }
                        ]
                    });

                    panel.webview.postMessage({
                        type: 'answer',
                        answer: response.message.content
                    });
                } catch (err) {
                    panel.webview.postMessage({
                        type: 'answer',
                        answer: `Error analyzing with model ${activeModel}: ${err}`
                    });
                }
            }
        });
    });
    context.subscriptions.push(contextualQnACommand);

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
                vscode.window.showInformationMessage('RAG enabled! Please reload the extension to initialize the knowledge base.');
                return;
            } else if (enableRAG === 'Open Settings') {
                vscode.commands.executeCommand('workbench.action.openSettings', 'codeGuardian.enableRAG');
                return;
            }
            return;
        }

        const options = [
            'View Knowledge Base',
            'Add Security Knowledge', 
            'Rebuild Vector Store',
            'Search Knowledge',
            'Update Vulnerability Data',
            'View Vulnerability Stats',
            'Clear Vulnerability Cache',
            'Toggle RAG On/Off'
        ];

        const choice = await vscode.window.showQuickPick(options, {
            placeHolder: 'Select RAG management action'
        });

        switch (choice) {
            case 'Toggle RAG On/Off':
                const currentStatus = isRAGEnabled ? 'enabled' : 'disabled';
                const newStatus = !isRAGEnabled;
                const action = newStatus ? 'enable' : 'disable';
                
                const confirm = await vscode.window.showInformationMessage(
                    `RAG is currently ${currentStatus}. Do you want to ${action} it?`,
                    `${action.charAt(0).toUpperCase() + action.slice(1)} RAG`,
                    'Cancel'
                );
                
                if (confirm?.includes('RAG')) {
                    await vscode.workspace.getConfiguration('codeGuardian').update('enableRAG', newStatus, vscode.ConfigurationTarget.Global);
                    vscode.window.showInformationMessage(`RAG ${action}d! Please reload the extension for changes to take effect.`);
                }
                break;

            case 'View Knowledge Base':
                const knowledge = ragManager.getKnowledgeBase();
                const knowledgeInfo = knowledge.map(k => 
                    `• ${k.title} (${k.severity}) - ${k.category} - ${k.tags.join(', ')}`
                ).join('\n');
                
                vscode.window.showInformationMessage(
                    `Knowledge Base (${knowledge.length} entries):\n\n${knowledgeInfo}`,
                    { modal: true }
                );
                break;

            case 'Add Security Knowledge':
                const title = await vscode.window.showInputBox({
                    prompt: 'Enter security knowledge title',
                    placeHolder: 'e.g., "CSRF Prevention Techniques"'
                });
                
                if (!title) {
                    return;
                }

                const content = await vscode.window.showInputBox({
                    prompt: 'Enter security knowledge content',
                    placeHolder: 'Detailed explanation and prevention techniques...'
                });
                
                if (!content) {
                    return;
                }

                const category = await vscode.window.showQuickPick([
                    'injection', 'cryptography', 'authentication', 'authorization', 
                    'path-traversal', 'configuration', 'business-logic', 'other'
                ], { placeHolder: 'Select category' });
                
                if (!category) {
                    return;
                }

                const severity = await vscode.window.showQuickPick([
                    'high', 'medium', 'low'
                ], { placeHolder: 'Select severity level' });
                
                if (!severity) {
                    return;
                }

                const tags = await vscode.window.showInputBox({
                    prompt: 'Enter tags (comma-separated)',
                    placeHolder: 'csrf, web-security, token'
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

            case 'Rebuild Vector Store':
                try {
                    await ragManager.rebuildVectorStore();
                } catch (error) {
                    vscode.window.showErrorMessage(`❌ Failed to rebuild vector store: ${error}`);
                }
                break;

            case 'Search Knowledge':
                const searchQuery = await vscode.window.showInputBox({
                    prompt: 'Enter search query',
                    placeHolder: 'e.g., "XSS prevention", "SQL injection", "crypto"'
                });
                
                if (!searchQuery) {
                    return;
                }

                try {
                    const results = await ragManager.searchRelevantKnowledge(searchQuery, 5);
                    if (results.length === 0) {
                        vscode.window.showInformationMessage('No relevant knowledge found for your query.');
                        return;
                    }

                    const searchResults = results.map((doc, index) => {
                        const metadata = doc.metadata;
                        return `${index + 1}. ${metadata.title} (${metadata.severity})\n   ${doc.pageContent.substring(0, 200)}...`;
                    }).join('\n\n');

                    vscode.window.showInformationMessage(
                        `Search Results (${results.length} found):\n\n${searchResults}`,
                        { modal: true }
                    );
                } catch (error) {
                    vscode.window.showErrorMessage(`❌ Search failed: ${error}`);
                }
                break;

            case 'Update Vulnerability Data':
                const updateChoice = await vscode.window.showQuickPick([
                    'Update All Sources',
                    'Update CWE Data Only',
                    'Update OWASP Top 10 Only',
                    'Update Latest CVEs Only',
                    'Update JavaScript Vulnerabilities Only'
                ], { placeHolder: 'Select data source to update' });
                
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

            case 'View Vulnerability Stats':
                try {
                    if (!ragManager) {
                        vscode.window.showErrorMessage('RAG Manager not initialized');
                        return;
                    }

                    const stats = await ragManager.getVulnerabilityDataStats();
                    const cacheStatus = stats.cacheInfo.map(info => {
                        const ageHours = Math.round(info.age / (1000 * 60 * 60));
                        const sizeKB = Math.round(info.size / 1024);
                        return `${info.file}: ${info.exists ? `${ageHours}h old, ${sizeKB}KB` : 'Not cached'}`;
                    }).join('\n');

                    const statsMessage = `📊 Vulnerability Data Statistics\n\n` +
                        `Total Knowledge Entries: ${stats.totalKnowledge}\n` +
                        `Vulnerability Data Entries: ${stats.vulnerabilityData}\n` +
                        `Last Update: ${stats.lastUpdate || 'Never'}\n\n` +
                        `Cache Status:\n${cacheStatus}`;

                    vscode.window.showInformationMessage(statsMessage, { modal: true });
                } catch (error) {
                    vscode.window.showErrorMessage(`❌ Failed to get vulnerability stats: ${error}`);
                }
                break;

            case 'Clear Vulnerability Cache':
                const confirmClear = await vscode.window.showWarningMessage(
                    'This will clear all cached vulnerability data. Fresh data will be downloaded on next update.',
                    'Clear Cache',
                    'Cancel'
                );
                
                if (confirmClear === 'Clear Cache') {
                    try {
                        await ragManager.clearVulnerabilityCache();
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
        
        await currentConfig.update('enableRAG', newStatus, vscode.ConfigurationTarget.Global);
        updateStatusBar();
        
        vscode.window.showInformationMessage(
            `🧠 RAG ${action}! Reload the extension for changes to take effect.`,
            'Reload Extension'
        ).then(selection => {
            if (selection === 'Reload Extension') {
                vscode.commands.executeCommand('workbench.action.reloadWindow');
            }
        });
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
                        `   • OWASP: ${result.sources.owasp} entries\n` +
                        `   • CVEs: ${result.sources.cves} entries\n` +
                        `   • JavaScript: ${result.sources.javascript} entries\n\n` +
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
            updateStatusBar();
            
            const newRAGStatus = vscode.workspace.getConfiguration('codeGuardian').get<boolean>('enableRAG', true);
            const statusMessage = newRAGStatus ? 'enabled' : 'disabled';
            
            vscode.window.showInformationMessage(
                `🧠 RAG ${statusMessage}! Reload the extension for changes to take effect.`,
                'Reload Extension'
            ).then(selection => {
                if (selection === 'Reload Extension') {
                    vscode.commands.executeCommand('workbench.action.reloadWindow');
                }
            });
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
                        // TODO: Implement export functionality
                        vscode.window.showInformationMessage('Export feature coming soon!');
                        break;
                    case 'settings':
                        vscode.commands.executeCommand('workbench.action.openSettings', 'codeGuardian');
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
