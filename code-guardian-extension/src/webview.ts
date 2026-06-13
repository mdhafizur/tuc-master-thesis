import * as vscode from 'vscode';

import { getLogger } from './logger';
/**
 * Generates the HTML content for the webview panel, embedding code, analysis results,
 * and follow-up question UI, with Markdown support and secure escaping.
 *
 * @param panel - The active webview panel to render URIs properly.
 * @param context - The extension context to access local resources (like scripts).
 * @param code - The original code snippet provided by the user.
 * @param conversation - Optional conversation history to populate the view.
 * @param currentModel - The currently selected model name.
 * @returns A full HTML document string for the webview content.
 */
export function getWebviewContent(
    panel: vscode.WebviewPanel,
    context: vscode.ExtensionContext,
    code: string,
    conversation: any[] = [],
    currentModel: string = 'gemma2:2b'
): string {
    // Escape the code to safely inject into HTML
    const escapedCode = escapeHtml(code);

    // Convert conversation messages to HTML (supports Markdown rendering)
    const conversationHtml = conversation.map(msg => `
        <div class="message ${msg.role}">
            <div class="role">${msg.role === 'user' ? '👤 You' : '🛡️ Analyst'}</div>
            <div class="content ${msg.isMarkdown ? 'markdown-content' : ''}"${msg.isMarkdown ?
            ` data-markdown="${escapeHtml(msg.content)}"` : ''
        }>${msg.isMarkdown ? '' : escapeHtml(msg.content)}</div>
        </div>
    `).join('');

    // URIs must be resolved *inside* the function
    const markedJsUri = panel.webview.asWebviewUri(
        vscode.Uri.joinPath(context.extensionUri, 'media', 'marked.min.js')
    );
    const styleUri = panel.webview.asWebviewUri(
        vscode.Uri.joinPath(context.extensionUri, 'media', 'style.css')
    );
    const scriptUri = panel.webview.asWebviewUri(
        vscode.Uri.joinPath(context.extensionUri, 'media', 'app.js')
    );

    // Return complete HTML for the webview
    return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>code-guardian Analysis</title>
    <script src="${markedJsUri}"></script>
    <link rel="stylesheet" href="${styleUri}">
</head>
<body>
    <div class="header-section">
        <h2>🔍 Code Guardian Analysis</h2>
        <div class="model-selector-container">
            <label for="modelSelect">🎯 AI Model:</label>
            <select id="modelSelect" class="model-select">
                <option value="${escapeHtml(currentModel)}" selected>${escapeHtml(currentModel)}</option>
            </select>
            <button id="refreshModels" class="refresh-btn" title="Refresh available models">🔄</button>
        </div>
    </div>

    <h3>📝 Original Code</h3>
    <pre class="code-block">${escapedCode}</pre>

    <h3>💬 Security Analysis</h3>
    <div id="conversation">
        ${conversationHtml}
    </div>

    <div id="questionForm">
        <textarea id="questionInput" placeholder="Ask a follow-up question about the security analysis..."></textarea>
        <button id="askButton">
            Send
            <span id="loadingSpinner" class="spinner hidden"></span>
        </button>
    </div>

    <script>
        // Render Markdown content safely via DOM manipulation
        document.querySelectorAll('.markdown-content[data-markdown]').forEach(function(el) {
            el.innerHTML = marked.parse(el.getAttribute('data-markdown') || '');
        });
    </script>
    <script src="${scriptUri}"></script>
</body>
</html>
    `;
}

/**
 * Escapes special HTML characters to prevent injection vulnerabilities.
 *
 * @param str - The raw string to sanitize.
 * @returns The HTML-escaped version.
 */
function escapeHtml(str: string): string {
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

/**
 * Generates the HTML for the Contextual Q&A panel: a multi-turn security chat.
 *
 * The panel keeps a running conversation, streams the agent's tool activity as it
 * works, renders answers as Markdown, and surfaces each proposed fix as a card
 * with Preview-diff / Apply controls. Styling uses VS Code theme variables so the
 * panel matches the user's color theme.
 */
export function getContextualQnAWebviewContent(
    panel: vscode.WebviewPanel,
    context: vscode.ExtensionContext,
    currentModel: string = 'gemma2:2b'
): string {
    const markedJsUri = panel.webview.asWebviewUri(
        vscode.Uri.joinPath(context.extensionUri, 'media', 'marked.min.js')
    );
    return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src ${panel.webview.cspSource} data:; script-src 'unsafe-inline' ${panel.webview.cspSource}; style-src ${panel.webview.cspSource} 'unsafe-inline';">
    <title>Code Guardian — Security Assistant</title>
    <script src="${markedJsUri}"></script>
    <style>
        :root {
            --cg-border: var(--vscode-panel-border, rgba(128,128,128,0.25));
            --cg-radius: 10px;
        }
        * { box-sizing: border-box; }
        html, body {
            height: 100%;
            margin: 0;
            padding: 0;
            font-family: var(--vscode-font-family);
            font-size: var(--vscode-font-size, 13px);
            color: var(--vscode-foreground);
            background: var(--vscode-editor-background);
        }
        .cg-app { display: flex; flex-direction: column; height: 100vh; }

        /* Header */
        .cg-header {
            display: flex; align-items: center; justify-content: space-between;
            padding: 12px 16px;
            border-bottom: 1px solid var(--cg-border);
            gap: 12px;
        }
        .cg-brand { display: flex; align-items: center; gap: 10px; min-width: 0; }
        .cg-logo {
            font-size: 20px; line-height: 1;
            width: 34px; height: 34px; flex: 0 0 34px;
            display: flex; align-items: center; justify-content: center;
            border-radius: 8px;
            background: var(--vscode-textLink-foreground, #3794ff);
            background: linear-gradient(135deg, var(--vscode-textLink-foreground, #3794ff), var(--vscode-charts-purple, #b180d7));
        }
        .cg-title { font-weight: 600; font-size: 1.05em; line-height: 1.1; }
        .cg-subtitle { opacity: 0.65; font-size: 0.82em; }
        .cg-model { display: flex; align-items: center; gap: 6px; }
        .cg-select {
            background: var(--vscode-dropdown-background);
            color: var(--vscode-dropdown-foreground);
            border: 1px solid var(--vscode-dropdown-border, var(--cg-border));
            border-radius: 6px; padding: 4px 8px; max-width: 200px;
            font-size: 0.85em;
        }
        .cg-icon-btn {
            background: transparent; color: var(--vscode-foreground);
            border: 1px solid var(--cg-border); border-radius: 6px;
            width: 28px; height: 28px; cursor: pointer; line-height: 1;
        }
        .cg-icon-btn:hover { background: var(--vscode-toolbar-hoverBackground, rgba(128,128,128,0.15)); }

        /* Context bar */
        .cg-context {
            display: flex; align-items: center; flex-wrap: wrap; gap: 6px;
            padding: 8px 16px;
            border-bottom: 1px solid var(--cg-border);
        }
        .cg-chip-btn {
            background: transparent; color: var(--vscode-textLink-foreground);
            border: 1px dashed var(--cg-border); border-radius: 14px;
            padding: 3px 10px; cursor: pointer; font-size: 0.82em;
        }
        .cg-chip-btn:hover { border-color: var(--vscode-textLink-foreground); }
        .cg-chips { display: flex; flex-wrap: wrap; gap: 6px; }
        .cg-chip {
            display: inline-flex; align-items: center; gap: 6px;
            background: var(--vscode-badge-background, rgba(128,128,128,0.2));
            color: var(--vscode-badge-foreground, inherit);
            border-radius: 14px; padding: 3px 6px 3px 10px; font-size: 0.8em;
            max-width: 240px;
        }
        .cg-chip span { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .cg-chip button {
            background: transparent; border: none; color: inherit; cursor: pointer;
            opacity: 0.7; padding: 0 2px; line-height: 1;
        }
        .cg-chip button:hover { opacity: 1; }

        /* Thread */
        .cg-thread { flex: 1; overflow-y: auto; padding: 18px 16px; scroll-behavior: smooth; }
        .cg-msg { display: flex; gap: 10px; margin-bottom: 18px; align-items: flex-start; }
        .cg-user { flex-direction: row-reverse; }
        .cg-avatar {
            flex: 0 0 28px; width: 28px; height: 28px; border-radius: 50%;
            display: flex; align-items: center; justify-content: center; font-size: 14px;
            background: var(--vscode-badge-background, rgba(128,128,128,0.2));
        }
        .cg-bubble {
            border-radius: var(--cg-radius); padding: 10px 14px; max-width: 88%;
            line-height: 1.5; word-wrap: break-word; overflow-wrap: anywhere;
        }
        .cg-user .cg-bubble {
            background: var(--vscode-textLink-foreground, #3794ff);
            color: #fff;
            border-bottom-right-radius: 3px;
        }
        .cg-assistant .cg-bubble {
            background: var(--vscode-editorWidget-background, rgba(128,128,128,0.1));
            border: 1px solid var(--cg-border);
            border-bottom-left-radius: 3px;
            width: 100%;
        }

        /* Markdown content */
        .cg-content :first-child { margin-top: 0; }
        .cg-content :last-child { margin-bottom: 0; }
        .cg-content pre {
            background: var(--vscode-textCodeBlock-background, rgba(128,128,128,0.15));
            padding: 10px 12px; border-radius: 6px; overflow-x: auto;
        }
        .cg-content code {
            font-family: var(--vscode-editor-font-family, monospace);
            font-size: 0.92em;
        }
        .cg-content :not(pre) > code {
            background: var(--vscode-textCodeBlock-background, rgba(128,128,128,0.15));
            padding: 1px 5px; border-radius: 4px;
        }
        .cg-content h1, .cg-content h2, .cg-content h3, .cg-content h4 { margin: 0.8em 0 0.4em; }
        .cg-content a { color: var(--vscode-textLink-foreground); }
        .cg-content table { border-collapse: collapse; }
        .cg-content th, .cg-content td { border: 1px solid var(--cg-border); padding: 4px 8px; }

        /* Activity (tool steps) */
        .cg-activity {
            margin-bottom: 10px; border: 1px solid var(--cg-border);
            border-radius: 8px; background: var(--vscode-editor-background); overflow: hidden;
        }
        .cg-activity summary {
            cursor: pointer; padding: 6px 10px; font-size: 0.82em; opacity: 0.85;
            user-select: none; list-style: none;
        }
        .cg-activity summary::-webkit-details-marker { display: none; }
        .cg-activity summary::before { content: '▸ '; }
        .cg-activity[open] summary::before { content: '▾ '; }
        .cg-steps { padding: 0 10px 8px 10px; }
        .cg-step {
            font-family: var(--vscode-editor-font-family, monospace);
            font-size: 0.8em; opacity: 0.8; padding: 2px 0;
            white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
        }

        /* Edit cards */
        .cg-edits { margin-top: 12px; display: flex; flex-direction: column; gap: 10px; }
        .cg-edit {
            border: 1px solid var(--cg-border);
            border-left: 3px solid var(--vscode-charts-green, #89d185);
            border-radius: 8px; padding: 10px 12px;
            background: var(--vscode-editor-background);
        }
        .cg-edit-head { display: flex; align-items: center; gap: 8px; margin-bottom: 4px; }
        .cg-edit-file {
            font-family: var(--vscode-editor-font-family, monospace);
            font-weight: 600; color: var(--vscode-charts-yellow, #d7ba7d);
            font-size: 0.88em; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
        }
        .cg-edit-lines { opacity: 0.6; font-size: 0.78em; flex: 0 0 auto; }
        .cg-edit-desc { font-size: 0.9em; opacity: 0.92; margin-bottom: 8px; }
        .cg-edit-warn { color: var(--vscode-charts-orange, #e8a33d); font-size: 0.82em; margin-bottom: 8px; }
        .cg-edit-actions { display: flex; gap: 8px; }

        /* Buttons */
        .cg-btn {
            border: none; border-radius: 6px; cursor: pointer;
            padding: 5px 12px; font-size: 0.85em; font-family: inherit;
        }
        .cg-btn-primary { background: var(--vscode-button-background); color: var(--vscode-button-foreground); }
        .cg-btn-primary:hover { background: var(--vscode-button-hoverBackground); }
        .cg-btn-primary:disabled { opacity: 0.5; cursor: default; }
        .cg-btn-secondary {
            background: var(--vscode-button-secondaryBackground, rgba(128,128,128,0.2));
            color: var(--vscode-button-secondaryForeground, inherit);
        }
        .cg-btn-secondary:hover { background: var(--vscode-button-secondaryHoverBackground, rgba(128,128,128,0.3)); }

        /* Empty state */
        .cg-empty { text-align: center; max-width: 460px; margin: 8vh auto 0; opacity: 0.95; }
        .cg-empty-icon { font-size: 40px; margin-bottom: 8px; }
        .cg-empty h3 { margin: 0 0 6px; }
        .cg-empty p { opacity: 0.7; line-height: 1.5; }
        .cg-suggestions { display: flex; flex-direction: column; gap: 8px; margin-top: 18px; }
        .cg-suggestion {
            background: var(--vscode-editorWidget-background, rgba(128,128,128,0.1));
            border: 1px solid var(--cg-border); border-radius: 8px;
            padding: 8px 12px; cursor: pointer; text-align: left; color: inherit; font: inherit;
        }
        .cg-suggestion:hover { border-color: var(--vscode-textLink-foreground); }

        /* Composer */
        .cg-composer {
            display: flex; align-items: flex-end; gap: 8px;
            padding: 12px 16px; border-top: 1px solid var(--cg-border);
        }
        .cg-mode { flex: 0 0 auto; height: 38px; }
        .cg-input {
            flex: 1; resize: none; max-height: 160px;
            background: var(--vscode-input-background); color: var(--vscode-input-foreground);
            border: 1px solid var(--vscode-input-border, var(--cg-border));
            border-radius: 8px; padding: 9px 12px; font: inherit; line-height: 1.4;
        }
        .cg-input:focus { outline: none; border-color: var(--vscode-focusBorder); }
        .cg-send {
            flex: 0 0 auto; width: 38px; height: 38px; border: none; border-radius: 8px;
            background: var(--vscode-button-background); color: var(--vscode-button-foreground);
            cursor: pointer; font-size: 15px;
        }
        .cg-send:hover { background: var(--vscode-button-hoverBackground); }
        .cg-send:disabled { opacity: 0.5; cursor: default; }

        .cg-spinner {
            display: inline-block; width: 12px; height: 12px;
            border: 2px solid currentColor; border-top-color: transparent;
            border-radius: 50%; animation: cg-spin 0.7s linear infinite; vertical-align: middle;
        }
        @keyframes cg-spin { to { transform: rotate(360deg); } }
        .hidden { display: none !important; }
    </style>
</head>
<body>
    <div class="cg-app">
        <header class="cg-header">
            <div class="cg-brand">
                <div class="cg-logo">🛡️</div>
                <div>
                    <div class="cg-title">Code Guardian</div>
                    <div class="cg-subtitle">Security Assistant</div>
                </div>
            </div>
            <div class="cg-model">
                <select id="modelSelect" class="cg-select" title="AI model">
                    <option value="${escapeHtml(currentModel)}" selected>${escapeHtml(currentModel)}</option>
                </select>
                <button id="refreshModels" class="cg-icon-btn" title="Refresh available models">⟳</button>
            </div>
        </header>

        <div class="cg-context">
            <button id="selectContextBtn" class="cg-chip-btn">＋ Add context</button>
            <div id="contextChips" class="cg-chips"></div>
        </div>

        <div id="thread" class="cg-thread">
            <div class="cg-empty" id="emptyState">
                <div class="cg-empty-icon">🛡️</div>
                <h3>Ask about your code's security</h3>
                <p>Add files or folders as context, then ask a question. The assistant reads your workspace, finds issues, and proposes fixes you can preview and apply.</p>
                <div class="cg-suggestions">
                    <button class="cg-suggestion">Find SQL injection risks and fix them</button>
                    <button class="cg-suggestion">Review authentication for security flaws</button>
                    <button class="cg-suggestion">Check this code for XSS vulnerabilities</button>
                </div>
            </div>
        </div>

        <div class="cg-composer">
            <select id="modeSelect" class="cg-select cg-mode" title="Auto routes between chat and analysis">
                <option value="auto" selected>⚡ Auto</option>
                <option value="chat">💬 Chat</option>
                <option value="analyze">🛡️ Analyze</option>
            </select>
            <textarea id="questionInput" class="cg-input" rows="1" placeholder="Ask a question or request a security analysis…  (Enter to send, Shift+Enter for newline)"></textarea>
            <button id="askButton" class="cg-send" title="Send">➤</button>
        </div>
    </div>

    <script>
    (function() {
        const vscode = acquireVsCodeApi();
        let contextUris = [];
        let currentModel = '${escapeHtml(currentModel)}';
        let busy = false;
        let current = null; // refs to the in-progress assistant message

        const thread = document.getElementById('thread');
        const emptyState = document.getElementById('emptyState');
        const questionInput = document.getElementById('questionInput');
        const askButton = document.getElementById('askButton');
        const contextChips = document.getElementById('contextChips');
        const modelSelect = document.getElementById('modelSelect');

        const TOOL_ICONS = { read_file: '📄', list_dir: '📁', search: '🔎', get_diagnostics: '🩺', propose_edit: '✏️', finish: '✅' };

        // ---- Context selection ----
        document.getElementById('selectContextBtn').onclick = function() {
            vscode.postMessage({ type: 'selectContext' });
        };
        function renderChips() {
            contextChips.innerHTML = '';
            contextUris.forEach(function(uri, index) {
                const name = uri.split(/[/\\\\]/).pop() || uri;
                const isFile = name.indexOf('.') !== -1;
                const chip = document.createElement('div');
                chip.className = 'cg-chip';
                chip.title = uri;
                const label = document.createElement('span');
                label.textContent = (isFile ? '📄 ' : '📁 ') + name;
                chip.appendChild(label);
                const x = document.createElement('button');
                x.textContent = '✕';
                x.title = 'Remove';
                x.onclick = function() { contextUris.splice(index, 1); renderChips(); };
                chip.appendChild(x);
                contextChips.appendChild(chip);
            });
        }

        // ---- Model selector ----
        modelSelect.onchange = function(e) {
            currentModel = e.target.value;
            vscode.postMessage({ type: 'modelChanged', model: currentModel });
        };
        document.getElementById('refreshModels').onclick = function() {
            vscode.postMessage({ type: 'refreshModels' });
        };

        // ---- Composer ----
        function autoGrow() {
            questionInput.style.height = 'auto';
            questionInput.style.height = Math.min(questionInput.scrollHeight, 160) + 'px';
        }
        questionInput.addEventListener('input', autoGrow);
        questionInput.addEventListener('keydown', function(e) {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                send();
            }
        });
        askButton.onclick = send;
        Array.prototype.forEach.call(document.querySelectorAll('.cg-suggestion'), function(btn) {
            btn.onclick = function() { questionInput.value = btn.textContent; autoGrow(); send(); };
        });

        function send() {
            if (busy) { return; }
            const question = questionInput.value.trim();
            if (!question) { return; }

            if (emptyState) { emptyState.classList.add('hidden'); }
            appendUserMessage(question);
            current = appendAssistantMessage();

            busy = true;
            askButton.disabled = true;
            askButton.innerHTML = '<span class="cg-spinner"></span>';
            questionInput.value = '';
            autoGrow();

            const modeSelect = document.getElementById('modeSelect');
            const mode = modeSelect ? modeSelect.value : 'auto';
            vscode.postMessage({ type: 'askQuestion', question: question, context: contextUris, model: currentModel, mode: mode });
        }

        function finishTurn() {
            busy = false;
            askButton.disabled = false;
            askButton.textContent = '➤';
            current = null;
        }

        // ---- Thread rendering ----
        function scrollDown() { thread.scrollTop = thread.scrollHeight; }

        function appendUserMessage(text) {
            const msg = document.createElement('div');
            msg.className = 'cg-msg cg-user';
            const avatar = document.createElement('div');
            avatar.className = 'cg-avatar';
            avatar.textContent = '🧑';
            const bubble = document.createElement('div');
            bubble.className = 'cg-bubble';
            bubble.textContent = text;
            msg.appendChild(bubble);
            msg.appendChild(avatar);
            thread.appendChild(msg);
            scrollDown();
        }

        function appendAssistantMessage() {
            const msg = document.createElement('div');
            msg.className = 'cg-msg cg-assistant';
            const avatar = document.createElement('div');
            avatar.className = 'cg-avatar';
            avatar.textContent = '🛡️';
            const bubble = document.createElement('div');
            bubble.className = 'cg-bubble';

            const activity = document.createElement('details');
            activity.className = 'cg-activity';
            activity.open = true;
            const summary = document.createElement('summary');
            summary.textContent = 'Working…';
            const steps = document.createElement('div');
            steps.className = 'cg-steps';
            activity.appendChild(summary);
            activity.appendChild(steps);

            const content = document.createElement('div');
            content.className = 'cg-content';
            content.innerHTML = '<span class="cg-spinner"></span>';

            const edits = document.createElement('div');
            edits.className = 'cg-edits';

            bubble.appendChild(activity);
            bubble.appendChild(content);
            bubble.appendChild(edits);
            msg.appendChild(avatar);
            msg.appendChild(bubble);
            thread.appendChild(msg);
            scrollDown();
            return { activity: activity, summary: summary, steps: steps, content: content, edits: edits, stepCount: 0 };
        }

        function renderEditCard(edit) {
            const card = document.createElement('div');
            card.className = 'cg-edit';
            card.setAttribute('data-edit-id', edit.id);

            const head = document.createElement('div');
            head.className = 'cg-edit-head';
            const file = document.createElement('div');
            file.className = 'cg-edit-file';
            file.textContent = edit.relativePath;
            const linesEl = document.createElement('div');
            linesEl.className = 'cg-edit-lines';
            linesEl.textContent = 'lines ' + edit.startLine + '–' + edit.endLine;
            head.appendChild(file);
            head.appendChild(linesEl);
            card.appendChild(head);

            if (edit.description) {
                const desc = document.createElement('div');
                desc.className = 'cg-edit-desc';
                desc.textContent = edit.description;
                card.appendChild(desc);
            }
            if (!edit.applicable) {
                const warn = document.createElement('div');
                warn.className = 'cg-edit-warn';
                warn.textContent = '⚠ Not auto-applicable: ' + (edit.notApplicableReason || 'did not parse as valid code') + '. Review before applying.';
                card.appendChild(warn);
            }

            const actions = document.createElement('div');
            actions.className = 'cg-edit-actions';
            const preview = document.createElement('button');
            preview.className = 'cg-btn cg-btn-secondary';
            preview.textContent = '🔍 Preview diff';
            preview.onclick = function() { vscode.postMessage({ type: 'previewEdit', editId: edit.id }); };
            const apply = document.createElement('button');
            apply.className = 'cg-btn cg-btn-primary';
            apply.textContent = '✅ Apply';
            apply.onclick = function() { vscode.postMessage({ type: 'applyEdit', editId: edit.id }); };
            actions.appendChild(preview);
            actions.appendChild(apply);
            card.appendChild(actions);
            return card;
        }

        // ---- Messages from the extension ----
        window.addEventListener('message', function(event) {
            const msg = event.data;
            if (msg.type === 'seed') {
                // Pre-populate context and (optionally) auto-run an initial question.
                if (msg.context && msg.context.length) {
                    contextUris = msg.context;
                    renderChips();
                }
                if (msg.question) {
                    questionInput.value = msg.question;
                    autoGrow();
                    if (msg.autoSend) { send(); }
                }
            } else if (msg.type === 'contextSelected') {
                contextUris = msg.uris;
                renderChips();
            } else if (msg.type === 'agentStep') {
                if (!current) { return; }
                current.stepCount++;
                const line = document.createElement('div');
                line.className = 'cg-step';
                line.textContent = (TOOL_ICONS[msg.step.tool] || '⚙️') + ' ' + msg.step.summary;
                current.steps.appendChild(line);
                scrollDown();
            } else if (msg.type === 'answer') {
                const target = current || appendAssistantMessage();
                if (target.stepCount > 0) {
                    target.summary.textContent = 'Investigated workspace · ' + target.stepCount + ' step' + (target.stepCount === 1 ? '' : 's');
                    target.activity.open = false;
                } else {
                    target.activity.classList.add('hidden');
                }
                target.content.innerHTML = (typeof marked !== 'undefined') ? marked.parse(msg.answer || '') : (msg.answer || '');
                target.edits.innerHTML = '';
                (msg.edits || []).forEach(function(edit) {
                    target.edits.appendChild(renderEditCard(edit));
                });
                scrollDown();
                finishTurn();
            } else if (msg.type === 'editApplied') {
                if (msg.ok) {
                    const card = thread.querySelector('.cg-edit[data-edit-id="' + msg.editId + '"]');
                    if (card) {
                        const apply = card.querySelector('.cg-edit-actions button:last-child');
                        if (apply) { apply.textContent = '✅ Applied'; apply.disabled = true; }
                    }
                }
            } else if (msg.type === 'modelsUpdated') {
                modelSelect.innerHTML = '';
                msg.models.forEach(function(model) {
                    const option = document.createElement('option');
                    option.value = model.name;
                    option.textContent = model.name + (model.description ? ' — ' + model.description : '');
                    option.selected = model.name === currentModel;
                    modelSelect.appendChild(option);
                });
            }
        });

        renderChips();
        autoGrow();

        // Tell the extension we're ready to receive a seed (initial context/question).
        vscode.postMessage({ type: 'webviewReady' });
    })();
    </script>
</body>
</html>
    `;
}
