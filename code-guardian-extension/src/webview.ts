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
 * Generates the HTML content for the Contextual Q&A webview panel.
 * Allows users to select files/folders as context and ask questions about them.
 */
export function getContextualQnAWebviewContent(
    panel: vscode.WebviewPanel,
    context: vscode.ExtensionContext,
    currentModel: string = 'gemma2:2b'
): string {
    const markedJsUri = panel.webview.asWebviewUri(
        vscode.Uri.joinPath(context.extensionUri, 'media', 'marked.min.js')
    );
    const styleUri = panel.webview.asWebviewUri(
        vscode.Uri.joinPath(context.extensionUri, 'media', 'style.css')
    );
    return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline' ${panel.webview.cspSource}; style-src ${panel.webview.cspSource} 'unsafe-inline';">
    <title>Code Guardian: Contextual Q&A</title>
    <script src="${markedJsUri}"></script>
    <link rel="stylesheet" href="${styleUri}">
</head>
<body>
    <div class="header-section">
        <h2>💬 Contextual Q&A</h2>
        <div class="model-selector-container">
            <label for="modelSelect">🎯 AI Model:</label>
            <select id="modelSelect" class="model-select">
                <option value="${escapeHtml(currentModel)}" selected>${escapeHtml(currentModel)}</option>
            </select>
            <button id="refreshModels" class="refresh-btn" title="Refresh available models">🔄</button>
        </div>
    </div>
    
    <div class="context-section">
        <h3>📁 Context Selection</h3>
        <p class="context-help">Select files or folders to analyze for security vulnerabilities. The extension will automatically filter for security-relevant files.</p>
        <button id="selectContextBtn" class="primary-btn">📂 Select Files/Folders as Context</button>
        <button id="testBtn" class="primary-btn" style="margin-left: 10px; background-color: #28a745;">🧪 Test Button</button>
        <div id="contextContainer">
            <div id="contextSummary" class="context-summary hidden">
                <span id="contextStats"></span>
            </div>
            <ul id="contextList" class="context-list"></ul>
        </div>
    </div>
    
    <div id="analysisSection" class="analysis-section">
        <h3>🔍 Security Analysis</h3>
        <div id="questionForm">
            <textarea id="questionInput" placeholder="Ask about security vulnerabilities (e.g., 'Find SQL injection risks', 'Check for XSS vulnerabilities', 'Analyze authentication flaws')..."></textarea>
            <button id="askButton" class="primary-btn">
                🛡️ Analyze Security
                <span id="loadingSpinner" class="spinner hidden">⏳</span>
            </button>
        </div>
        <div id="answerArea" class="answer-area"></div>
    </div>
    <script>
    (function() {
        logger.info('Webview script starting...');
        const vscode = acquireVsCodeApi();
        logger.info('VS Code API acquired:', vscode);
        let contextUris = [];
        let currentModel = '${escapeHtml(currentModel)}';
        
        // DOM elements
        const contextList = document.getElementById('contextList');
        const contextSummary = document.getElementById('contextSummary');
        const contextStats = document.getElementById('contextStats');
        const answerArea = document.getElementById('answerArea');
        const questionInput = document.getElementById('questionInput');
        const askButton = document.getElementById('askButton');
        const loadingSpinner = document.getElementById('loadingSpinner');
        const selectContextBtn = document.getElementById('selectContextBtn');
        
        logger.info('DOM elements found:', {
            contextList: !!contextList,
            selectContextBtn: !!selectContextBtn,
            askButton: !!askButton
        });
        
        // Model selector functionality
        document.getElementById('modelSelect').onchange = function(e) {
            currentModel = e.target.value;
            vscode.postMessage({ type: 'modelChanged', model: currentModel });
        };
        
        document.getElementById('refreshModels').onclick = function() {
            vscode.postMessage({ type: 'refreshModels' });
        };
        
        document.getElementById('selectContextBtn').onclick = function() {
            logger.info('Select context button clicked');
            vscode.postMessage({ type: 'selectContext' });
        };
        
        document.getElementById('testBtn').onclick = function() {
            logger.info('Test button clicked - Script is working!');
            alert('Test button works! Script is running correctly.');
        };
        
        function updateContextDisplay() {
            if (contextUris.length === 0) {
                contextSummary.classList.add('hidden');
                contextList.innerHTML = '<li class="empty-state">No files or folders selected yet</li>';
                askButton.disabled = true;
                return;
            }
            
            askButton.disabled = false;
            contextSummary.classList.remove('hidden');
            contextStats.textContent = contextUris.length + ' item(s) selected';
            
            contextList.innerHTML = '';
            contextUris.forEach(function(uri, index) {
                const li = document.createElement('li');
                li.className = 'context-item';
                
                const isFile = uri.includes('.');
                const icon = isFile ? '📄' : '📁';
                const name = uri.split('/').pop() || uri;
                
                li.innerHTML = 
                    '<span class="context-icon">' + icon + '</span>' +
                    '<span class="context-name" title="' + uri + '">' + name + '</span>' +
                    '<span class="context-path">' + uri + '</span>' +
                    '<button class="remove-btn" onclick="removeContext(' + index + ')" title="Remove">✕</button>';
                contextList.appendChild(li);
            });
        }
        
        window.removeContext = function(index) {
            contextUris.splice(index, 1);
            updateContextDisplay();
        };
        
        window.addEventListener('message', function(event) {
            const msg = event.data;
            if (msg.type === 'contextSelected') {
                contextUris = msg.uris;
                updateContextDisplay();
            } else if (msg.type === 'answer') {
                loadingSpinner.classList.add('hidden');
                askButton.disabled = false;
                askButton.textContent = '🛡️ Analyze Security';
                
                // Format the answer with better styling
                const formattedAnswer = msg.answer.replace(/\\n/g, '<br>');
                answerArea.innerHTML = 
                    '<div class="analysis-result">' +
                        '<h4>🔍 Security Analysis Results</h4>' +
                        '<div class="analysis-content">' + formattedAnswer + '</div>' +
                    '</div>';
                answerArea.scrollIntoView({ behavior: 'smooth' });
            } else if (msg.type === 'modelsUpdated') {
                const select = document.getElementById('modelSelect');
                select.innerHTML = '';
                msg.models.forEach(function(model) {
                    const option = document.createElement('option');
                    option.value = model.name;
                    option.textContent = model.name + (model.description ? ' - ' + model.description : '');
                    option.selected = model.name === currentModel;
                    select.appendChild(option);
                });
            }
        });
        
        document.getElementById('askButton').onclick = function() {
            var question = questionInput.value.trim();
            if (!question) {
                question = 'Perform a comprehensive security analysis of the selected codebase. Look for vulnerabilities, security weaknesses, and provide recommendations.';
            }
            
            if (contextUris.length === 0) {
                alert('Please select files or folders to analyze first.');
                return;
            }
            
            // Show loading state
            loadingSpinner.classList.remove('hidden');
            askButton.disabled = true;
            askButton.textContent = 'Analyzing...';
            
            answerArea.innerHTML = 
                '<div class="analysis-loading">' +
                    '<h4>🔍 Analyzing Security...</h4>' +
                    '<p>Examining ' + contextUris.length + ' selected item(s) for vulnerabilities...</p>' +
                    '<div class="loading-animation">⏳ Please wait...</div>' +
                '</div>';
            
            vscode.postMessage({ 
                type: 'askQuestion', 
                question: question, 
                context: contextUris,
                model: currentModel 
            });
            
            questionInput.value = '';
        };
        
        // Initialize display
        updateContextDisplay();
    })();
    </script>
</body>
</html>
    `;
}
