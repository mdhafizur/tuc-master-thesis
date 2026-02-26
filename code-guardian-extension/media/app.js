// Establish communication with the VS Code extension
const vscode = acquireVsCodeApi();

// Get references to DOM elements
const conversation = document.getElementById('conversation');
const questionInput = document.getElementById('questionInput');
const askButton = document.getElementById('askButton');
const loadingSpinner = document.getElementById('loadingSpinner');
const modelSelect = document.getElementById('modelSelect');
const refreshModelsBtn = document.getElementById('refreshModels');

// Current model state
let currentModel = modelSelect ? modelSelect.value : 'gemma2:2b';

// Initialize model selector if present
if (modelSelect) {
    modelSelect.addEventListener('change', (e) => {
        currentModel = e.target.value;
        vscode.postMessage({ type: 'modelChanged', model: currentModel });
    });
}

if (refreshModelsBtn) {
    refreshModelsBtn.addEventListener('click', () => {
        vscode.postMessage({ type: 'refreshModels' });
    });
}

// Listen for messages sent from the extension backend
window.addEventListener('message', event => {
    const msg = event.data;

    switch (msg.type) {
        case 'addMessage':
            addMessage(msg.role, msg.content, msg.isMarkdown);
            break;
        case 'updateLastMessage':
            updateLastMessage(msg.content, msg.isMarkdown);
            break;
        case 'enableInput':
            enableInput();
            break;
        case 'modelsUpdated':
            updateModelSelector(msg.models);
            break;
        case 'modelChanged':
            currentModel = msg.model;
            if (modelSelect) {
                modelSelect.value = currentModel;
            }
            break;
    }
});

/**
 * Adds a new message block to the conversation area.
 * @param {string} role - The sender's role: 'user', 'assistant', or 'error'.
 * @param {string} content - The message text content.
 * @param {boolean} isMarkdown - Whether the message should be rendered using Markdown.
 */
function addMessage(role, content, isMarkdown = false) {
    const messageDiv = document.createElement('div');
    messageDiv.className = `message ${role}`;

    const formattedContent = isMarkdown ? marked.parse(content) : content;

    messageDiv.innerHTML = `
        <div class="role">${role === 'user' ? '👤 You' : role === 'error' ? '❌ Error' : '🛡️ Analyst'}</div>
        <div class="content ${isMarkdown ? 'markdown' : ''}">${formattedContent}</div>
    `;

    conversation.appendChild(messageDiv);
    scrollToBottom();
}

/**
 * Updates the last message in the conversation (e.g., during streaming output).
 * @param {string} content - The new content to display.
 * @param {boolean} isMarkdown - Whether the content should be parsed as Markdown.
 */
function updateLastMessage(content, isMarkdown = false) {
    const messages = conversation.getElementsByClassName('message');
    if (messages.length > 0) {
        const lastMessage = messages[messages.length - 1];
        const contentDiv = lastMessage.querySelector('.content');
        if (contentDiv) {
            contentDiv.innerHTML = isMarkdown ? marked.parse(content) : content;
            scrollToBottom();
        }
    }
}

/**
 * Automatically scrolls the conversation view to the latest message.
 */
function scrollToBottom() {
    conversation.scrollTop = conversation.scrollHeight;
}

// Handle "Send" button click
askButton.addEventListener('click', sendQuestion);

// Handle Enter key press to send message (Shift+Enter = newline)
questionInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendQuestion();
    }
});

/**
 * Sends the follow-up question to the extension and shows loading state.
 */
function sendQuestion() {
    const question = questionInput.value.trim();
    if (question) {
        addMessage('user', question, false);

        // Disable input to prevent multiple sends
        questionInput.disabled = true;
        askButton.disabled = true;
        loadingSpinner.classList.remove('hidden');
        questionInput.value = '';

        // Post message to the extension backend with current model
        vscode.postMessage({
            type: 'followUpQuestion',
            question: question,
            model: currentModel
        });
    }
}

/**
 * Re-enables input field and button when ready for next question.
 */
function enableInput() {
    questionInput.disabled = false;
    askButton.disabled = false;
    loadingSpinner.classList.add('hidden');
    questionInput.focus();
}

/**
 * Updates the model selector dropdown with available models.
 * @param {Array} models - Array of model objects with name and description.
 */
function updateModelSelector(models) {
    if (!modelSelect) {
        return;
    }

    const currentSelection = modelSelect.value;
    modelSelect.innerHTML = '';

    models.forEach(model => {
        const option = document.createElement('option');
        option.value = model.name;
        option.textContent = model.name + (model.description ? ` - ${model.description}` : '');
        option.selected = model.name === currentSelection;
        modelSelect.appendChild(option);
    });

    // If current selection is not in the list, add it
    if (!models.find(m => m.name === currentSelection)) {
        const option = document.createElement('option');
        option.value = currentSelection;
        option.textContent = currentSelection;
        option.selected = true;
        modelSelect.appendChild(option);
    }
}

// Helper function to disable input during processing
function disableInput() {
    questionInput.disabled = true;
    askButton.disabled = true;
    loadingSpinner.classList.remove('hidden');
}

// Automatically focus on the input when the webview loads
questionInput.focus();
