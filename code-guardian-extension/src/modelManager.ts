import * as vscode from 'vscode';
import ollama, { ModelResponse } from 'ollama';

import { getLogger } from './logger';
/**
 * List of allowed/recommended model patterns for code analysis
 * These patterns will be matched against available models from Ollama
 */
const ALLOWED_MODEL_PATTERNS = [
    // Qwen 2.5-Coder models
    /^qwen2\.5-coder:(0\.5b|1\.5b|3b|7b|14b|32b)$/,

    // Gemma 3 models
    /^gemma3:(270m|1b|4b|12b|27b)$/,

    // CodeLlama models - base versions
    /^codellama:(7b|13b|34b|70b)$/,

    // DeepSeek-Coder models
    /^deepseek-coder:(1\.3b|6\.7b|33b)$/,

    // WizardCoder models
    /^wizardcoder:33b$/,

    // StarCoder2 models
    /^starcoder2:(3b|7b|15b)$/,

    // StableCode models
    /^stable-code:3b$/,

    // Allow any instruct, python, or other variants that might exist
    /^codellama:(7b|13b|34b|70b)-(instruct|python)$/,
    /^deepseek-coder:(1\.3b|6\.7b|33b)-instruct$/,
    /^qwen2\.5-coder:(0\.5b|1\.5b|3b|7b|14b|32b)-instruct$/
];

/**
 * Model categories for better organization
 */
const MODEL_CATEGORIES = {
    'Recommended for Code Analysis': [
        'gemma3:1b', 'llama3.2:1b', 'codellama:7b', 'qwen2.5-coder:7b'
    ],
    'Lightweight Models': [
        'gemma3:1b', 'llama3.2:1b', 'qwen2.5-coder:0.5b', 'qwen2.5-coder:1.5b', 'gemma3:270m'
    ],
    'Professional Grade': [
        'qwen2.5-coder:32b', 'codellama:70b', 'deepseek-coder:33b', 'wizardcoder:33b'
    ],
    'Balanced Performance': [
        'qwen2.5-coder:7b', 'gemma3:4b', 'codellama:13b', 'starcoder2:7b'
    ]
};

/**
 * Check if a model is allowed/suitable for code analysis
 */
function isModelAllowed(modelName: string): boolean {
    return ALLOWED_MODEL_PATTERNS.some(pattern => pattern.test(modelName));
}

/**
 * Get model category and description based on model name
 */
function getModelInfo(modelName: string): { category: string; description: string; size: string } {
    // Extract size from model name
    const sizeMatch = modelName.match(/(\d+(?:\.\d+)?)(b|m)$/i);
    let size = 'Unknown';
    if (sizeMatch) {
        const num = parseFloat(sizeMatch[1]);
        const unit = sizeMatch[2].toLowerCase();
        if (unit === 'b') {
            if (num <= 2) { size = 'Small'; }
            else if (num <= 7) { size = 'Medium'; }
            else if (num <= 15) { size = 'Large'; }
            else { size = 'X-Large'; }
        } else if (unit === 'm') {
            size = 'Micro';
        }
    }

    // Determine category and description
    let category = 'General';
    let description = 'Code analysis model';

    if (modelName.includes('qwen2.5-coder')) {
        category = 'Qwen 2.5-Coder';
        description = 'Specialized for code generation and analysis';
    } else if (modelName.includes('gemma3')) {
        category = 'Google Gemma 3';
        description = 'Multimodal model with coding support';
    } else if (modelName.includes('codellama')) {
        category = 'Meta CodeLlama';
        if (modelName.includes('python')) { description = 'Python-specialized coding model'; }
        else if (modelName.includes('instruct')) { description = 'Instruction-tuned for coding tasks'; }
        else { description = 'Foundation model for code understanding'; }
    } else if (modelName.includes('deepseek-coder')) {
        category = 'DeepSeek Coder';
        description = 'Advanced reasoning for code analysis';
    } else if (modelName.includes('wizardcoder')) {
        category = 'WizardCoder';
        description = 'Enhanced code generation capabilities';
    } else if (modelName.includes('starcoder2')) {
        category = 'StarCoder2';
        description = 'Next-generation code model';
    } else if (modelName.includes('stable-code')) {
        category = 'StableCode';
        description = 'Stable and reliable code model';
    }

    return { category, description, size };
}

/**
 * Get recommendation text for a model
 */
function getModelRecommendation(modelName: string): string {
    // Recommended models for different use cases
    const recommendations: Record<string, string> = {
        'qwen2.5-coder:7b': '⭐ Recommended for code generation',
        'gemma3:1b': '⭐ Recommended for quick analysis',
        'codellama:7b': '⭐ Recommended for code understanding',
        'deepseek-coder:6.7b': '⭐ Recommended for security analysis',
        'qwen2.5-coder:0.5b': '� Ultra lightweight',
        'qwen2.5-coder:1.5b': '🚀 Lightweight and fast',
        'gemma3:270m': '� Micro model',
        'qwen2.5-coder:14b': '💪 Advanced code understanding',
        'gemma3:4b': '💪 Good balance of speed and accuracy',
        'codellama:13b': '� Enhanced code capabilities',
        'qwen2.5-coder:32b': '🚀 Expert code generation',
        'codellama:70b': '🚀 Maximum coding capabilities',
        'deepseek-coder:33b': '🚀 Premium security analysis',
        'wizardcoder:33b': '🚀 Magic-enhanced generation'
    };

    return recommendations[modelName] || '';
}

/**
 * Interface representing an available Ollama model
 */
export interface OllamaModel {
    name: string;
    size: number;
    digest: string;
    details: any;
    modified_at: string;
    category?: string;
    description?: string;
    sizeCategory?: string;
}

/**
 * Interface for model selection result
 */
export interface ModelSelection {
    model: string;
    isCustom: boolean;
}

/**
 * Get the currently configured model name
 */
export function getCurrentModel(): string {
    // Check for environment variable first (useful for testing)
    const envModel = process.env.CODE_GUARDIAN_MODEL;
    if (envModel) {
        return envModel;
    }

    const config = vscode.workspace.getConfiguration('codeGuardian');
    const selectedModel = config.get<string>('model', 'gemma3:1b');

    if (selectedModel === 'custom') {
        const customModel = config.get<string>('customModel', '');
        return customModel || 'gemma2:2b';
    }

    return selectedModel;
}

/**
 * Get the Ollama host URL from configuration
 */
export function getOllamaHost(): string {
    const config = vscode.workspace.getConfiguration('codeGuardian');
    return config.get<string>('ollamaHost', 'http://localhost:11434');
}

/**
 * Get available models from Ollama server, filtered by allowed patterns
 */
export async function getAvailableModels(): Promise<OllamaModel[]> {
	const logger = getLogger();
    try {
        const response = await ollama.list();

        // Filter and transform models
        const availableModels: OllamaModel[] = response.models
            .filter((model: ModelResponse) => isModelAllowed(model.name))
            .map((model: ModelResponse) => {
                const info = getModelInfo(model.name);
                return {
                    name: model.name,
                    size: model.size,
                    digest: model.digest,
                    details: model.details,
                    category: info.category,
                    description: info.description,
                    sizeCategory: info.size,
                    modified_at: typeof model.modified_at === 'string' ? model.modified_at : model.modified_at.toISOString()
                };
            })
            .sort((a: OllamaModel, b: OllamaModel) => {
                // Sort by category first, then by name
                if (a.category !== b.category) {
                    return (a.category || '').localeCompare(b.category || '');
                }
                return a.name.localeCompare(b.name);
            });

        // If no allowed models are available, provide fallback suggestions
        if (availableModels.length === 0) {
            vscode.window.showWarningMessage(
                'No suitable code analysis models found on Ollama server. Consider installing: gemma3:1b, llama3.2:1b, or codellama:7b',
                'View Recommended Models'
            ).then(selection => {
                if (selection === 'View Recommended Models') {
                    vscode.env.openExternal(vscode.Uri.parse('https://ollama.ai/library'));
                }
            });
        }

        return availableModels;
    } catch (error) {
        logger.error('Error fetching available models:', error);
        vscode.window.showErrorMessage(
            'Failed to fetch models from Ollama server. Please ensure Ollama is running.'
        );

        // Return fallback models in case of error
        return getPreDefinedModels().map((modelObj: any) => {
            const info = getModelInfo(modelObj.name);
            return {
                name: modelObj.name,
                size: 0,
                digest: '',
                details: {},
                category: info.category,
                description: info.description,
                sizeCategory: info.size,
                modified_at: new Date().toISOString()
            };
        });
    }
}

/**
 * Check if a specific model exists on the Ollama server
 */
export async function validateModel(modelName: string): Promise<boolean> {
	const logger = getLogger();
    try {
        const models = await getAvailableModels();
        return models.some(model => model.name === modelName);
    } catch (error) {
        logger.error('Failed to validate model:', error);
        return false;
    }
}

/**
 * Set the selected model in VS Code configuration
 */
export async function setSelectedModel(model: string, isCustom: boolean = false): Promise<void> {
    const config = vscode.workspace.getConfiguration('codeGuardian');

    if (isCustom) {
        await config.update('model', 'custom', vscode.ConfigurationTarget.Global);
        await config.update('customModel', model, vscode.ConfigurationTarget.Global);
    } else {
        await config.update('model', model, vscode.ConfigurationTarget.Global);
    }
}

/**
 * Show model selection quick pick to user
 */
export async function showModelSelector(): Promise<ModelSelection | undefined> {
    try {
        // First, show a loading message
        const loadingItem = vscode.window.showQuickPick(
            [{ label: 'Loading available models...', description: 'Fetching from Ollama server' }],
            { placeHolder: 'Loading models...' }
        );

        // Get available models
        const availableModels = await getAvailableModels();

        // Dismiss loading message
        loadingItem.then(item => {
            if (item) {
                // The loading item was selected, but we'll replace it
            }
        });

        if (availableModels.length === 0) {
            const tryAgain = await vscode.window.showWarningMessage(
                'No models found on Ollama server. Make sure Ollama is running and models are installed.',
                'Retry',
                'Use Default'
            );

            if (tryAgain === 'Retry') {
                return showModelSelector();
            } else if (tryAgain === 'Use Default') {
                return { model: 'gemma2:2b', isCustom: false };
            }
            return undefined;
        }

        // Create quick pick items with enhanced categorization
        const quickPickItems: vscode.QuickPickItem[] = [];
        const currentModel = getCurrentModel();

        // Add available server models (filtered by allowed patterns)
        if (availableModels.length > 0) {
            // Group models by category
            const groupedModels = availableModels.reduce((groups: Record<string, OllamaModel[]>, model) => {
                const category = model.category || 'Other';
                if (!groups[category]) {
                    groups[category] = [];
                }
                groups[category].push(model);
                return groups;
            }, {});

            // Add grouped models
            Object.entries(groupedModels).forEach(([category, models]) => {
                quickPickItems.push({
                    label: `$(folder) ${category}`,
                    kind: vscode.QuickPickItemKind.Separator
                });

                models.forEach(model => {
                    const sizeFormatted = formatBytes(model.size);
                    const recommendation = getModelRecommendation(model.name);
                    const isCurrentModel = model.name === currentModel;

                    quickPickItems.push({
                        label: `${isCurrentModel ? '$(check) ' : ''}${model.name}`,
                        description: `${model.description || 'Code analysis model'} • ${model.sizeCategory || 'Unknown size'}`,
                        detail: `${recommendation ? recommendation + ' • ' : ''}Size: ${sizeFormatted} • Modified: ${new Date(model.modified_at).toLocaleDateString()}`
                    });
                });
            });
        }

        // Add separator for recommendations
        quickPickItems.push({
            label: '$(info) Recommended Models',
            kind: vscode.QuickPickItemKind.Separator
        });

        // Add recommended models that aren't installed
        const installedModelNames = availableModels.map(m => m.name);
        const recommendedModels = [
            'qwen2.5-coder:7b',
            'gemma3:1b',
            'codellama:7b',
            'deepseek-coder:6.7b'
        ].filter(name => !installedModelNames.includes(name));

        recommendedModels.forEach(modelName => {
            const info = getModelInfo(modelName);
            quickPickItems.push({
                label: `$(cloud-download) ${modelName}`,
                description: `${info.description} • Not installed`,
                detail: '⭐ Recommended for code analysis - Click to view installation guide'
            });
        });

        // Add custom model option
        quickPickItems.push(
            {
                label: '$(edit) Custom Model',
                kind: vscode.QuickPickItemKind.Separator
            },
            {
                label: '$(add) Enter Custom Model Name',
                description: 'Type a custom model name'
            }
        );

        const selected = await vscode.window.showQuickPick(quickPickItems, {
            placeHolder: `Current model: ${currentModel}. Select a new model or press Escape to cancel.`,
            matchOnDescription: true,
            matchOnDetail: true
        });

        if (!selected) {
            return undefined;
        }

        // Handle different selection types
        if (selected.label === '$(add) Enter Custom Model Name') {
            const customModel = await vscode.window.showInputBox({
                prompt: 'Enter the name of the Ollama model (e.g., "llama2:7b")',
                placeHolder: 'model-name:tag',
                validateInput: (value) => {
                    if (!value || value.trim() === '') {
                        return 'Model name cannot be empty';
                    }
                    if (!/^[a-zA-Z0-9._-]+:[a-zA-Z0-9._-]+$/.test(value.trim())) {
                        return 'Model name should be in format "name:tag" (e.g., "llama2:7b")';
                    }
                    return null;
                }
            });

            if (customModel) {
                return { model: customModel.trim(), isCustom: true };
            }
            return undefined;
        }

        // Handle model installation guidance
        if (selected.label.includes('$(cloud-download)')) {
            const modelName = selected.label.replace(/^\$\([^)]+\)\s*/, '');
            const installChoice = await vscode.window.showInformationMessage(
                `"${modelName}" is not installed. Would you like to install it?`,
                'Install with Ollama',
                'View Installation Guide',
                'Cancel'
            );

            if (installChoice === 'Install with Ollama') {
                // Copy command to clipboard
                const command = `ollama pull ${modelName}`;
                await vscode.env.clipboard.writeText(command);
                vscode.window.showInformationMessage(
                    `Installation command copied to clipboard: ${command}`,
                    'Open Terminal'
                ).then(action => {
                    if (action === 'Open Terminal') {
                        vscode.commands.executeCommand('workbench.action.terminal.new');
                    }
                });
            } else if (installChoice === 'View Installation Guide') {
                vscode.env.openExternal(vscode.Uri.parse(`https://ollama.ai/library/${modelName.split(':')[0]}`));
            }
            return undefined;
        }

        // Extract model name from label (remove icons and prefixes)
        const modelName = selected.label.replace(/^\$\([^)]+\)\s*/, '').replace(/^✓\s*/, '');
        return { model: modelName, isCustom: false };

    } catch (error) {
        vscode.window.showErrorMessage(`Error selecting model: ${error}`);
        return undefined;
    }
}

/**
 * Get predefined model options with descriptions
 */
function getPreDefinedModels() {
    return [
        // Qwen 2.5-Coder models - All available sizes
        { name: 'qwen2.5-coder:0.5b', description: 'Ultra lightweight', size: 'Micro', details: 'Minimal resource coding model' },
        { name: 'qwen2.5-coder:1.5b', description: 'Lightweight', size: 'Small', details: 'Fast and efficient coding model' },
        { name: 'qwen2.5-coder:3b', description: 'Compact', size: 'Small', details: 'Balanced size and performance' },
        { name: 'qwen2.5-coder:7b', description: 'Code specialist', size: 'Medium', details: 'Dedicated coding proficiency' },
        { name: 'qwen2.5-coder:14b', description: 'Advanced coder', size: 'Large', details: 'Enhanced coding capabilities' },
        { name: 'qwen2.5-coder:32b', description: 'Expert coder', size: 'X-Large', details: 'Professional code generation' },

        // Gemma 3 models - All available sizes
        { name: 'gemma3:270m', description: 'Micro', size: 'Micro', details: 'Ultra-compact multimodal model' },
        { name: 'gemma3:1b', description: 'Small', size: 'Small', details: 'Efficient multimodal capabilities' },
        { name: 'gemma3:4b', description: 'Medium', size: 'Medium', details: 'Balanced multimodal performance' },
        { name: 'gemma3:12b', description: 'Large', size: 'Large', details: 'Advanced multimodal capabilities' },
        { name: 'gemma3:27b', description: 'Premium', size: 'X-Large', details: 'Full multimodal capabilities' },

        // CodeLlama models - All available sizes
        { name: 'codellama:7b', description: 'Foundation', size: 'Medium', details: 'Base coding model' },
        { name: 'codellama:13b', description: 'Enhanced', size: 'Large', details: 'Improved code understanding' },
        { name: 'codellama:34b', description: 'Professional', size: 'X-Large', details: 'Advanced code analysis' },
        { name: 'codellama:70b', description: 'Expert', size: 'XX-Large', details: 'Maximum coding capabilities' },

        // DeepSeek-Coder models - All available sizes
        { name: 'deepseek-coder:1.3b', description: 'Lightweight', size: 'Small', details: 'Efficient code analysis' },
        { name: 'deepseek-coder:6.7b', description: 'Balanced', size: 'Medium', details: 'Good speed and capability' },
        { name: 'deepseek-coder:33b', description: 'Expert', size: 'X-Large', details: 'Advanced code understanding' },

        // WizardCoder models
        { name: 'wizardcoder:33b', description: 'Wizard', size: 'X-Large', details: 'Magic-enhanced code generation' },

        // StarCoder2 models - All available sizes
        { name: 'starcoder2:3b', description: 'Compact', size: 'Small', details: 'Next-gen code model (small)' },
        { name: 'starcoder2:7b', description: 'Standard', size: 'Medium', details: 'Next-gen code model (medium)' },
        { name: 'starcoder2:15b', description: 'Advanced', size: 'Large', details: 'Enhanced StarCoder capabilities' },

        // StableCode models
        { name: 'stable-code:3b', description: 'Stable', size: 'Small', details: 'Reliable code generation' }
    ];
}

/**
 * Format bytes to human readable format
 */
function formatBytes(bytes: number): string {
    if (bytes === 0) {
        return '0 B';
    }
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

/**
 * Test connection to Ollama server
 */
export async function testOllamaConnection(): Promise<boolean> {
	const logger = getLogger();
    try {
        await ollama.list();
        return true;
    } catch (error) {
        logger.error('Ollama connection test failed:', error);
        return false;
    }
}

/**
 * Pull a model from Ollama registry
 */
export async function pullModel(modelName: string): Promise<boolean> {
    try {
        await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: `Pulling model: ${modelName}`,
            cancellable: false
        }, async (progress) => {
            progress.report({ message: 'Downloading...' });

            try {
                const stream = await ollama.pull({ model: modelName, stream: true });

                for await (const chunk of stream) {
                    if (chunk.status) {
                        progress.report({ message: chunk.status });
                    }
                }

                return true;
            } catch (error) {
                throw error;
            }
        });

        vscode.window.showInformationMessage(`Model ${modelName} has been successfully downloaded.`);
        return true;
    } catch (error) {
        vscode.window.showErrorMessage(`Failed to pull model ${modelName}: ${error}`);
        return false;
    }
}
