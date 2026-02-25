import * as vscode from 'vscode';
import ollama from 'ollama';
import { getWebviewContent } from './webview';
import { getCurrentModel, getAvailableModels } from './modelManager';
import { RAGManager } from './ragManager';
import { getAnalysisCache } from './analysisCache';
import { getLogger } from './logger';

/**
 * Interface for the expected structure of a security issue returned by the LLM.
 */
export interface SecurityIssue {
	message: string;         // Description of the issue
	startLine: number;       // 1-based line number where the issue starts
	endLine: number;         // 1-based line number where the issue ends
	suggestedFix?: string;   // Optional secure version or remediation advice
}

/**
 * Error types for better error handling
 */
export enum AnalysisErrorType {
	CONNECTION_ERROR = 'CONNECTION_ERROR',
	TIMEOUT_ERROR = 'TIMEOUT_ERROR',
	PARSE_ERROR = 'PARSE_ERROR',
	MODEL_NOT_FOUND = 'MODEL_NOT_FOUND',
	RATE_LIMIT = 'RATE_LIMIT',
	UNKNOWN_ERROR = 'UNKNOWN_ERROR'
}

export class AnalysisError extends Error {
	constructor(
		public type: AnalysisErrorType,
		message: string,
		public originalError?: unknown
	) {
		super(message);
		this.name = 'AnalysisError';
	}
}

/**
 * Retry configuration
 */
const RETRY_CONFIG = {
	maxAttempts: 3,
	baseDelay: 1000, // 1 second
	maxDelay: 5000,  // 5 seconds
	retryableErrors: [
		AnalysisErrorType.CONNECTION_ERROR,
		AnalysisErrorType.TIMEOUT_ERROR,
		AnalysisErrorType.RATE_LIMIT
	]
};

/**
 * Delay function for exponential backoff
 */
async function delay(ms: number): Promise<void> {
	return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Analyzes the provided code snippet using an LLM and returns a list of security issues.
 *
 * @param code - The source code to be analyzed.
 * @param modelName - Optional model name to use (defaults to configured model).
 * @param ragManager - Optional RAG manager for enhanced prompts.
 * @returns A promise resolving to an array of SecurityIssue objects detected by the LLM.
 */
export async function analyzeCodeWithLLM(code: string, modelName?: string, ragManager?: RAGManager): Promise<SecurityIssue[]> {
	const logger = getLogger();
	const model = modelName || getCurrentModel();
	const ragEnabled = Boolean(ragManager);

	// Check cache first
	const cache = getAnalysisCache();
	const cachedResult = cache.get(code, model, ragEnabled);
	if (cachedResult !== null) {
		logger.debug('Cache hit - returning cached analysis result');
		return cachedResult;
	}

	logger.info('Cache miss - analyzing with LLM', { model, codeLength: code.length });

	let systemPrompt = `You are a secure code analyzer. Detect security issues in code and return ONLY a JSON array.

CRITICAL: Your response MUST be ONLY a valid JSON array. Do not include any explanatory text, markdown formatting, or comments.

Response format:
[
	{
		"message": "Issue description",
		"startLine": 1,
		"endLine": 3,
		"suggestedFix": "Optional suggested secure version"
	}
]

If no issues are found, return an empty array: []

DO NOT include any text before or after the JSON array. DO NOT wrap the response in markdown code blocks.`;

	let userPrompt = `Analyze the following code for security vulnerabilities and return ONLY a JSON array:\n\n${code}`;

	// Enhance prompts with RAG if available
	if (ragManager) {
		try {
			const enhancedSystemPrompt = await ragManager.generateEnhancedPrompt(systemPrompt, code);
			const enhancedUserPrompt = await ragManager.generateEnhancedPrompt(userPrompt, code);

			if (enhancedSystemPrompt !== systemPrompt) {
				systemPrompt = enhancedSystemPrompt;
			}
			if (enhancedUserPrompt !== userPrompt) {
				userPrompt = enhancedUserPrompt;
			}
		} catch (error) {
			logger.warn('⚠️ Failed to enhance prompts with RAG, continuing with standard prompts:', error);
		}
	}

	const messages = [
		{ role: 'system', content: systemPrompt },
		{ role: 'user', content: userPrompt }
	];

	// Retry logic with exponential backoff
	for (let attempt = 1; attempt <= RETRY_CONFIG.maxAttempts; attempt++) {
		try {
			const res = await Promise.race([
				ollama.chat({ model, messages }),
				new Promise<never>((_, reject) =>
					setTimeout(() => reject(new AnalysisError(
						AnalysisErrorType.TIMEOUT_ERROR,
						`Analysis timed out after 30 seconds (attempt ${attempt}/${RETRY_CONFIG.maxAttempts})`
					)), 30000)
				)
			]);

			try {
				let raw = res.message.content.trim();

				// Remove Markdown code blocks and single quotes, if present
				if (raw.startsWith('```json') || raw.startsWith('```')) {
					raw = raw.replace(/^```(?:json)?/, '').replace(/```$/, '').trim();
				}
				if (raw.startsWith("'") && raw.endsWith("'")) {
					raw = raw.slice(1, -1).trim();
				}

				// Locate and extract the JSON array from the raw response
				const jsonStart = raw.indexOf('[');
				const jsonEnd = raw.lastIndexOf(']');

				if (jsonStart === -1 || jsonEnd === -1) {
					throw new AnalysisError(
						AnalysisErrorType.PARSE_ERROR,
						'No valid JSON array found in LLM response'
					);
				}

				const json = raw.slice(jsonStart, jsonEnd + 1);
				const parsed = JSON.parse(json);

				// Validate structure
				if (!Array.isArray(parsed)) {
					throw new AnalysisError(
						AnalysisErrorType.PARSE_ERROR,
						'LLM response is not a JSON array'
					);
				}

				// Validate and sanitize each issue object
				const validated: SecurityIssue[] = parsed
					.filter((item: any) =>
						item &&
						typeof item === 'object' &&
						typeof item.message === 'string' &&
						typeof item.startLine === 'number' &&
						typeof item.endLine === 'number'
					)
					.map((item: any) => ({
						message: item.message,
						startLine: Math.max(1, Math.round(item.startLine)),
						endLine: Math.max(1, Math.round(item.endLine)),
						suggestedFix: typeof item.suggestedFix === 'string' ? item.suggestedFix : undefined
					}));

				if (validated.length === 0 && parsed.length > 0) {
					logger.warn(`LLM returned ${parsed.length} items but none had valid structure`);
				}

				// Cache the successful result
				cache.set(code, model, validated, ragEnabled);
				logger.debug('Cached analysis result');

				return validated; // Return structured array of issues

			} catch (parseError) {
				if (parseError instanceof AnalysisError) {
					throw parseError;
				}
				throw new AnalysisError(
					AnalysisErrorType.PARSE_ERROR,
					`Failed to parse LLM response: ${parseError instanceof Error ? parseError.message : String(parseError)}`,
					parseError
				);
			}

		} catch (error) {
			// Classify error
			let analysisError: AnalysisError;

			if (error instanceof AnalysisError) {
				analysisError = error;
			} else if (error instanceof Error) {
				if (error.message.includes('ECONNREFUSED') || error.message.includes('ENOTFOUND')) {
					analysisError = new AnalysisError(
						AnalysisErrorType.CONNECTION_ERROR,
						`Cannot connect to Ollama. Make sure Ollama is running (attempt ${attempt}/${RETRY_CONFIG.maxAttempts})`,
						error
					);
				} else if (error.message.includes('model') && error.message.includes('not found')) {
					analysisError = new AnalysisError(
						AnalysisErrorType.MODEL_NOT_FOUND,
						`Model "${model}" not found. Please pull it with: ollama pull ${model}`,
						error
					);
				} else if (error.message.includes('rate limit') || error.message.includes('429')) {
					analysisError = new AnalysisError(
						AnalysisErrorType.RATE_LIMIT,
						`Rate limit exceeded (attempt ${attempt}/${RETRY_CONFIG.maxAttempts})`,
						error
					);
				} else {
					analysisError = new AnalysisError(
						AnalysisErrorType.UNKNOWN_ERROR,
						`Analysis failed: ${error.message} (attempt ${attempt}/${RETRY_CONFIG.maxAttempts})`,
						error
					);
				}
			} else {
				analysisError = new AnalysisError(
					AnalysisErrorType.UNKNOWN_ERROR,
					`Unknown error during analysis (attempt ${attempt}/${RETRY_CONFIG.maxAttempts})`,
					error
				);
			}

			// Check if error is retryable and we haven't exhausted retries
			const isRetryable = RETRY_CONFIG.retryableErrors.includes(analysisError.type);
			const hasRetriesLeft = attempt < RETRY_CONFIG.maxAttempts;

			if (isRetryable && hasRetriesLeft) {
				const delayMs = Math.min(
					RETRY_CONFIG.baseDelay * Math.pow(2, attempt - 1),
					RETRY_CONFIG.maxDelay
				);
				logger.warn(`⚠️ ${analysisError.message}. Retrying in ${delayMs}ms...`);
				await delay(delayMs);
				continue; // Retry
			}

			// Non-retryable error or exhausted retries - log and return empty array
			logger.error(`❌ ${analysisError.message}`);
			if (analysisError.originalError) {
				logger.error('Original error:', analysisError.originalError);
			}

			// Show user-friendly error message for non-retryable errors
			if (analysisError.type === AnalysisErrorType.MODEL_NOT_FOUND) {
				vscode.window.showErrorMessage(analysisError.message, 'Open Settings').then(selection => {
					if (selection === 'Open Settings') {
						vscode.commands.executeCommand('codeSecurity.selectModel');
					}
				});
			} else if (analysisError.type === AnalysisErrorType.CONNECTION_ERROR) {
				vscode.window.showErrorMessage(
					'Cannot connect to Ollama. Please start Ollama and try again.',
					'Retry'
				).then(selection => {
					if (selection === 'Retry') {
						// User can manually retry
					}
				});
			}

			return []; // Return empty array to fail gracefully
		}
	}

	// Should never reach here, but TypeScript requires it
	return [];
}

/**
 * Displays a webview panel and streams security analysis results from the LLM.
 *
 * @param code - The source code to analyze.
 * @param context - The extension context used to access resources.
 * @param ragManager - Optional RAG manager for enhanced analysis.
 */
export async function analyzeCode(code: string, context: vscode.ExtensionContext, ragManager?: RAGManager) {
	const logger = getLogger();
	const currentModel = getCurrentModel();

	const panel = vscode.window.createWebviewPanel(
		'codeSecurityAnalysis',
		'🔐 code-guardian Analysis',
		vscode.ViewColumn.Beside,
		{
			enableScripts: true,
			retainContextWhenHidden: true,
			localResourceRoots: [vscode.Uri.joinPath(context.extensionUri, 'media')]
		}
	);

	// Maintains the full conversation history with the LLM
	let baseSystemPrompt = `You are a secure code analyzer. Analyze code snippets for security vulnerabilities, 
						insecure patterns, or bad practices. Be concise but thorough. When users ask follow-up
						questions, provide detailed explanations and remediation advice. Format your responses
						using Markdown for better readability.`;
	
	// Enhance system prompt with RAG if available
	let enhancedSystemPrompt = baseSystemPrompt;
	if (ragManager) {
		try {
			enhancedSystemPrompt = await ragManager.generateEnhancedPrompt(baseSystemPrompt, code);
		} catch (error) {
			logger.warn('Failed to enhance system prompt with RAG:', error);
		}
	}

	let conversationHistory = [
		{
			role: 'system',
			content: enhancedSystemPrompt
		}
	];

	// Track the current model being used
	let activeModel = currentModel;

	// Initialize webview content with code and empty issue list
	panel.webview.html = getWebviewContent(panel, context, code, [], activeModel);

	try {
		let initialPrompt = `Analyze this code for security issues:\n\n\`\`\`\n${code}\n\`\`\``;
		
		// Enhance initial prompt with RAG if available
		if (ragManager) {
			try {
				const enhancedPrompt = await ragManager.generateEnhancedPrompt(initialPrompt, code);
				if (enhancedPrompt !== initialPrompt) {
					initialPrompt = enhancedPrompt;
				}
			} catch (error) {
				logger.warn('Failed to enhance initial prompt with RAG:', error);
			}
		}
		
		conversationHistory.push({ role: 'user', content: initialPrompt });

		panel.webview.postMessage({
			type: 'addMessage',
			role: 'assistant',
			content: 'Analyzing code...',
			isMarkdown: false
		});

		// Stream LLM response to the webview
		const stream = await ollama.chat({
			model: activeModel,
			messages: conversationHistory,
			stream: true
		});

		let fullResponse = '';
		for await (const chunk of stream) {
			if (chunk?.message?.content) {
				fullResponse += chunk.message.content;
				panel.webview.postMessage({
					type: 'updateLastMessage',
					content: fullResponse,
					isMarkdown: true
				});
			}
		}

		conversationHistory.push({ role: 'assistant', content: fullResponse });
		panel.webview.postMessage({ type: 'enableInput' });

	} catch (error) {
		panel.webview.postMessage({
			type: 'addMessage',
			role: 'error',
			content: `Error analyzing code: ${error}`,
			isMarkdown: false
		});
		panel.webview.postMessage({ type: 'enableInput' });
	}

	// Listen for follow-up questions from the webview
	panel.webview.onDidReceiveMessage(async (message) => {
		if (message.type === 'followUpQuestion') {
			const question = message.question;
			const requestedModel = message.model || activeModel;

			// Update active model if user selected a different one
			if (requestedModel !== activeModel) {
				activeModel = requestedModel;
			}

			conversationHistory.push({ role: 'user', content: question });

			try {
				panel.webview.postMessage({
					type: 'addMessage',
					role: 'assistant',
					content: 'Thinking...',
					isMarkdown: false
				});

				const stream = await ollama.chat({
					model: activeModel,
					messages: conversationHistory,
					stream: true
				});

				let fullResponse = '';
				for await (const chunk of stream) {
					if (chunk?.message?.content) {
						fullResponse += chunk.message.content;
						panel.webview.postMessage({
							type: 'updateLastMessage',
							content: fullResponse,
							isMarkdown: true
						});
					}
				}

				conversationHistory.push({ role: 'assistant', content: fullResponse });
				panel.webview.postMessage({ type: 'enableInput' });

			} catch (error) {
				panel.webview.postMessage({
					type: 'updateLastMessage',
					content: `Error processing question with model ${activeModel}: ${error}`,
					isMarkdown: false
				});
				panel.webview.postMessage({ type: 'enableInput' });
			}
		} else if (message.type === 'modelChanged') {
			// Update the active model when user selects a different one
			activeModel = message.model;
			panel.webview.postMessage({
				type: 'modelChanged',
				model: activeModel
			});
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
		}
	});
}
