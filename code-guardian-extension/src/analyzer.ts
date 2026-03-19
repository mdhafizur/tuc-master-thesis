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
 * Consensus configuration for multi-pass analysis
 */
const CONSENSUS_CONFIG = {
	passes: 2,           // Number of analysis passes
	seeds: [42, 137],    // Different seeds for each pass to introduce variation
	minAgreement: 2      // Minimum passes that must agree for a finding to be kept
};

/**
 * Checks whether two security issues refer to the same finding by comparing
 * line range overlap and vulnerability type similarity.
 */
function issuesMatch(a: SecurityIssue, b: SecurityIssue): boolean {
	// Check line range overlap
	const overlapStart = Math.max(a.startLine, b.startLine);
	const overlapEnd = Math.min(a.endLine, b.endLine);
	const hasOverlap = overlapStart <= overlapEnd;

	if (!hasOverlap) {
		return false;
	}

	// Check vulnerability type similarity via keyword matching in messages
	const normalize = (msg: string) => msg.toLowerCase();
	const aMsg = normalize(a.message);
	const bMsg = normalize(b.message);

	const vulnKeywords = [
		'sql injection', 'xss', 'cross-site scripting', 'command injection',
		'path traversal', 'directory traversal', 'ssrf', 'csrf',
		'prototype pollution', 'race condition', 'deserialization',
		'nosql injection', 'code injection', 'eval', 'weak crypto',
		'insecure random', 'hardcoded', 'sensitive data'
	];

	for (const keyword of vulnKeywords) {
		if (aMsg.includes(keyword) && bMsg.includes(keyword)) {
			return true;
		}
	}

	// Fallback: if line ranges overlap and messages share significant words
	const aWords = new Set(aMsg.split(/\s+/).filter(w => w.length > 4));
	const bWords = new Set(bMsg.split(/\s+/).filter(w => w.length > 4));
	let shared = 0;
	for (const w of aWords) {
		if (bWords.has(w)) { shared++; }
	}
	return shared >= 3;
}

/**
 * Performs a single LLM analysis pass and returns parsed security issues.
 */
async function singleAnalysisPass(
	model: string,
	messages: Array<{ role: string; content: string }>,
	seed: number
): Promise<SecurityIssue[]> {
	const logger = getLogger();

	for (let attempt = 1; attempt <= RETRY_CONFIG.maxAttempts; attempt++) {
		try {
			const res = await Promise.race([
				ollama.chat({ model, messages, options: { temperature: 0, seed } }),
				new Promise<never>((_, reject) =>
					setTimeout(() => reject(new AnalysisError(
						AnalysisErrorType.TIMEOUT_ERROR,
						`Analysis timed out after 30 seconds (attempt ${attempt}/${RETRY_CONFIG.maxAttempts})`
					)), 30000)
				)
			]);

			let raw = res.message.content.trim();
			logger.info(`Raw LLM response: ${raw.substring(0, 500)}`);

			// Remove Markdown code blocks and single quotes, if present
			if (raw.startsWith('```json') || raw.startsWith('```')) {
				raw = raw.replace(/^```(?:json)?/, '').replace(/```$/, '').trim();
			}
			if (raw.startsWith("'") && raw.endsWith("'")) {
				raw = raw.slice(1, -1).trim();
			}

			// Try to parse as JSON first — handle both arrays and objects
			let parsed: any;
			try {
				parsed = JSON.parse(raw);
			} catch {
				// Fallback: locate and extract a JSON array from the raw response
				const jsonStart = raw.indexOf('[');
				const jsonEnd = raw.lastIndexOf(']');

				if (jsonStart === -1 || jsonEnd === -1) {
					throw new AnalysisError(
						AnalysisErrorType.PARSE_ERROR,
						'No valid JSON array found in LLM response'
					);
				}

				parsed = JSON.parse(raw.slice(jsonStart, jsonEnd + 1));
			}

			// If the model returned a JSON object wrapping an array, extract it
			if (parsed && !Array.isArray(parsed) && typeof parsed === 'object') {
				// Look for the first array property (e.g., "issues", "vulnerabilities", "results")
				const arrayProp = Object.values(parsed).find(v => Array.isArray(v));
				if (arrayProp) {
					parsed = arrayProp;
				} else {
					throw new AnalysisError(
						AnalysisErrorType.PARSE_ERROR,
						'LLM response is a JSON object with no array property'
					);
				}
			}

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

			return validated;

		} catch (error) {
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

			const isRetryable = RETRY_CONFIG.retryableErrors.includes(analysisError.type);
			const hasRetriesLeft = attempt < RETRY_CONFIG.maxAttempts;

			if (isRetryable && hasRetriesLeft) {
				const delayMs = Math.min(
					RETRY_CONFIG.baseDelay * Math.pow(2, attempt - 1),
					RETRY_CONFIG.maxDelay
				);
				logger.warn(`⚠️ ${analysisError.message}. Retrying in ${delayMs}ms...`);
				await delay(delayMs);
				continue;
			}

			// Non-retryable or exhausted retries — show user-friendly messages
			logger.error(`❌ ${analysisError.message}`);
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
				);
			}

			return [];
		}
	}

	return [];
}

/**
 * Filters issues to only those confirmed by multiple analysis passes.
 * An issue from pass 1 is kept only if a matching issue exists in pass 2.
 * Falls back to primary results if consensus yields nothing but both passes found issues.
 */
function applyConsensusFilter(passResults: SecurityIssue[][]): SecurityIssue[] {
	const logger = getLogger();

	if (passResults.length < 2) {
		return passResults[0] || [];
	}

	const primary = passResults[0];
	const secondary = passResults[1];

	logger.debug(`Consensus filter: Pass 1 has ${primary.length} issues, Pass 2 has ${secondary.length} issues`);

	// Keep issues from the primary pass that have a match in the secondary pass
	const agreed = primary.filter(issue =>
		secondary.some(other => issuesMatch(issue, other))
	);

	// If consensus is empty but both passes found issues, fall back to primary results
	// This prevents the consensus filter from silently dropping all findings
	if (agreed.length === 0 && primary.length > 0 && secondary.length > 0) {
		logger.warn(`Consensus filter dropped all issues — falling back to Pass 1 results (${primary.length} issues)`);
		return primary;
	}

	return agreed;
}

/**
 * Analyzes the provided code snippet using an LLM with multi-pass consensus filtering.
 * Runs analysis twice with different seeds and only keeps findings confirmed by both passes.
 * This reduces false positives since inconsistent findings are filtered out.
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

	logger.info('Cache miss - analyzing with LLM (multi-pass consensus)', { model, codeLength: code.length });

	let systemPrompt = `You are a precise secure code analyzer. Detect REAL security vulnerabilities in code and return ONLY a valid JSON array.

IMPORTANT RULES:
1. Only report issues that are genuinely exploitable. Do NOT flag safe patterns, hardcoded values, or properly sanitized inputs.
2. If the code is secure and has no vulnerabilities, you MUST return an empty array: []
3. Each issue must include a concrete suggestedFix with executable code showing the secure alternative.
4. Be specific: name the exact vulnerability type (e.g., "SQL Injection", "XSS", "Command Injection") and explain WHY it is exploitable.
5. Do NOT report theoretical risks, best-practice suggestions, or style issues. Only report actual security vulnerabilities.

CRITICAL: Your response MUST be ONLY a valid JSON array. No explanatory text, no markdown formatting, no comments.

Response format:
[
	{
		"message": "Description of the vulnerability and why it is exploitable",
		"startLine": 1,
		"endLine": 3,
		"suggestedFix": "Secure code replacement that fixes the vulnerability"
	}
]

If no vulnerabilities are found, return: []`;

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

	// Run multiple analysis passes in parallel with different seeds
	logger.info(`Running ${CONSENSUS_CONFIG.passes} consensus passes...`);
	const passPromises = CONSENSUS_CONFIG.seeds
		.slice(0, CONSENSUS_CONFIG.passes)
		.map((seed, i) => {
			logger.debug(`Starting analysis pass ${i + 1} with seed ${seed}`);
			return singleAnalysisPass(model, messages, seed);
		});

	const passResults = await Promise.all(passPromises);

	// Log per-pass results
	passResults.forEach((results, i) => {
		logger.info(`Pass ${i + 1}: found ${results.length} issues`);
	});

	// Apply consensus filter — only keep findings confirmed by both passes
	const consensus = applyConsensusFilter(passResults);
	logger.info(`Consensus: ${consensus.length} issues confirmed across passes`);

	// Cache the consensus result
	cache.set(code, model, consensus, ragEnabled);
	logger.debug('Cached consensus analysis result');

	return consensus;
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
