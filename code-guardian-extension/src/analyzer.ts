import * as vscode from 'vscode';
import ollama from 'ollama';
import { getWebviewContent } from './webview';
import { getCurrentModel, getAvailableModels } from './modelManager';
import { RAGManager } from './ragManager';
import { getAnalysisCache } from './analysisCache';
import { getLogger } from './logger';

/**
 * Provenance of a finding. `llm` = produced by the model only; `sast` = produced by a
 * deterministic baseline tool only; `hybrid` = both agreed (used by the SAST+LLM gate
 * introduced in Phase 2 of the thesis refinement plan).
 */
export type DetectionSource = 'llm' | 'sast' | 'hybrid';

/**
 * Interface for the expected structure of a security issue returned by the LLM.
 *
 * `confidence` is in [0, 1]: 1.0 = both consensus passes agreed; 0.3 = single-pass
 * fallback (consensus filter dropped everything but at least one pass found issues);
 * undefined = no consensus information available (e.g. legacy callers).
 *
 * `detectionSource` is set by the analyzer pipeline so downstream gates can apply
 * different policies to LLM-only vs SAST-confirmed findings.
 */
export interface SecurityIssue {
	message: string;                // Description of the issue
	startLine: number;              // 1-based line number where the issue starts
	endLine: number;                // 1-based line number where the issue ends
	suggestedFix?: string;          // Optional secure version or remediation advice
	confidence?: number;            // [0,1] — see comment above
	detectionSource?: DetectionSource;
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
		return (passResults[0] || []).map(issue => ({
			...issue,
			confidence: issue.confidence ?? 0.5,
			detectionSource: issue.detectionSource ?? 'llm'
		}));
	}

	const primary = passResults[0];
	const secondary = passResults[1];

	logger.debug(`Consensus filter: Pass 1 has ${primary.length} issues, Pass 2 has ${secondary.length} issues`);

	// Keep issues from the primary pass that have a match in the secondary pass.
	// Both-pass agreement is the strongest LLM signal we can produce locally → confidence 1.0.
	const agreed = primary
		.filter(issue => secondary.some(other => issuesMatch(issue, other)))
		.map(issue => ({
			...issue,
			confidence: 1.0,
			detectionSource: 'llm' as DetectionSource
		}));

	// If consensus is empty but both passes found issues, fall back to primary results
	// at low confidence. This preserves recall but lets downstream confidence gates
	// (Phase 2) suppress these findings if the user opts into stricter filtering.
	if (agreed.length === 0 && primary.length > 0 && secondary.length > 0) {
		logger.warn(`Consensus filter dropped all issues — falling back to Pass 1 results at confidence 0.3 (${primary.length} issues)`);
		return primary.map(issue => ({
			...issue,
			confidence: 0.3,
			detectionSource: 'llm' as DetectionSource
		}));
	}

	return agreed;
}

/**
 * Generates a targeted repair for a single detected vulnerability using a dedicated prompt.
 * This second-stage prompt focuses purely on fix generation, producing higher-quality repairs
 * than asking the model to detect and fix simultaneously.
 */
async function generateRepair(
	model: string,
	code: string,
	issue: SecurityIssue,
	ragManager?: RAGManager
): Promise<string | undefined> {
	const logger = getLogger();

	const vulnerableLines = code.split('\n')
		.slice(Math.max(0, issue.startLine - 1), issue.endLine)
		.join('\n');

	let repairSystemPrompt = `You are a secure code repair specialist. You are given a code snippet and a specific vulnerability found in it. Your ONLY job is to produce a fixed version of the vulnerable lines.

RULES:
1. Return ONLY a JSON object with a single "fix" field containing the corrected code.
2. The fix must directly address the reported vulnerability type.
3. The fix must be executable code, not prose or explanation.
4. Preserve the original code's functionality while eliminating the vulnerability.
5. Use established secure coding patterns (parameterized queries, input validation, safe APIs).

Response format:
{"fix": "the corrected code here"}`;

	let repairUserPrompt = `Vulnerability: ${issue.message}
Vulnerable lines (${issue.startLine}-${issue.endLine}):
${vulnerableLines}

Full code context:
${code}

Return ONLY the JSON object with the fix.`;

	// Enhance repair prompt with RAG if available
	if (ragManager) {
		try {
			const enhanced = await ragManager.generateEnhancedPrompt(repairSystemPrompt, vulnerableLines);
			if (enhanced !== repairSystemPrompt) {
				repairSystemPrompt = enhanced;
			}
		} catch {
			// Continue with standard prompt
		}
	}

	try {
		const res = await Promise.race([
			ollama.chat({
				model,
				messages: [
					{ role: 'system', content: repairSystemPrompt },
					{ role: 'user', content: repairUserPrompt }
				],
				format: 'json',
				options: { temperature: 0, seed: 42 }
			}),
			new Promise<never>((_, reject) =>
				setTimeout(() => reject(new Error('Repair generation timed out')), 15000)
			)
		]);

		const raw = res.message.content.trim();
		const parsed = JSON.parse(raw);

		if (parsed && typeof parsed.fix === 'string' && parsed.fix.trim().length > 0) {
			return parsed.fix.trim();
		}

		// Fallback: check for any string value in the response
		const firstString = Object.values(parsed).find(v => typeof v === 'string' && (v as string).trim().length > 0);
		if (firstString) {
			return (firstString as string).trim();
		}

		return undefined;
	} catch (error) {
		logger.debug(`Repair generation failed for lines ${issue.startLine}-${issue.endLine}: ${error}`);
		return undefined;
	}
}

/**
 * Analyzes the provided code snippet using an LLM with multi-pass consensus filtering
 * and two-stage repair generation.
 *
 * Stage 1: Detect vulnerabilities using consensus filtering (two passes, keep only agreed findings).
 * Stage 2: For each confirmed vulnerability, generate a targeted repair using a dedicated prompt.
 *
 * This separation improves both detection precision (consensus) and repair quality (focused prompt).
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

	logger.info('Cache miss - analyzing with LLM (multi-pass consensus + two-stage repair)', { model, codeLength: code.length });

	// ========== STAGE 1: Detection with consensus filtering ==========

	let systemPrompt = `You are a precise secure code analyzer. Detect REAL security vulnerabilities in code and return ONLY a valid JSON array.

IMPORTANT RULES:
1. Only report issues that are genuinely exploitable. Do NOT flag safe patterns, hardcoded values, or properly sanitized inputs.
2. If the code is secure and has no vulnerabilities, you MUST return an empty array: []
3. Be specific: name the exact vulnerability type (e.g., "SQL Injection", "XSS", "Command Injection") and explain WHY it is exploitable.
4. Do NOT report theoretical risks, best-practice suggestions, or style issues. Only report actual security vulnerabilities.

CRITICAL: Your response MUST be ONLY a valid JSON array. No explanatory text, no markdown formatting, no comments.

Response format:
[
	{
		"message": "Description of the vulnerability and why it is exploitable",
		"startLine": 1,
		"endLine": 3
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

	passResults.forEach((results, i) => {
		logger.info(`Pass ${i + 1}: found ${results.length} issues`);
	});

	const consensus = applyConsensusFilter(passResults);
	logger.info(`Consensus: ${consensus.length} issues confirmed across passes`);

	if (consensus.length === 0) {
		cache.set(code, model, consensus, ragEnabled);
		return consensus;
	}

	// ========== STAGE 2: Targeted repair generation ==========

	logger.info(`Generating targeted repairs for ${consensus.length} confirmed issues...`);

	const repairPromises = consensus.map(issue =>
		generateRepair(model, code, issue, ragManager)
	);

	const repairs = await Promise.all(repairPromises);

	// Merge repairs into issues
	const finalResults = consensus.map((issue, i) => ({
		...issue,
		suggestedFix: repairs[i] || issue.suggestedFix
	}));

	const repairCount = repairs.filter(r => r !== undefined).length;
	logger.info(`Repairs generated: ${repairCount}/${consensus.length}`);

	// Cache the final result
	cache.set(code, model, finalResults, ragEnabled);
	logger.debug('Cached analysis result with repairs');

	return finalResults;
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
