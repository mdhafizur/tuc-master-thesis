import * as vscode from 'vscode';
import ollama from 'ollama';
import { RAGManager } from './ragManager';
import { validateRepair } from './repairValidator';
import { getLogger } from './logger';

/**
 * Agentic security assistant for the Contextual Q&A panel.
 *
 * Unlike the one-shot Q&A (read every file up front, stuff it into a single
 * prompt, answer once), this drives a read→reason→act loop: each turn the local
 * model emits a single structured-JSON action, the extension executes the
 * matching workspace tool, feeds the observation back, and repeats until the
 * model calls `finish` or the step budget runs out. Edits are never applied
 * automatically — the model can only *propose* a range-based edit, which the UI
 * surfaces with Preview-diff / Apply buttons.
 *
 * Structured-JSON turns (rather than native tool-calling) are used because they
 * are markedly more reliable on the small local models the thesis targets, and
 * they reuse the constrained-decoding pattern already established in analyzer.ts.
 */

/** Hard ceiling on tool-calling turns, so a confused model cannot loop forever. */
const MAX_STEPS = 8;
/** Cap on how many characters of any single observation are fed back to the model. */
const MAX_OBSERVATION_CHARS = 8000;
/** Per-turn inference timeout (ms). */
const STEP_TIMEOUT_MS = 60000;

/** A range-based edit the agent wants to make. Never applied without user action. */
export interface ProposedEdit {
	id: string;
	/** Absolute path of the target file. */
	path: string;
	/** Workspace-relative path, for display. */
	relativePath: string;
	/** 1-based inclusive line range to replace. */
	startLine: number;
	endLine: number;
	/** Replacement text for that range. */
	newText: string;
	/** Human-readable explanation of the change. */
	description: string;
	/** Whether the replacement parses as valid JS/TS (from repairValidator). */
	applicable: boolean;
	/** Reason the edit is not applicable, if any. */
	notApplicableReason?: string;
}

/** A single step in the agent transcript, surfaced to the UI as it happens. */
export interface AgentStep {
	tool: string;
	thought?: string;
	summary: string;
}

export interface AgentResult {
	answer: string;
	edits: ProposedEdit[];
	steps: AgentStep[];
}

type StepListener = (step: AgentStep) => void;

/** Tools the model may call. `finish` ends the loop. */
const TOOL_NAMES = ['list_dir', 'read_file', 'search', 'get_diagnostics', 'propose_edit', 'finish'] as const;

/**
 * Loose schema for a single agent turn. Ollama's structured-output mode pins the
 * top-level shape; `args` is left open because its fields vary per tool. A
 * tolerant parser (parseAction) recovers from the occasional malformed turn.
 */
const ACTION_SCHEMA = {
	type: 'object',
	properties: {
		thought: { type: 'string' },
		tool: { type: 'string', enum: [...TOOL_NAMES] },
		args: { type: 'object' }
	},
	required: ['tool', 'args']
} as const;

interface AgentAction {
	thought?: string;
	tool: string;
	args: Record<string, unknown>;
}

const SYSTEM_PROMPT = `You are Code Guardian, a security assistant embedded in VS Code. You investigate a JavaScript/TypeScript workspace to answer the user's question and, where appropriate, propose secure fixes.

You work in a loop. On every turn you respond with ONE JSON object and nothing else:
{ "thought": "<brief reasoning>", "tool": "<tool name>", "args": { ... } }

Available tools:
- list_dir { "path": "relative/dir" } — list a directory's entries.
- read_file { "path": "relative/file.js", "startLine"?: number, "endLine"?: number } — read a file; output is annotated with 1-based line numbers.
- search { "query": "text or regex", "maxResults"?: number } — search file contents across the workspace.
- get_diagnostics { "path": "relative/file.js" } — list Code Guardian's existing findings for a file.
- propose_edit { "path": "relative/file.js", "startLine": number, "endLine": number, "newText": "<replacement>", "description": "<what and why>" } — propose replacing an inclusive 1-based line range. This does NOT apply the change; the user reviews and applies it.
- finish { "answer": "<final answer in Markdown>" } — end the session.

Rules:
- Read before you edit. Use line numbers from read_file when choosing edit ranges.
- propose_edit's newText must be complete, valid code for the replaced range, indented to match the original.
- Prefer small, targeted edits over rewriting whole files.
- Propose an edit only when the user asks for a fix or it clearly resolves a security issue you found.
- When you have enough information, call finish with a clear Markdown answer that references the files and lines involved.
- Respond with the JSON object only — no prose, no code fences.`;

/**
 * Resolves a model-supplied path to an absolute path inside a workspace folder,
 * rejecting anything that escapes the workspace (path-traversal guard).
 */
function resolveWorkspacePath(rawPath: string): vscode.Uri | undefined {
	const folders = vscode.workspace.workspaceFolders;
	if (!folders || folders.length === 0) {
		return undefined;
	}
	const cleaned = rawPath.trim().replace(/^[./\\]+/, '');
	for (const folder of folders) {
		const candidate = vscode.Uri.joinPath(folder.uri, cleaned);
		const root = folder.uri.fsPath.replace(/[/\\]+$/, '');
		// Containment check: the resolved path must stay within the folder root.
		if (candidate.fsPath === root || candidate.fsPath.startsWith(root + '/') || candidate.fsPath.startsWith(root + '\\')) {
			return candidate;
		}
	}
	return undefined;
}

function relativeOf(uri: vscode.Uri): string {
	return vscode.workspace.asRelativePath(uri, false);
}

function truncate(text: string, max = MAX_OBSERVATION_CHARS): string {
	if (text.length <= max) {
		return text;
	}
	return text.slice(0, max) + `\n… (truncated, ${text.length - max} more chars)`;
}

const SKIP_DIRS = new Set(['node_modules', 'dist', 'build', 'out', 'target', '.git', '.vscode-test', 'coverage', '__pycache__']);
const SEARCHABLE_GLOB = '**/*.{js,jsx,ts,tsx,json,html,env,yml,yaml}';

/** Tolerantly parse a single agent turn from the model's raw text. */
function parseAction(raw: string): AgentAction | undefined {
	let text = raw.trim();
	// Strip markdown fences the model sometimes adds despite instructions.
	text = text.replace(/^```(?:json)?/i, '').replace(/```$/i, '').trim();
	const tryParse = (s: string): AgentAction | undefined => {
		try {
			const obj = JSON.parse(s);
			if (obj && typeof obj.tool === 'string') {
				return { thought: obj.thought, tool: obj.tool, args: obj.args ?? {} };
			}
		} catch {
			// fall through
		}
		return undefined;
	};
	const direct = tryParse(text);
	if (direct) {
		return direct;
	}
	// Fallback: extract the first {...} block.
	const start = text.indexOf('{');
	const end = text.lastIndexOf('}');
	if (start !== -1 && end > start) {
		return tryParse(text.slice(start, end + 1));
	}
	return undefined;
}

/** Reads a file and annotates each line with its 1-based number. */
async function toolReadFile(args: Record<string, unknown>): Promise<string> {
	const uri = resolveWorkspacePath(String(args.path ?? ''));
	if (!uri) {
		return `Error: path "${String(args.path)}" is outside the workspace or no workspace is open.`;
	}
	let content: string;
	try {
		content = Buffer.from(await vscode.workspace.fs.readFile(uri)).toString('utf8');
	} catch (e) {
		return `Error reading ${relativeOf(uri)}: ${e instanceof Error ? e.message : String(e)}`;
	}
	const lines = content.split('\n');
	const start = typeof args.startLine === 'number' ? Math.max(1, args.startLine) : 1;
	const end = typeof args.endLine === 'number' ? Math.min(lines.length, args.endLine) : lines.length;
	const numbered = lines
		.slice(start - 1, end)
		.map((line, i) => `${start + i}: ${line}`)
		.join('\n');
	return truncate(`File ${relativeOf(uri)} (lines ${start}-${end} of ${lines.length}):\n${numbered}`);
}

async function toolListDir(args: Record<string, unknown>): Promise<string> {
	const uri = resolveWorkspacePath(String(args.path ?? '.'));
	if (!uri) {
		return `Error: path "${String(args.path)}" is outside the workspace or no workspace is open.`;
	}
	try {
		const entries = await vscode.workspace.fs.readDirectory(uri);
		const listed = entries
			.filter(([name]) => !SKIP_DIRS.has(name))
			.map(([name, type]) => (type & vscode.FileType.Directory ? `${name}/` : name))
			.sort();
		return truncate(`Directory ${relativeOf(uri)}:\n${listed.join('\n') || '(empty)'}`);
	} catch (e) {
		return `Error listing ${relativeOf(uri)}: ${e instanceof Error ? e.message : String(e)}`;
	}
}

async function toolSearch(args: Record<string, unknown>): Promise<string> {
	const query = String(args.query ?? '').trim();
	if (!query) {
		return 'Error: search requires a non-empty "query".';
	}
	const maxResults = typeof args.maxResults === 'number' ? Math.min(50, args.maxResults) : 20;
	let regex: RegExp;
	try {
		regex = new RegExp(query, 'i');
	} catch {
		// Treat as a literal if it is not a valid regex.
		regex = new RegExp(query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');
	}
	const files = await vscode.workspace.findFiles(SEARCHABLE_GLOB, '**/{node_modules,dist,build,out,.git}/**', 400);
	const hits: string[] = [];
	for (const file of files) {
		if (hits.length >= maxResults) {
			break;
		}
		let content: string;
		try {
			content = Buffer.from(await vscode.workspace.fs.readFile(file)).toString('utf8');
		} catch {
			continue;
		}
		const lines = content.split('\n');
		for (let i = 0; i < lines.length && hits.length < maxResults; i++) {
			if (regex.test(lines[i])) {
				hits.push(`${relativeOf(file)}:${i + 1}: ${lines[i].trim().slice(0, 200)}`);
			}
		}
	}
	return truncate(hits.length ? `Found ${hits.length} match(es):\n${hits.join('\n')}` : `No matches for "${query}".`);
}

async function toolGetDiagnostics(args: Record<string, unknown>): Promise<string> {
	const uri = resolveWorkspacePath(String(args.path ?? ''));
	if (!uri) {
		return `Error: path "${String(args.path)}" is outside the workspace or no workspace is open.`;
	}
	const diags = vscode.languages
		.getDiagnostics(uri)
		.filter(d => d.source === 'CodeGuardian');
	if (diags.length === 0) {
		return `No Code Guardian diagnostics for ${relativeOf(uri)}.`;
	}
	const listed = diags
		.map(d => `L${d.range.start.line + 1}-${d.range.end.line + 1}: ${d.message}`)
		.join('\n');
	return truncate(`Code Guardian diagnostics for ${relativeOf(uri)}:\n${listed}`);
}

/**
 * Registers a proposed edit. Validates the replacement text and clamps the range
 * to the file; does NOT modify the file. Returns the edit plus an observation.
 */
async function toolProposeEdit(
	args: Record<string, unknown>,
	makeId: () => string
): Promise<{ edit?: ProposedEdit; observation: string }> {
	const uri = resolveWorkspacePath(String(args.path ?? ''));
	if (!uri) {
		return { observation: `Error: path "${String(args.path)}" is outside the workspace or no workspace is open.` };
	}
	const startLine = Number(args.startLine);
	const endLine = Number(args.endLine);
	const newText = typeof args.newText === 'string' ? args.newText : undefined;
	const description = String(args.description ?? 'Proposed secure fix');
	if (!Number.isFinite(startLine) || !Number.isFinite(endLine) || startLine < 1 || endLine < startLine) {
		return { observation: 'Error: propose_edit requires valid 1-based startLine ≤ endLine.' };
	}
	if (newText === undefined) {
		return { observation: 'Error: propose_edit requires a "newText" string.' };
	}
	let lineCount: number;
	try {
		const content = Buffer.from(await vscode.workspace.fs.readFile(uri)).toString('utf8');
		lineCount = content.split('\n').length;
	} catch (e) {
		return { observation: `Error reading ${relativeOf(uri)}: ${e instanceof Error ? e.message : String(e)}` };
	}
	if (startLine > lineCount) {
		return { observation: `Error: startLine ${startLine} is past end of file (${lineCount} lines).` };
	}
	const validation = validateRepair(newText);
	const edit: ProposedEdit = {
		id: makeId(),
		path: uri.fsPath,
		relativePath: relativeOf(uri),
		startLine,
		endLine: Math.min(endLine, lineCount),
		newText,
		description,
		applicable: validation.valid,
		notApplicableReason: validation.valid ? undefined : validation.reason
	};
	const note = validation.valid
		? 'The replacement parses as valid code and is ready for the user to apply.'
		: `Warning: the replacement did not parse (${validation.reason}); it will be shown but flagged as not auto-applicable.`;
	return {
		edit,
		observation: `Registered proposed edit for ${edit.relativePath} lines ${edit.startLine}-${edit.endLine}. ${note}`
	};
}

function chatWithTimeout(model: string, messages: { role: string; content: string }[]): Promise<string> {
	const call = ollama
		.chat({
			model,
			messages,
			format: ACTION_SCHEMA as unknown as Record<string, unknown>,
			options: { temperature: 0 }
		})
		.then(r => r.message.content);
	const timeout = new Promise<string>((_, reject) =>
		setTimeout(() => reject(new Error('Agent step timed out')), STEP_TIMEOUT_MS)
	);
	return Promise.race([call, timeout]);
}

/**
 * Runs the agentic loop for one user question.
 *
 * @param question     The user's question.
 * @param contextPaths File/folder paths the user selected as starting context.
 * @param model        The Ollama model to drive the loop.
 * @param ragManager   Optional RAG manager (used to enrich the system prompt).
 * @param onStep       Called as each tool step completes, for live UI updates.
 */
export async function runSecurityAgent(
	question: string,
	contextPaths: string[],
	model: string,
	ragManager: RAGManager | undefined,
	onStep: StepListener,
	history: { role: string; content: string }[] = []
): Promise<AgentResult> {
	const logger = getLogger();
	const steps: AgentStep[] = [];
	const edits: ProposedEdit[] = [];
	let editCounter = 0;
	const makeId = () => `edit-${++editCounter}`;

	let systemPrompt = SYSTEM_PROMPT;
	if (ragManager) {
		try {
			systemPrompt = await ragManager.generateEnhancedPrompt(SYSTEM_PROMPT, question);
		} catch (e) {
			logger.warn(`Agent: RAG enrichment failed, continuing without it: ${e}`);
		}
	}

	const contextList = contextPaths.length
		? contextPaths.map(p => `- ${vscode.workspace.asRelativePath(p, false)}`).join('\n')
		: '(none — explore from the workspace root with list_dir)';

	const messages: { role: string; content: string }[] = [
		{ role: 'system', content: systemPrompt },
		// Prior turns of this conversation (questions and final answers) so
		// follow-ups keep their context.
		...history,
		{
			role: 'user',
			content: `Question: ${question}\n\nStarting context the user selected:\n${contextList}\n\nBegin by inspecting the relevant files, then answer. Respond with one JSON action.`
		}
	];

	for (let step = 0; step < MAX_STEPS; step++) {
		let raw: string;
		try {
			raw = await chatWithTimeout(model, messages);
		} catch (e) {
			const msg = e instanceof Error ? e.message : String(e);
			logger.error('Agent: inference failed', e);
			return { answer: `The assistant could not complete the request: ${msg}`, edits, steps };
		}

		const action = parseAction(raw);
		if (!action) {
			messages.push({ role: 'assistant', content: raw });
			messages.push({
				role: 'user',
				content: 'That was not valid JSON. Respond with exactly one JSON action object.'
			});
			continue;
		}

		messages.push({ role: 'assistant', content: JSON.stringify(action) });

		if (action.tool === 'finish') {
			const answer = String(action.args.answer ?? 'Done.');
			steps.push({ tool: 'finish', thought: action.thought, summary: 'Completed analysis.' });
			onStep(steps[steps.length - 1]);
			return { answer, edits, steps };
		}

		let observation: string;
		let summary: string;
		switch (action.tool) {
			case 'read_file':
				observation = await toolReadFile(action.args);
				summary = `Read ${String(action.args.path ?? '?')}`;
				break;
			case 'list_dir':
				observation = await toolListDir(action.args);
				summary = `Listed ${String(action.args.path ?? '.')}`;
				break;
			case 'search':
				observation = await toolSearch(action.args);
				summary = `Searched "${String(action.args.query ?? '')}"`;
				break;
			case 'get_diagnostics':
				observation = await toolGetDiagnostics(action.args);
				summary = `Checked diagnostics for ${String(action.args.path ?? '?')}`;
				break;
			case 'propose_edit': {
				const result = await toolProposeEdit(action.args, makeId);
				if (result.edit) {
					edits.push(result.edit);
				}
				observation = result.observation;
				summary = `Proposed edit to ${String(action.args.path ?? '?')}`;
				break;
			}
			default:
				observation = `Unknown tool "${action.tool}". Valid tools: ${TOOL_NAMES.join(', ')}.`;
				summary = `Unknown tool: ${action.tool}`;
		}

		const stepEntry: AgentStep = { tool: action.tool, thought: action.thought, summary };
		steps.push(stepEntry);
		onStep(stepEntry);

		messages.push({ role: 'user', content: `OBSERVATION:\n${observation}` });
	}

	// Step budget exhausted — ask for a final synthesis without more tools.
	messages.push({
		role: 'user',
		content: 'You have reached the step limit. Summarize your findings and recommendations now as plain Markdown (no JSON, no tool calls).'
	});
	try {
		const final = await ollama.chat({ model, messages, options: { temperature: 0 } });
		return { answer: final.message.content, edits, steps };
	} catch (e) {
		const msg = e instanceof Error ? e.message : String(e);
		return { answer: `Reached the step limit and could not synthesize a final answer: ${msg}`, edits, steps };
	}
}

const CHAT_SYSTEM_PROMPT = `You are Code Guardian, a friendly security assistant embedded in VS Code. Hold a normal conversation: answer questions about security concepts, explain prior findings, and discuss code clearly and concisely in Markdown. Be direct and helpful. If the user asks you to scan, analyze, detect vulnerabilities in, or fix specific code, let them know you can do that when they ask for an analysis or attach files as context.`;

/**
 * A plain conversational reply — no tools, no structured output. Used for
 * general questions and follow-ups that do not require inspecting the workspace.
 */
export async function runChat(
	question: string,
	model: string,
	ragManager: RAGManager | undefined,
	history: { role: string; content: string }[] = []
): Promise<string> {
	const logger = getLogger();
	let systemPrompt = CHAT_SYSTEM_PROMPT;
	if (ragManager) {
		try {
			systemPrompt = await ragManager.generateEnhancedPrompt(CHAT_SYSTEM_PROMPT, question);
		} catch (e) {
			logger.warn(`Chat: RAG enrichment failed, continuing without it: ${e}`);
		}
	}
	const messages = [
		{ role: 'system', content: systemPrompt },
		...history,
		{ role: 'user', content: question }
	];
	const call = ollama.chat({ model, messages, options: { temperature: 0.3 } }).then(r => r.message.content);
	const timeout = new Promise<string>((_, reject) =>
		setTimeout(() => reject(new Error('Chat request timed out')), STEP_TIMEOUT_MS)
	);
	return Promise.race([call, timeout]);
}

/** Translates an edit's 1-based inclusive line range into a document Range. */
function editRange(edit: ProposedEdit, doc: vscode.TextDocument): vscode.Range {
	const startLine = Math.max(0, Math.min(doc.lineCount - 1, edit.startLine - 1));
	const endLine = Math.max(startLine, Math.min(doc.lineCount - 1, edit.endLine - 1));
	const endChar = doc.lineAt(endLine).range.end.character;
	return new vscode.Range(startLine, 0, endLine, endChar);
}

/** Computes the full file content as it would look after applying the edit. */
function fileAfterEdit(original: string, edit: ProposedEdit): string {
	const lines = original.split('\n');
	const start = Math.max(0, edit.startLine - 1);
	const end = Math.min(lines.length, edit.endLine);
	return [...lines.slice(0, start), edit.newText, ...lines.slice(end)].join('\n');
}

/** Applies a proposed edit to its file via WorkspaceEdit and reveals the file. */
export async function applyProposedEdit(edit: ProposedEdit): Promise<boolean> {
	const uri = vscode.Uri.file(edit.path);
	const doc = await vscode.workspace.openTextDocument(uri);
	const wsEdit = new vscode.WorkspaceEdit();
	wsEdit.replace(uri, editRange(edit, doc), edit.newText);
	const ok = await vscode.workspace.applyEdit(wsEdit);
	if (ok) {
		await vscode.window.showTextDocument(doc, { preview: false });
	}
	return ok;
}

/**
 * Backs the agent's diff previews with in-memory content (no temp files), so the
 * user can inspect a proposed edit as a whole-file before/after diff.
 */
export class AgentDiffContentProvider implements vscode.TextDocumentContentProvider {
	public static readonly scheme = 'code-guardian-agent-diff';
	private nextId = 1;
	private readonly store = new Map<string, { original: string; fix: string }>();
	private readonly emitter = new vscode.EventEmitter<vscode.Uri>();
	public readonly onDidChange = this.emitter.event;

	public register(original: string, fix: string): string {
		const id = String(this.nextId++);
		this.store.set(id, { original, fix });
		if (this.store.size > 32) {
			const oldest = this.store.keys().next().value;
			if (oldest !== undefined) {
				this.store.delete(oldest);
			}
		}
		return id;
	}

	public static uri(id: string, side: 'original' | 'fix'): vscode.Uri {
		return vscode.Uri.parse(`${AgentDiffContentProvider.scheme}:/${side}/${id}`);
	}

	public provideTextDocumentContent(uri: vscode.Uri): string {
		const segments = uri.path.split('/').filter(Boolean);
		if (segments.length !== 2) {
			return '';
		}
		const [side, id] = segments;
		const entry = this.store.get(id);
		if (!entry) {
			return '';
		}
		return side === 'original' ? entry.original : entry.fix;
	}
}

/** Opens a whole-file before/after diff for a proposed edit. */
export async function previewProposedEdit(edit: ProposedEdit, provider: AgentDiffContentProvider): Promise<void> {
	const uri = vscode.Uri.file(edit.path);
	const doc = await vscode.workspace.openTextDocument(uri);
	const original = doc.getText();
	const after = fileAfterEdit(original, edit);
	const id = provider.register(original, after);
	await vscode.commands.executeCommand(
		'vscode.diff',
		AgentDiffContentProvider.uri(id, 'original'),
		AgentDiffContentProvider.uri(id, 'fix'),
		`Code Guardian: ${edit.relativePath} (proposed fix)`
	);
}
