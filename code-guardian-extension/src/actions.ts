import * as vscode from 'vscode';
import { generateFunctionRepair } from './analyzer';
import { getCurrentModel } from './modelManager';
import { RAGManager } from './ragManager';
import { getEnclosingFunction } from './functionExtractor';
import { getLogger } from './logger';

/**
 * Quick-fix actions for security diagnostics. Apply / Preview both replace the
 * ENTIRE enclosing function (not just the diagnostic's line range) using a
 * whole-function rewrite from the LLM. Function-level replacement avoids the
 * "echoed context" and "dropped wrapper" failure modes that surgical line
 * replacements suffer from — the function is the unit of context, so the
 * model has nothing outside it to leak in.
 *
 * The repair is generated lazily the first time the user opens the lightbulb
 * on a diagnostic and cached per (uri, function-range, issue-message) so the
 * second invocation (e.g. Preview then Apply) doesn't re-issue the LLM call.
 */

type RagProvider = () => Promise<RAGManager | undefined>;

interface CachedRepair {
	functionRange: vscode.Range;
	rewrittenFunction: string;
}

const repairCache = new Map<string, CachedRepair>();

function repairKey(uri: vscode.Uri, functionRange: vscode.Range, message: string): string {
	const r = `${functionRange.start.line}:${functionRange.start.character}-${functionRange.end.line}:${functionRange.end.character}`;
	return `${uri.toString()}|${r}|${message}`;
}

/**
 * Resolves the function enclosing a diagnostic and produces (or returns from
 * cache) a rewritten version that fixes the reported vulnerability.
 */
async function getOrGenerateFunctionRepair(
	document: vscode.TextDocument,
	diagnosticRange: vscode.Range,
	message: string,
	getRag: RagProvider
): Promise<CachedRepair | undefined> {
	const logger = getLogger();
	logger.info(`SecureFix: looking up enclosing function at ${diagnosticRange.start.line}:${diagnosticRange.start.character} for "${message}"`);

	// The diagnostic range is line-based, so its start often lands on a column
	// that's BEFORE the actual function's start offset (e.g. column 0 of an
	// `app.get("/x", (req,res) => { … })` line is on `app`, but the arrow
	// function node starts at `(req`). And the model can put the range on the
	// declaration line itself, which is technically outside the function body.
	// Walk a sequence of positions through the range until the AST recognizes
	// one as inside a function.
	const candidates: vscode.Position[] = [];
	const seenKeys = new Set<string>();
	const pushPos = (p: vscode.Position) => {
		const key = `${p.line}:${p.character}`;
		if (!seenKeys.has(key)) {
			seenKeys.add(key);
			candidates.push(p);
		}
	};
	for (let line = diagnosticRange.start.line; line <= diagnosticRange.end.line; line++) {
		if (line < 0 || line >= document.lineCount) {
			continue;
		}
		const textLine = document.lineAt(line);
		pushPos(new vscode.Position(line, textLine.firstNonWhitespaceCharacterIndex));
		pushPos(textLine.range.end);
	}
	pushPos(diagnosticRange.start);
	pushPos(diagnosticRange.end);

	let enclosing: ReturnType<typeof getEnclosingFunction> = null;
	for (const pos of candidates) {
		enclosing = getEnclosingFunction(document, pos);
		if (enclosing) {
			logger.info(`SecureFix: enclosing-function lookup succeeded at ${pos.line}:${pos.character}`);
			break;
		}
	}
	if (!enclosing) {
		logger.warn(`SecureFix: no enclosing function found for diagnostic at ${diagnosticRange.start.line}:${diagnosticRange.start.character}`);
		vscode.window.showWarningMessage(
			'Code Guardian could not locate an enclosing function for this issue.'
		);
		return undefined;
	}

	logger.info(`SecureFix: enclosing function spans ${enclosing.range.start.line}-${enclosing.range.end.line} (${enclosing.code.length} chars)`);

	const key = repairKey(document.uri, enclosing.range, message);
	const cached = repairCache.get(key);
	if (cached) {
		logger.info('SecureFix: reusing cached repair');
		return cached;
	}

	const model = getCurrentModel();
	const ragManager = await getRag();

	logger.info(`SecureFix: requesting function repair from model ${model}`);
	const rewritten = await vscode.window.withProgress(
		{
			location: vscode.ProgressLocation.Window,
			title: '🛡️ Code Guardian: rewriting function with secure fix…'
		},
		() => generateFunctionRepair(model, enclosing.code, message, ragManager)
	);

	if (!rewritten) {
		logger.warn(`SecureFix: function repair returned no fix for "${message}"`);
		return undefined;
	}

	logger.info(`SecureFix: received rewrite (${rewritten.length} chars)`);
	const result: CachedRepair = { functionRange: enclosing.range, rewrittenFunction: rewritten };
	repairCache.set(key, result);
	return result;
}

export function provideFixes(): vscode.CodeActionProvider {
	return {
		provideCodeActions(document, _range, context) {
			const actions: vscode.CodeAction[] = [];

			for (const diagnostic of context.diagnostics) {
				if (diagnostic.code !== 'codeSecurity.fixSuggestion') {
					continue;
				}

				// A single Code Guardian quick-fix on the lightbulb.
				const fix = new vscode.CodeAction('🛡️ Code Guardian: Fix', vscode.CodeActionKind.QuickFix);
				fix.diagnostics = [diagnostic];
				fix.isPreferred = true;
				fix.command = {
					title: 'Code Guardian: Fix',
					command: 'codeSecurity.applySecureFix',
					arguments: [document.uri, diagnostic.range, diagnostic.message]
				};
				actions.push(fix);
			}

			return actions;
		}
	};
}

export function registerSecureFixCommands(
	context: vscode.ExtensionContext,
	getRag: RagProvider
): void {
	const provider = new SecureFixDiffContentProvider();
	context.subscriptions.push(
		vscode.workspace.registerTextDocumentContentProvider(SecureFixDiffContentProvider.scheme, provider)
	);

	context.subscriptions.push(
		vscode.commands.registerCommand(
			'codeSecurity.applySecureFix',
			async (uri: vscode.Uri, diagnosticRange: vscode.Range, message: string) => {
				const logger = getLogger();
				logger.info(`SecureFix: applySecureFix invoked for ${uri.toString()}`);
				const document = await vscode.workspace.openTextDocument(uri);
				const repair = await getOrGenerateFunctionRepair(document, diagnosticRange, message, getRag);
				if (!repair) {
					vscode.window.showWarningMessage('Code Guardian could not generate a secure fix for this function.');
					return;
				}
				const edit = new vscode.WorkspaceEdit();
				edit.replace(uri, repair.functionRange, repair.rewrittenFunction);
				const ok = await vscode.workspace.applyEdit(edit);
				logger.info(`SecureFix: applyEdit returned ${ok}`);
				if (!ok) {
					vscode.window.showWarningMessage('Code Guardian: the workspace rejected the edit. Is the file saved / writable?');
				}
			}
		)
	);

	context.subscriptions.push(
		vscode.commands.registerCommand(
			'codeSecurity.previewSecureFix',
			async (uri: vscode.Uri, diagnosticRange: vscode.Range, message: string) => {
				const document = await vscode.workspace.openTextDocument(uri);
				const repair = await getOrGenerateFunctionRepair(document, diagnosticRange, message, getRag);
				if (!repair) {
					vscode.window.showWarningMessage('Code Guardian could not generate a secure fix for this function.');
					return;
				}
				const originalFunction = document.getText(repair.functionRange);
				const id = provider.register(originalFunction, repair.rewrittenFunction);
				const leftUri = SecureFixDiffContentProvider.uri(id, 'original');
				const rightUri = SecureFixDiffContentProvider.uri(id, 'fix');
				await vscode.commands.executeCommand(
					'vscode.diff',
					leftUri,
					rightUri,
					'Secure Fix Preview: original ↔ proposed'
				);
			}
		)
	);
}

/**
 * Backs the diff editor with in-memory content so the preview never writes a
 * temp file. Each preview gets a fresh ID; old entries are GC'd lazily.
 */
class SecureFixDiffContentProvider implements vscode.TextDocumentContentProvider {
	public static readonly scheme = 'code-guardian-diff';
	private nextId = 1;
	private store = new Map<string, { original: string; fix: string }>();
	private readonly emitter = new vscode.EventEmitter<vscode.Uri>();
	public readonly onDidChange = this.emitter.event;

	public register(original: string, fix: string): string {
		const id = String(this.nextId++);
		this.store.set(id, { original, fix });
		if (this.store.size > 32) {
			const oldestKey = this.store.keys().next().value;
			if (oldestKey !== undefined) {
				this.store.delete(oldestKey);
			}
		}
		return id;
	}

	public static uri(id: string, side: 'original' | 'fix'): vscode.Uri {
		return vscode.Uri.parse(`${SecureFixDiffContentProvider.scheme}:/${side}/${id}`);
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
