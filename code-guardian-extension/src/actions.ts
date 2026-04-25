import * as vscode from 'vscode';

/**
 * Provides quick fix actions for security issues detected by the analyzer.
 * These are shown in the lightbulb (💡) menu in VS Code when diagnostics are available.
 *
 * Two actions are surfaced per applicable diagnostic:
 *   - "Apply Secure Fix" — auto-replaces the vulnerable range with the fix
 *   - "Preview Secure Fix (diff)" — opens a side-by-side diff before any change
 *     so the developer can review what would be applied (Phase 5 R4 polish).
 */
export function provideFixes(): vscode.CodeActionProvider {
	return {
		provideCodeActions(document, range, context) {
			const actions: vscode.CodeAction[] = [];

			for (const diagnostic of context.diagnostics) {
				if (diagnostic.code !== 'codeSecurity.fixSuggestion') {
					continue;
				}

				const fixText = diagnostic.relatedInformation?.[0]?.message ?? '';
				if (!fixText) {
					continue;
				}

				// Action 1: direct apply (existing behavior)
				const apply = new vscode.CodeAction('💡 Apply Secure Fix', vscode.CodeActionKind.QuickFix);
				apply.diagnostics = [diagnostic];
				apply.isPreferred = true;
				const edit = new vscode.WorkspaceEdit();
				edit.replace(document.uri, diagnostic.range, fixText);
				apply.edit = edit;
				actions.push(apply);

				// Action 2: preview as side-by-side diff before applying
				const preview = new vscode.CodeAction('🔍 Preview Secure Fix (diff)', vscode.CodeActionKind.QuickFix);
				preview.diagnostics = [diagnostic];
				preview.command = {
					title: 'Preview Secure Fix',
					command: 'codeSecurity.previewSecureFix',
					arguments: [document.uri, diagnostic.range, fixText]
				};
				actions.push(preview);
			}

			return actions;
		}
	};
}

/**
 * Registers the `codeSecurity.previewSecureFix` command. Builds two ephemeral
 * documents (the original vulnerable slice and the proposed fix) and opens
 * VS Code's built-in diff editor between them. Nothing is written to the user's
 * file unless they then explicitly invoke the apply action.
 */
export function registerSecureFixPreviewCommand(context: vscode.ExtensionContext): void {
	const provider = new SecureFixDiffContentProvider();
	context.subscriptions.push(
		vscode.workspace.registerTextDocumentContentProvider(SecureFixDiffContentProvider.scheme, provider)
	);
	context.subscriptions.push(
		vscode.commands.registerCommand(
			'codeSecurity.previewSecureFix',
			async (uri: vscode.Uri, range: vscode.Range, fixText: string) => {
				const document = await vscode.workspace.openTextDocument(uri);
				const originalSlice = document.getText(range);
				const id = provider.register(originalSlice, fixText);
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
		// Keep at most ~32 previews in memory.
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
