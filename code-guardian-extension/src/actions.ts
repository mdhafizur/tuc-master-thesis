import * as vscode from 'vscode';

/**
 * Provides quick fix actions for security issues detected by the analyzer.
 * These are shown in the lightbulb (💡) menu in VS Code when diagnostics are available.
 */
export function provideFixes(): vscode.CodeActionProvider {
	return {
		/**
		 * This method is triggered by VS Code when it wants to know what fixes are available for a given range.
		 * It receives the current document, the selected range, and diagnostics affecting that range.
		 */
		provideCodeActions(document, range, context) {
			const actions: vscode.CodeAction[] = [];

			for (const diagnostic of context.diagnostics) {
				// Check if this diagnostic is one of our secure fix suggestions
				if (diagnostic.code === 'codeSecurity.fixSuggestion') {

					// Create a new CodeAction of kind "QuickFix"
					const fix = new vscode.CodeAction('💡 Apply Secure Fix', vscode.CodeActionKind.QuickFix);

					// Attach the diagnostic that this fix resolves
					fix.diagnostics = [diagnostic];

					// Mark this as a preferred fix if multiple options exist
					fix.isPreferred = true;

					// Extract the suggested replacement code from the related information (e.g., LLM output)
					const fixText = diagnostic.relatedInformation?.[0]?.message ?? '';

					// Create a WorkspaceEdit to replace the vulnerable code with the fix
					const edit = new vscode.WorkspaceEdit();
					edit.replace(document.uri, diagnostic.range, fixText);

					// Attach the edit to the CodeAction
					fix.edit = edit;

					// Add this fix to the list of available actions
					actions.push(fix);
				}
			}

			return actions;
		}
	};
}
