import * as vscode from 'vscode';
import { analyzeCodeWithLLM, SecurityIssue } from './analyzer';

import { getLogger } from './logger';
/**
 * Analyzes a given piece of code using an LLM, parses the issues,
 * and reports them as diagnostics in the VS Code editor.
 *
 * @param code - The code to analyze (can be full file or a function snippet).
 * @param doc - The active text document.
 * @param collection - The diagnostic collection to update.
 * @param lineOffset - The starting line number in the full document (used when analyzing a function snippet).
 */
export async function analyzeAndReportDiagnosticsFromText(
	code: string | null,
	doc: vscode.TextDocument,
	collection: vscode.DiagnosticCollection,
	lineOffset: number = 0 // Used to shift line numbers if analyzing a sub-block
) {
	if (!code) { return; }; // Skip analysis if no code is provided

	// Run the LLM analysis and retrieve detected security issues
	const issues: SecurityIssue[] = await analyzeCodeWithLLM(code);

	const diagnostics: vscode.Diagnostic[] = issues.map(issue => {
		/**
		 * Adjust line numbers based on offset (e.g., if this is a function extracted from the middle of the file).
		 * - LLM returns 1-based line numbers.
		 * - VS Code expects 0-based line numbers.
		 */
		const startLine = Math.max(0, Math.min(doc.lineCount - 1, lineOffset + issue.startLine - 1));
		const endLine = Math.max(0, Math.min(doc.lineCount - 1, lineOffset + issue.endLine - 1));

		// Create positions for the range of the issue
		const start = new vscode.Position(startLine, 0);
		const endLineText = doc.lineAt(endLine);
		const end = new vscode.Position(
			endLine,
			endLineText.range.end.character // Span to the end of the line
		);

		const range = new vscode.Range(start, end);

		// Create a diagnostic warning for the issue
		const diag = new vscode.Diagnostic(
			range,
			issue.message,
			vscode.DiagnosticSeverity.Warning
		);

		// Set the source to identify our diagnostics
		diag.source = 'CodeGuardian';

		// If the LLM suggests a fix, attach it as a quick fix option
		if (issue.suggestedFix) {
			diag.code = 'codeSecurity.fixSuggestion';

			diag.relatedInformation = [
				new vscode.DiagnosticRelatedInformation(
					new vscode.Location(doc.uri, range),
					issue.suggestedFix
				)
			];
		}

		return diag;
	});

	// Apply all diagnostics to the document
	collection.set(doc.uri, diagnostics);
}
