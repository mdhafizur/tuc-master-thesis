import * as vscode from 'vscode';
import { analyzeCodeWithLLM, AnalysisScope, SecurityIssue } from './analyzer';
import { RAGManager } from './ragManager';

import { getLogger } from './logger';
/**
 * Analyzes a given piece of code using an LLM, parses the issues,
 * and reports them as diagnostics in the VS Code editor.
 *
 * @param code - The code to analyze (can be full file or a function snippet).
 * @param doc - The active text document.
 * @param collection - The diagnostic collection to update.
 * @param lineOffset - The starting line number in the full document (used when analyzing a function snippet).
 * @param ragManager - Optional RAG manager for enhanced analysis.
 * @param scope - 'function' for inline real-time snippets, 'file' for whole-file scans (the latter requests a larger Ollama context window).
 */
export async function analyzeAndReportDiagnosticsFromText(
	code: string | null,
	doc: vscode.TextDocument,
	collection: vscode.DiagnosticCollection,
	lineOffset: number = 0, // Used to shift line numbers if analyzing a sub-block
	ragManager?: RAGManager,
	scope: AnalysisScope = 'function'
) {
	const logger = getLogger();

	if (!code) { return; }; // Skip analysis if no code is provided

	// Run the LLM analysis and retrieve detected security issues
	const issues: SecurityIssue[] = await analyzeCodeWithLLM(code, undefined, ragManager, scope);

	logger.info(`Diagnostics: received ${issues.length} issues from LLM analysis`);
	issues.forEach((issue, i) => {
		logger.debug(`Issue ${i + 1}: [L${issue.startLine}-${issue.endLine}] ${issue.message} | Fix: ${issue.suggestedFix ? 'YES' : 'NO'}`);
	});

	// The model can hallucinate line numbers that exceed the analyzed snippet's
	// actual length (seen in the wild: endLine: 20 on a 5-line function). Cap
	// at the last snippet line in document space so the squiggle never bleeds
	// past the function we asked the model about.
	const snippetLineCount = code.split('\n').length;
	const snippetLastLine = lineOffset + snippetLineCount - 1;

	const diagnostics: vscode.Diagnostic[] = issues.map(issue => {
		// LLM returns 1-based, VS Code expects 0-based. Clamp to both the
		// document's bounds and the snippet's bounds.
		const upperBound = Math.min(doc.lineCount - 1, snippetLastLine);
		const startLine = Math.max(lineOffset, Math.min(upperBound, lineOffset + issue.startLine - 1));
		const endLine = Math.max(startLine, Math.min(upperBound, lineOffset + issue.endLine - 1));

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

		// Mark the diagnostic as fixable so the lightbulb appears. On the real-time
		// path the fix isn't pre-generated (Stage 2 is skipped to avoid spamming
		// Ollama on every keystroke); the code-action provider lazy-generates it
		// when the user opens the lightbulb. Pre-generated fixes (file-scope scans)
		// are still attached so Apply / Preview can use them without a round-trip.
		diag.code = 'codeSecurity.fixSuggestion';
		if (issue.suggestedFix) {
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
