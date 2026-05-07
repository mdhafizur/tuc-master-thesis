import * as ts from 'typescript';
import * as vscode from 'vscode';

/**
 * Represents the extracted function's code, the document range it occupies,
 * and its starting line number. `range` is the precise span of the function
 * (start of the function node to its end) — used by the function-level repair
 * applier to replace the whole function in one WorkspaceEdit.
 */
export interface ExtractedFunction {
	code: string;
	startLine: number;
	range: vscode.Range;
}

/**
 * Extracts the innermost function-like block surrounding the given cursor position.
 * Supports traditional functions, arrow functions, methods, and constructors.
 *
 * @param doc The current text document.
 * @param position The cursor position in the document.
 * @returns An object containing the function's code and its starting line in the full document.
 */
export function getEnclosingFunction(
	doc: vscode.TextDocument,
	position: vscode.Position
): ExtractedFunction | null {
	// Full source text from the document
	const sourceCode = doc.getText();

	// Create a TypeScript AST from the code
	const sourceFile = ts.createSourceFile(
		doc.fileName,
		sourceCode,
		ts.ScriptTarget.Latest,
		true
	);

	// Get the absolute character offset of the cursor
	const offset = doc.offsetAt(position);

	// Store all valid candidate functions that enclose the offset
	const candidates: ts.FunctionLikeDeclaration[] = [];

	/**
	 * Determines if the node is a function-like declaration we want to consider.
	 */
	function isFunctionLike(node: ts.Node): node is ts.FunctionLikeDeclaration {
		return ts.isFunctionDeclaration(node) ||
			ts.isFunctionExpression(node) ||
			ts.isArrowFunction(node) ||
			ts.isMethodDeclaration(node) ||
			ts.isConstructorDeclaration(node);
	}

	/**
	 * Recursively visit AST nodes to collect enclosing functions.
	 */
	function visit(node: ts.Node) {
		if (isFunctionLike(node) && node.pos <= offset && offset <= node.end) {
			candidates.push(node);
		}
		ts.forEachChild(node, visit);
	}

	// Start traversing the AST
	visit(sourceFile);

	if (candidates.length > 0) {
		// Choose the innermost function (smallest enclosing)
		const targetFn = candidates.reduce((a, b) =>
			(a.end - a.pos) <= (b.end - b.pos) ? a : b
		);

		const startPos = doc.positionAt(targetFn.getStart());
		const endPos = doc.positionAt(targetFn.getEnd());
		const code = sourceCode.slice(targetFn.getStart(), targetFn.getEnd());

		return {
			code,
			startLine: startPos.line,
			range: new vscode.Range(startPos, endPos)
		};
	}

	// No function-like block found at the cursor location
	return null;
}
