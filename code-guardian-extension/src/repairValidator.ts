import { parse } from '@babel/parser';

/**
 * Phase 5 refinement: deterministic syntax validation of LLM-generated repairs.
 *
 * The thesis's R3 evaluation rests on 25 manually reviewed repair samples. This
 * module provides an automated quality signal — `autoApplicable` — that scales
 * to all 101 cases. The check is intentionally lightweight:
 *
 *   1. Parse the fix as a JS / TS expression OR as a JS / TS module (statements).
 *   2. Tolerate partial snippets via the loose-mode flags.
 *   3. Reject empty / prose / Markdown-fenced output.
 *
 * Passing parsing does NOT guarantee the fix is correct — it only guarantees it
 * could be applied to a file without breaking the build. That is exactly what
 * `autoApplicable` is meant to capture, and what the thesis can defensibly
 * report alongside the manual review.
 *
 * Both this module and evaluation/repair-validator.js are kept in sync via a
 * snapshot test in evaluation/repair-validator.snapshot.test.js.
 */

export interface RepairValidationResult {
	valid: boolean;
	reason?: string;
	parsedAs?: 'expression' | 'module' | 'script';
}

const PROSE_INDICATORS = [
	/^you\s+should/i,
	/^to\s+fix/i,
	/^the\s+vulnerability/i,
	/^use\s+(a\s+)?(parameterized|prepared|bind)/i,
	/^replace\s+with/i,
	/^consider\s+using/i,
	/^make\s+sure/i,
	/^this\s+code/i,
	/^example\s*:/i
];

const BABEL_PLUGINS: Array<string | [string, object]> = [
	'jsx',
	'typescript',
	'classProperties',
	'asyncGenerators',
	'objectRestSpread',
	'optionalChaining',
	'nullishCoalescingOperator',
	'dynamicImport',
	'topLevelAwait',
	'exportDefaultFrom',
	'exportNamespaceFrom',
	'numericSeparator',
	'logicalAssignment'
];

function stripFencesAndQuotes(raw: string): string {
	let s = raw.trim();
	// Remove leading triple-backtick fence (```js, ```ts, ```javascript etc.)
	const fenceStart = /^```[a-zA-Z]*\s*\n?/;
	if (fenceStart.test(s)) {
		s = s.replace(fenceStart, '');
		const trailingFence = /\n?```\s*$/;
		s = s.replace(trailingFence, '');
	}
	// Remove single-line backticks if the whole thing is wrapped
	if (s.startsWith('`') && s.endsWith('`') && s.length > 1) {
		s = s.slice(1, -1).trim();
	}
	return s.trim();
}

function looksLikeProse(s: string): boolean {
	if (s.length === 0) {
		return true;
	}
	for (const re of PROSE_INDICATORS) {
		if (re.test(s)) {
			return true;
		}
	}
	return false;
}

export function validateRepair(fix: string | undefined | null): RepairValidationResult {
	if (typeof fix !== 'string') {
		return { valid: false, reason: 'not_a_string' };
	}
	const cleaned = stripFencesAndQuotes(fix);
	if (cleaned.length === 0) {
		return { valid: false, reason: 'empty' };
	}
	if (looksLikeProse(cleaned)) {
		return { valid: false, reason: 'prose_not_code' };
	}

	// Try expression mode first (handles fragments like `db.query("SELECT...", [id])`).
	try {
		parse(cleaned, {
			sourceType: 'module',
			plugins: BABEL_PLUGINS as never,
			errorRecovery: false,
			allowReturnOutsideFunction: true,
			allowAwaitOutsideFunction: true,
			allowSuperOutsideMethod: true,
			allowUndeclaredExports: true
		});
		return { valid: true, parsedAs: 'module' };
	} catch (e1) {
		// Fall back to script mode — some snippets use top-level statements that
		// parse as scripts but not modules.
		try {
			parse(cleaned, {
				sourceType: 'script',
				plugins: BABEL_PLUGINS as never,
				errorRecovery: false,
				allowReturnOutsideFunction: true,
				allowAwaitOutsideFunction: true,
				allowSuperOutsideMethod: true
			});
			return { valid: true, parsedAs: 'script' };
		} catch (e2) {
			// Final attempt: wrap the fix as the body of an arrow function so a bare
			// expression can still be validated as syntactically meaningful.
			try {
				parse(`(() => { ${cleaned} })`, {
					sourceType: 'module',
					plugins: BABEL_PLUGINS as never,
					errorRecovery: false
				});
				return { valid: true, parsedAs: 'expression' };
			} catch (e3) {
				const msg = (e2 as Error).message || (e1 as Error).message || (e3 as Error).message;
				return { valid: false, reason: `parse_error: ${msg.slice(0, 120)}` };
			}
		}
	}
}
