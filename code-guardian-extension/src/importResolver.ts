import resolverData from './importResolver.json';
import type { CanonicalCategory } from './categoryTaxonomy';

/**
 * Phase 3 refinement: lightweight semantic context for prompts.
 *
 * Pure regex-based extractor. Operates on a single code snippet (function or
 * file). Returns a small bundle the analyzer can append to the user prompt as
 * `Context: imports={...}, sinks={...}, hints={...}`.
 *
 * Intentionally NOT a real static analyzer — that would be Phase 4+ work. The
 * goal here is to surface enough signal so the LLM can detect categories
 * (input-validation, auth, crypto, deserialization) that it currently misses
 * because the dangerous API is not lexically obvious in the snippet.
 *
 * Both the TS module and the JS twin (evaluation/import-resolver.js) load the
 * same shared JSON catalog at importResolver.json.
 */

interface SinkPattern {
	regex: RegExp;
	category: CanonicalCategory;
	description: string;
}

const COMPILED_SINKS: SinkPattern[] = (resolverData.sinkPatterns as Array<{
	regex: string; category: string; description: string;
}>).map(p => ({
	regex: new RegExp(p.regex, 'i'),
	category: p.category as CanonicalCategory,
	description: p.description
}));

const VALIDATOR_MODULES: ReadonlySet<string> = new Set(resolverData.validatorModules);

const REQUIRE_RE = /\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)/g;
const ESM_FROM_RE = /\bimport\s+(?:[\w*\s,{}]+\s+from\s+)?['"]([^'"]+)['"]/g;
const ESM_BARE_RE = /\bimport\s+['"]([^'"]+)['"]/g;

export interface ImportContext {
	modules: string[];          // unique imported module names
	validators: string[];       // subset of modules recognized as sanitizers/validators
	sinks: { description: string; category: CanonicalCategory; line: number }[];
	categoryHints: CanonicalCategory[]; // unique canonical categories implied by sinks
}

function uniq<T>(arr: T[]): T[] {
	return Array.from(new Set(arr));
}

function extractModules(code: string): string[] {
	const out: string[] = [];
	for (const re of [REQUIRE_RE, ESM_FROM_RE, ESM_BARE_RE]) {
		re.lastIndex = 0;
		let m: RegExpExecArray | null;
		while ((m = re.exec(code)) !== null) {
			if (m[1]) {
				out.push(m[1]);
			}
		}
	}
	return uniq(out);
}

function lineNumberOf(code: string, charIndex: number): number {
	let line = 1;
	for (let i = 0; i < charIndex && i < code.length; i++) {
		if (code.charCodeAt(i) === 10) {
			line++; // '\n'
		}
	}
	return line;
}

export function resolveImportContext(code: string): ImportContext {
	if (typeof code !== 'string' || code.length === 0) {
		return { modules: [], validators: [], sinks: [], categoryHints: [] };
	}

	const modules = extractModules(code);
	const validators = modules.filter(m => VALIDATOR_MODULES.has(m));

	const sinks: ImportContext['sinks'] = [];
	for (const sink of COMPILED_SINKS) {
		const re = new RegExp(sink.regex.source, sink.regex.flags.includes('g') ? sink.regex.flags : sink.regex.flags + 'g');
		let m: RegExpExecArray | null;
		while ((m = re.exec(code)) !== null) {
			sinks.push({
				description: sink.description,
				category: sink.category,
				line: lineNumberOf(code, m.index)
			});
			if (m.index === re.lastIndex) {
				re.lastIndex++; // guard against zero-width matches
			}
		}
	}

	const categoryHints = uniq(sinks.map(s => s.category));

	return { modules, validators, sinks, categoryHints };
}

/**
 * Format the context bundle as a short string the LLM prompt can absorb. Bound
 * the output length so we don't blow the prompt budget on pathological inputs.
 */
export function formatImportContext(ctx: ImportContext, maxLen: number = 400): string {
	if (ctx.modules.length === 0 && ctx.sinks.length === 0) {
		return '';
	}
	const parts: string[] = [];
	if (ctx.modules.length > 0) {
		parts.push(`imports: ${ctx.modules.slice(0, 12).join(', ')}`);
	}
	if (ctx.validators.length > 0) {
		parts.push(`validators-available: ${ctx.validators.join(', ')}`);
	}
	if (ctx.sinks.length > 0) {
		const sinkSummary = ctx.sinks.slice(0, 8).map(s => `${s.description}@L${s.line}`).join(', ');
		parts.push(`sinks: ${sinkSummary}`);
	}
	if (ctx.categoryHints.length > 0) {
		parts.push(`likely-categories: ${ctx.categoryHints.join(', ')}`);
	}
	let s = parts.join(' | ');
	if (s.length > maxLen) {
		s = s.slice(0, maxLen - 3) + '...';
	}
	return s;
}
