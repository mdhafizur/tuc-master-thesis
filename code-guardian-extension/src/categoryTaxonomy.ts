import taxonomyData from './categoryTaxonomy.json';

export type CanonicalCategory =
	| 'sql-injection'
	| 'nosql-injection'
	| 'xss'
	| 'command-injection'
	| 'code-injection'
	| 'path-traversal'
	| 'ssrf'
	| 'xxe'
	| 'ldap-injection'
	| 'header-injection'
	| 'deserialization'
	| 'weak-crypto'
	| 'weak-encryption'
	| 'hardcoded-credential'
	| 'auth-bypass'
	| 'improper-auth'
	| 'prototype-pollution'
	| 'race-condition'
	| 'redos'
	| 'input-validation'
	| 'information-exposure'
	| 'crypto-verification'
	| 'other';

interface CompiledPattern {
	regex: RegExp;
	category: CanonicalCategory;
}

const COMPILED_PATTERNS: CompiledPattern[] = taxonomyData.patterns.map(p => ({
	regex: new RegExp(p.regex, 'i'),
	category: p.category as CanonicalCategory
}));

export const TAXONOMY_VERSION: string = taxonomyData.version;
export const ALL_CATEGORIES: readonly CanonicalCategory[] =
	taxonomyData.categories as readonly CanonicalCategory[];

export function normalizeCategory(raw: string | undefined | null): CanonicalCategory {
	if (!raw) {
		return 'other';
	}
	const haystack = String(raw);
	for (const p of COMPILED_PATTERNS) {
		if (p.regex.test(haystack)) {
			return p.category;
		}
	}
	return 'other';
}

export function normalizeCategories(rawList: ReadonlyArray<string | undefined | null>): Set<CanonicalCategory> {
	const out = new Set<CanonicalCategory>();
	for (const r of rawList) {
		out.add(normalizeCategory(r));
	}
	return out;
}
