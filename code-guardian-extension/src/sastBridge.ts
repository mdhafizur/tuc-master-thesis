import type { SecurityIssue, DetectionSource } from './analyzer';
import { normalizeCategory } from './categoryTaxonomy';

/**
 * TypeScript twin of evaluation/sast-fusion.js.
 *
 * Phase 2 (MVP): fusion logic only. Running Semgrep from the extension is
 * intentionally deferred — the thesis rerun goes through the harness, which
 * already has Semgrep plumbed. Exposing a runtime Semgrep subprocess from the
 * extension is tracked as Phase 3+ refinement work.
 *
 * Both twins must stay behaviorally identical. A JS-side snapshot test in
 * evaluation/sast-fusion.snapshot.test.js pins expected outputs.
 */

export interface SastFinding {
	type?: string;
	startLine: number;
	endLine: number;
	ruleId?: string;
	tool?: string;
	message?: string;
}

function rangesOverlap(a: { startLine: number; endLine: number }, b: { startLine: number; endLine: number }): boolean {
	return Math.max(a.startLine, b.startLine) <= Math.min(a.endLine, b.endLine);
}

function categoriesAgree(llmType: string | undefined, sastType: string | undefined): boolean {
	const c1 = normalizeCategory(llmType);
	const c2 = normalizeCategory(sastType);
	return c1 !== 'other' && c1 === c2;
}

/**
 * Promote LLM findings to `detectionSource: 'hybrid'` (confidence 1.0) when a
 * SAST finding corroborates both the line range and the canonical category.
 * LLM-only findings pass through unchanged.
 */
export function fuseSastWithLlm(llmIssues: SecurityIssue[], sastIssues: SastFinding[]): SecurityIssue[] {
	if (!Array.isArray(llmIssues) || llmIssues.length === 0) {
		return [];
	}
	if (!Array.isArray(sastIssues) || sastIssues.length === 0) {
		return llmIssues.map(issue => ({ ...issue }));
	}

	return llmIssues.map(llm => {
		const llmType = (llm as SecurityIssue & { type?: string }).type ?? llm.message;
		const match = sastIssues.find(sast =>
			rangesOverlap(llm, sast) && categoriesAgree(llmType, sast.type)
		);
		if (match) {
			return {
				...llm,
				confidence: 1.0,
				detectionSource: 'hybrid' as DetectionSource
			};
		}
		return { ...llm };
	});
}
