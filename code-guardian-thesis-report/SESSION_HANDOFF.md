# Thesis Review: SESSION HANDOFF

## Thesis Title
Privacy-Preserving Source Code Vulnerability Detection and Repair using Retrieval-Augmented LLMs for Visual Studio Code

## Overall Assessment
Well-structured and carefully written Master's thesis tackling a relevant, timely problem. Technically grounded, honest about limitations, and demonstrates a clear engineering contribution. Writing quality is consistently high across all chapters.

---

## Strengths

1. **Clear problem framing and motivation.** The introduction articulates the tension between cloud-based LLM capabilities and privacy requirements well. The threat model table (src/chapters/introduction.tex:36-52) grounds privacy claims concretely.

2. **Honest, transparent evaluation.** The thesis's greatest strength. Best F1 is 42.70% and stated clearly. The "Negative Results and Boundary Conditions" subsection and threats-to-validity discussion are exemplary. Many theses would hide that 2/5 models (qwen3:4b, CodeLlama) essentially failed due to parse collapse.

3. **Reproducibility.** Artifact provenance table, exact invocation commands, model fingerprints, and run window timestamps show strong reproducibility awareness. Evaluation harness is self-contained in the repository.

4. **Well-defined requirements traceability.** R1-R6 defined in Analysis chapter and traced through Concept, Implementation, and Evaluation. The claim-to-evidence map (src/chapters/evaluation/summary.tex:19-36) ties research questions to concrete measurements.

5. **Practical engineering contributions.** Debounced triggers, function-level scoping, LRU caching, and defensive JSON parsing demonstrate practical system design thinking.

---

## Weaknesses and Concerns

### Major

1. **Very small evaluation dataset (33 cases).** With only 18 vulnerable and 15 secure samples, individual misclassifications swing metrics dramatically. For example, qwen3:8b recall going from 18/54 to 19/54 with RAG (one additional correct detection across 3 runs) is reported as +1.86pp improvement -- within noise. The task description mentions "40-50 test cases" and "one actively maintained real-world project" -- neither materialised. This gap should be addressed more explicitly.

2. **No user study or developer feedback.** R6 (Usability) is narrowed to latency only. A system claiming to be an IDE-integrated developer tool would benefit from even a small informal user study. Absence weakens practical usefulness claims.

3. **RAG implementation appears minimal.** Uses "static security snippets" with k=5 in evaluation. RAG *hurt* gemma3:1b (reducing recall to 0%) and had negligible effect on gemma3:4b, suggesting retrieval may inject generic/irrelevant context that confuses smaller models. Needs retrieval quality analysis -- what snippets were actually retrieved and were they relevant?

4. **Best F1 of 42.70% is quite low for practical utility.** The framing sometimes suggests the system is "useful" without sufficiently qualifying what useful means at sub-50% F1 with 27% FPR. A developer encountering ~1 false alarm per 3 findings may quickly lose trust.

### Minor

5. **Repetition across chapters.** Same architectural decisions and component descriptions repeated substantially across Concept (concept_derivations, components, strategies) and Implementation (system_workflow, agent, strategy). Debouncing, function-level scoping, and JSON output contract described in nearly identical terms in at least 4 places.

6. **Requirements sections are verbose.** Each R1-R6 subsection follows the same formulaic template. Evaluation scale tables define thresholds (e.g., "High: F1 >= 0.80") that are never met in evaluation results, creating an awkward disconnect.

7. **Task description vs. actual work mismatch.** Task description mentions "signed corpora," "network isolation," "deterministic decoding," "containerized execution," and "Juliet and OWASP Benchmark." Several (signed corpora, containerized execution, standard benchmarks) do not appear in final implementation or evaluation.

8. **Missing comparison with existing tools.** Positioned against SAST tools (Semgrep, CodeQL) but never runs them on the same dataset. Even a brief Semgrep comparison on the 33 test cases would contextualize LLM results.

9. **Listing language annotation error.** src/chapters/implementation/agent.tex:23 uses `language=Java` for a TypeScript interface definition. Should be `language=TypeScript` or removed.

---

## Specific Suggestions

| Location | Issue | Suggestion |
|---|---|---|
| abstract.tex:6 | "best F1 in this run" -- unusual for abstract | Simplify to "the highest F1 score (42.70%) was achieved by qwen3:8b with RAG" |
| introduction.tex:94 | Date "15.12.2025" on title page | Verify intended submission date |
| analysis.tex:13 | "Chapter~1" hardcoded | Use `\ref{chap:introduction}` for consistency |
| r6.tex:24-31 | TikZ star/circle symbols for usability scale | May be hard to distinguish in print; consider text labels |
| concept.tex:1-7 | Opening paragraph repeats Ch.1 motivation verbatim | Shorten to forward reference |
| strategy.tex (impl) | Entire section largely duplicates strategies.tex (concept) | Merge or cross-reference to avoid redundancy |
| evaluation_metrics.tex:18-20 | "15 intentionally secure snippets" restated | Already in dataset section; remove duplication |
| Template.tex:170 | `splncs04` bibliography style | This is Springer LNCS conference style; verify department requirements |

---

## Open Questions for the Author

1. Why was `qwen3:4b` so dramatically worse than `qwen3:8b` in parse success (1-4% vs 78-85%)? Known model issue or prompt format incompatibility?
2. Did you experiment with `temperature=0.0` for maximum determinism? Why was 0.1 chosen?
3. Does the cache key include RAG configuration? If not, toggling RAG on/off could serve stale results.
4. How large is the actual knowledge base (number of entries, total tokens)? Not quantified anywhere.

---

## Summary Verdict
Solid Master's thesis with clear research contribution and honest evaluation. Main improvement areas: (a) evaluation scale -- larger dataset and/or comparison with existing tools, (b) reducing repetition between Concept and Implementation chapters, (c) reconciling task description with actual delivered work. Writing quality is above average; self-critical evaluation approach is commendable.
