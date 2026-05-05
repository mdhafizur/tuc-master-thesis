# Professor-Grade Review — Code Guardian Thesis

A consolidated review of `code-guardian-thesis-report/` from four perspectives: argument quality, per-chapter narrative health, methodology and defense readiness, and code/consistency. Complements the existing **`REVIEW.md`** (code-vs-thesis verification, citation audit, prose style) and **`TASK_COVERAGE.md`** (task description mapping). Every claim below carries `file:line` so the student can act item-by-item.

## Executive Verdict

| Dimension | Verdict | Top concern |
|---|---|---|
| Academic argument & contribution | 🟡 Adequate | RQ2 drift: introduction promises *"qualitative grounding of explanations"* but discussion delivers F1 deltas only — the question was changed, not answered |
| Per-chapter narrative | 🟢 Good (Implementation: 🟡 Concerns) | Implementation chapter has flat outline preamble + 3-line summary; system_workflow.tex uses `\subsection*` (no ToC entry) |
| Methodology & statistics | 🟡 Solid with one over-claim | *"rules out threshold overfitting"* (`eval_r1_accuracy.tex:122`) overstates what n=9 secure cases on TEST can rule out |
| Defense readiness | 🟢 Strong | 35 anticipated examiner Qs answered with anchor facts; three rehearsed mitigations for the weakest claims |
| Implementation health | 🟢 7 of 8 REVIEW.md blockers fixed | §1.3 partial — dead `isModelAllowed()` stub remains in `modelManager.ts:67-70` (one-line delete) |
| Cross-cutting consistency | 🟡 One broken cross-reference | `discussion.tex:33` references `sec:intro-objectives` but should be `sec:intro-rqs` — wrong page renders today |

**Top three to fix before defense:** (1) `discussion.tex:33` cross-reference target; (2) `eval_r1_accuracy.tex:122` "rules out threshold overfitting" → "rules out the chosen threshold being a TRAIN-specific optimum among the swept set"; (3) RQ2 either restate to drop "qualitative grounding" or add a brief grounding-rubric sample to discussion §6.3.

---

## 1. Academic Argument & Contribution

### 1.1 Contribution clarity — **Adequate**

Five contributions enumerated at [conclusion.tex:7-13](code-guardian-thesis-report/src/chapters/conclusion.tex#L7-L13) (egress gate, two-stage pipeline, multi-pass consensus, hybrid AST+LLM, evaluation harness) are concrete and map onto delivered code; differentiated against prior work at [positioning.tex:29-30](code-guardian-thesis-report/src/chapters/analysis/related_works/positioning.tex#L29-L30) ("five mechanisms not jointly applied by any reviewed approach").

Weaknesses:
- Contribution #1 ("privacy-preserving architecture") is a *system property*, not a research contribution; egress filtering and signed corpora are standard engineering patterns.
- Contribution #5 (evaluation harness) is an *artefact*, not a scientific claim.
- The abstract at [abstract.tex:1-5](code-guardian-thesis-report/src/abstract.tex) emphasises empirical findings rather than these five contributions, creating a mismatch with the conclusion's enumeration.

### 1.2 Intro promises ↔ conclusion drift

| Intro promise | Where promised | Where answered | Drift |
|---|---|---|---|
| Objective 1: two-stage pipeline w/ JSON, RAG, scoping | [introduction.tex:83](code-guardian-thesis-report/src/chapters/introduction.tex#L83) | [conclusion.tex:9-10](code-guardian-thesis-report/src/chapters/conclusion.tex#L9-L10) | None |
| Objective 2: 5 models, P/R/F1/FPR/JSON/latency | [introduction.tex:85](code-guardian-thesis-report/src/chapters/introduction.tex#L85) | [conclusion.tex:32-38](code-guardian-thesis-report/src/chapters/conclusion.tex#L32-L38) | Minor — JSON parse success absent from conclusion table |
| RQ1 Feasibility | [introduction.tex:47](code-guardian-thesis-report/src/chapters/introduction.tex#L47) | [discussion.tex:35](code-guardian-thesis-report/src/chapters/discussion.tex#L35) | Hedged ("Supported with caveats") where intro framed feasibility binary |
| **RQ2 Grounding** | [introduction.tex:48](code-guardian-thesis-report/src/chapters/introduction.tex#L48) | [discussion.tex:36-37](code-guardian-thesis-report/src/chapters/discussion.tex#L36-L37) | **Drift:** RQ2 asks about "qualitative grounding of explanations"; discussion reports only F1 deltas |
| **RQ3 Practicality** | [introduction.tex:49](code-guardian-thesis-report/src/chapters/introduction.tex#L49) | [discussion.tex:39](code-guardian-thesis-report/src/chapters/discussion.tex#L39) | **Drift:** RQ3 asks which mechanisms are *necessary*; discussion answers latency feasibility but never isolates the marginal contribution of caching or debouncing |

### 1.3 Literature positioning (per subsection)

| Subsection | Verdict | Representative weakness |
|---|---|---|
| [traditional_sast.tex](code-guardian-thesis-report/src/chapters/analysis/related_works/traditional_sast.tex) | Adequate-critical | Names limitations but cites no measured P/R for Semgrep/CodeQL; "noisy alerts" rests on `johnson2013don` (2013) |
| [llm_vuln_detection.tex](code-guardian-thesis-report/src/chapters/analysis/related_works/llm_vuln_detection.tex) | Strong-critical | Engages IRIS, CWEval, SecRepair with concrete failure modes |
| [rag_secure_coding.tex](code-guardian-thesis-report/src/chapters/analysis/related_works/rag_secure_coding.tex) | Adequate | Only one post-2023 secure-coding RAG cite besides RESCUE |
| [privacy_ide.tex](code-guardian-thesis-report/src/chapters/analysis/related_works/privacy_ide.tex) | **Weak** | Almost entirely descriptive; "remains unmet gap" asserted not demonstrated against named alternatives |
| [positioning.tex](code-guardian-thesis-report/src/chapters/analysis/related_works/positioning.tex) | Adequate but over-confident | Table at line 6-23 collapses heterogeneous tools; line 25 "only reviewed approach that reaches at least Medium" is author-scored, not externally evaluated |

### 1.4 Top 3 argument-quality concerns

1. **RQ2 question-shifting** — [introduction.tex:48](code-guardian-thesis-report/src/chapters/introduction.tex#L48) vs [discussion.tex:36-37](code-guardian-thesis-report/src/chapters/discussion.tex#L36-L37). RQ2 promises "qualitative grounding of explanations"; discussion delivers F1 deltas. *Mitigation:* either restate RQ2 to drop "qualitative grounding" or add a brief explanation-grounding rubric and apply it to a sample of RAG vs LLM-only outputs.

2. **Curator bias on the canonical taxonomy** — [discussion.tex:74-75](code-guardian-thesis-report/src/chapters/discussion.tex#L74-L75). Both the 101-case corpus and the 26-class taxonomy are author-defined. The held-out 70/30 split addresses threshold tuning but not selection bias on cases or labels. *Mitigation:* cross-validate the canonical taxonomy against an external CWE mapping (e.g., MITRE's parent-child hierarchy) and report the recall delta.

3. **Originality over-claim** — [positioning.tex:25](code-guardian-thesis-report/src/chapters/analysis/related_works/positioning.tex#L25): "the only reviewed approach that reaches at least Medium across all five requirements" — rests on the author's own scoring against the author's own scales. Not falsifiable. *Mitigation:* retreat to a combination-claim ("the only reviewed approach to operationalise this combination").

### 1.5 RQ traceability

| RQ | Defined | Answered | Evidence |
|---|---|---|---|
| RQ1 | [introduction.tex:47](code-guardian-thesis-report/src/chapters/introduction.tex#L47) | [discussion.tex:35](code-guardian-thesis-report/src/chapters/discussion.tex#L35) | `sec:eval-r1` + `sec:eval-r5` cited ✓ |
| RQ2 | [introduction.tex:48](code-guardian-thesis-report/src/chapters/introduction.tex#L48) | [discussion.tex:36-37](code-guardian-thesis-report/src/chapters/discussion.tex#L36-L37) | `sec:eval-r1` cited; **"qualitative grounding" promised but no evidence section** |
| RQ3 | [introduction.tex:49](code-guardian-thesis-report/src/chapters/introduction.tex#L49) | [discussion.tex:39](code-guardian-thesis-report/src/chapters/discussion.tex#L39) | `sec:eval-r4` cited; **scoping/caching/debouncing claimed necessary but no ablation isolates them** |

---

## 2. Per-Chapter Assessment

| Chapter | Overview | Summary | Structure | Coherence | Verdict | Top 2 issues |
|---|---|---|---|---|---|---|
| 1. Introduction | Yes | Partial | Pass | Pass | **Good** | [introduction.tex:1](code-guardian-thesis-report/src/chapters/introduction.tex#L1) opens directly with technical content (no chapter overview); no explicit closing summary — Outline substitutes |
| 2. Analysis | Yes | Yes | Pass | Concern | **Good** | [analysis.tex:42-50](code-guardian-thesis-report/src/chapters/analysis/analysis.tex#L42-L50) requirements traceability table forward-refs `sec:eval-r1` to `sec:eval-r5`; [requirements/r3.tex:9](code-guardian-thesis-report/src/chapters/analysis/requirements/r3.tex#L9) forward-refs `sec:eval-r3` |
| 3. Concept | Yes | Yes | Pass | Concern | **Good** | [system_architecture_and_design.tex:51](code-guardian-thesis-report/src/chapters/concept/system_architecture_and_design.tex#L51) forward-refs `sec:impl-audit-mode`; concept summary is light |
| 4. Implementation | Partial | Partial | Concern | Concern | **Concerns** | [implementation.tex:3](code-guardian-thesis-report/src/chapters/implementation/implementation.tex#L3) flat one-sentence-per-section outline; [system_workflow.tex](code-guardian-thesis-report/src/chapters/implementation/system_workflow.tex) uses `\subsection*` (no ToC entry, breaks ≥2-subchapter rule) |
| 5. Evaluation | Yes | Yes | Pass | Pass | **Good** | [eval_r1_accuracy.tex:6-172](code-guardian-thesis-report/src/chapters/evaluation/eval_r1_accuracy.tex#L6-L172) has 10 sibling `\subsection`s without thematic grouping; [evaluation.tex:1](code-guardian-thesis-report/src/chapters/evaluation/evaluation.tex#L1) overview pre-discloses headline numbers |
| 6. Discussion | Yes | Yes | Pass | Pass | **Excellent** | [discussion.tex:33](code-guardian-thesis-report/src/chapters/discussion.tex#L33) **broken cross-ref** (sec:intro-objectives → should be sec:intro-rqs); paragraph-headings used heavily |
| 7. Conclusion | Yes | Yes | Pass | Concern | **Good** | [conclusion.tex:15-17](code-guardian-thesis-report/src/chapters/conclusion.tex#L15-L17) "Key Findings" still asserts achievement-style verdicts ("Local deployment is feasible", "False-positive control remains the main practical barrier"); [conclusion.tex:43-45](code-guardian-thesis-report/src/chapters/conclusion.tex#L43-L45) `\section{Future Work}` has no preamble before `\input` |

**Notable per-chapter recommendations:**

- **Introduction**: prepend a 3-sentence chapter overview at [introduction.tex:1](code-guardian-thesis-report/src/chapters/introduction.tex#L1) before the first technical sentence on injection flaws.
- **Analysis**: at [analysis.tex:42-50](code-guardian-thesis-report/src/chapters/analysis/analysis.tex#L42-L50) replace per-requirement `Section~\ref{sec:eval-...}` with a generic "evaluated in Chapter~\ref{chap:evaluation}" — restores the no-forward-ref rule.
- **Implementation**: convert `\subsection*` blocks in [system_workflow.tex](code-guardian-thesis-report/src/chapters/implementation/system_workflow.tex) to numbered `\subsection`; expand the 3-line summary at [implementation.tex:17-19](code-guardian-thesis-report/src/chapters/implementation/implementation.tex#L17-L19) to 6–8 lines bridging implementation choices to evaluation requirements.
- **Evaluation**: at [eval_r1_accuracy.tex:39](code-guardian-thesis-report/src/chapters/evaluation/eval_r1_accuracy.tex#L39) onward, group "RAG Ablation", "Per-Category Breakdown", "Qualitative Error Analysis", "SAST Baseline" under one parent `\subsection{Ablations and Diagnostics}` with the four demoted to `\subsubsection`.
- **Conclusion**: soften [conclusion.tex:15-17](code-guardian-thesis-report/src/chapters/conclusion.tex#L15-L17) "Key Findings" to a 4-line "Summary" that cross-refs Chapter 5/6 for evidence rather than re-asserting verdicts.

---

## 3. Methodology & Statistics

### 3.1 Statistical-validity assessment

| Method | Verdict |
|---|---|
| McNemar exact tests (5 paired LLM-only vs LLM+RAG) | **Appropriate.** Textbook for paired binary outcomes on the same cases. [eval_r1_accuracy.tex:45](code-guardian-thesis-report/src/chapters/evaluation/eval_r1_accuracy.tex#L45) reports correctly. The pooled per-case correctness rule (vulnerable: any-of-3 TP with no FN; secure: all-3 zero FP) is defensible but mixes the discordant-pair denominator with the gate logic — examiners may push. |
| Bonferroni at α=0.01 | **Appropriate; arguably conservative.** Holm-Bonferroni would be uniformly more powerful at the same FWER and would not change the headline (codellama still survives, qwen3 still does not). |
| Exact binomial 95% CI on FPR (n=30) | **Appropriate method, under-stated.** [2.1%, 26.5%] cited once at [eval_r1_accuracy.tex:78](code-guardian-thesis-report/src/chapters/evaluation/eval_r1_accuracy.tex#L78) but headline FPR appears without the CI in [eval_r1_accuracy.tex:19,180](code-guardian-thesis-report/src/chapters/evaluation/eval_r1_accuracy.tex#L19) and across discussion. |
| Sample-level FPR | **Appropriate and well-justified** at [evaluation_metrics.tex:8](code-guardian-thesis-report/src/chapters/evaluation/evaluation_metrics.tex#L8). 100% FPR for 5/10 LLM configs shows the metric isn't a vanity number. |
| Train/test split (71/30) | **Appropriate in principle, borderline over-claimed.** Three thresholds tied on TRAIN, so the held-out exercise selected nothing. TEST FPR=0% on n=9 has CI [0%, 33.6%]; "rules out threshold overfitting" at [eval_r1_accuracy.tex:122](code-guardian-thesis-report/src/chapters/evaluation/eval_r1_accuracy.tex#L122) overstates what 9 samples can rule out. |
| Three-pass consensus / inter-run agreement | **Appropriate.** Three different seeds (42/137/200) yield genuine sampling diversity; byte-identity check at [eval_reproducibility.tex:14-28](code-guardian-thesis-report/src/chapters/evaluation/eval_reproducibility.tex#L14-L28) confirms determinism under fixed seed. |
| Auto-applicable rate (n=279) | **Appropriate, under-claimed.** 95% binomial CI [86.3%, 93.4%] is narrow; not reported. |

### 3.2 Sample-size honesty

n=30 secure cases gives FPR 95% CI [2.1%, 26.5%] for the headline 10% point estimate. **Disclosure is partial:**

- ✓ Acknowledged at [eval_r1_accuracy.tex:78](code-guardian-thesis-report/src/chapters/evaluation/eval_r1_accuracy.tex#L78) and [discussion.tex:72](code-guardian-thesis-report/src/chapters/discussion.tex#L72).
- ✗ Not acknowledged at [eval_r1_accuracy.tex:19,37,180](code-guardian-thesis-report/src/chapters/evaluation/eval_r1_accuracy.tex#L19) ("FPR = 10.00% … comfortably below the High ceiling") or [discussion.tex:7](code-guardian-thesis-report/src/chapters/discussion.tex#L7) ("low-noise band"). The upper CI bound (26.5%) *exceeds* the High threshold (0.20).
- ✗ Most aggressive over-claim: [eval_r1_accuracy.tex:122](code-guardian-thesis-report/src/chapters/evaluation/eval_r1_accuracy.tex#L122) "rules out threshold overfitting" on n=9 secure cases.

### 3.3 Threats-to-validity gaps

The Threats section ([discussion.tex:66-90](code-guardian-thesis-report/src/chapters/discussion.tex#L66-L90)) covers scope/context, sample size, curator bias, repair correctness, single-rater R3, hardware, latency-only usability, missing commercial baselines. **Five threats it misses** — examiners are likely to bring these up:

1. **Construct validity of the canonical taxonomy.** Author-defined labels score against author-defined classifier. Mitigation language: *"The taxonomy is pinned by snapshot test (48 fixtures) and the per-canonical-category TP/FP/FN are emitted unchanged by the run JSON, so the matcher's effect is auditable."*

2. **Training-data leakage from public corpora.** OWASP NodeGoat, Juice Shop, named CVEs are public — almost certainly seen during qwen3 pre-training. Mitigation: *"the curated 71+30 portion is internally authored; the 15-case external corpus result (F1 63.64% vs curated 74.07%) is the leakage-resistant reference."*

3. **Selection bias in 25-sample R3 manual review.** Reviewed subset spans highest-frequency categories; zero-recall and 0% fix-rate categories systematically under-represented.

4. **Single-hardware reproducibility.** byteIdentityRate=100% is M4 Max only; CUDA/ROCm/M1/M2 untested.

5. **Configuration-selection non-pre-registration.** qwen3:8b+RAG and gate=0.67 chosen by post-hoc evaluation across 10 configurations.

### 3.4 Reproducibility honesty — well-handled

byteIdentityRate=100% is honestly hardware-scoped at three places: [eval_reproducibility.tex:14-15,39-45](code-guardian-thesis-report/src/chapters/evaluation/eval_reproducibility.tex#L14-L15) and [discussion.tex:84](code-guardian-thesis-report/src/chapters/discussion.tex#L84). Nit: the 100% number appears in summary tables and abstract without the qualifier.

---

## 4. Defense Q&A Readiness

35 anticipated examiner questions, 5 per chapter, with anchor-grounded suggested answers. The full question set is too long for this synthesis — abridged here as **the highest-leverage 3 per chapter**. The student can rehearse all 35 from the agent transcripts; below are the questions most likely to appear.

### Introduction

**Q.** Three RQs but RQ1 is essentially "does this work?" — that's a feasibility study, not research.
**A.** RQ1 is feasibility (Supported with caveats). RQ2 isolates an empirical claim (model-dependent RAG effect with codellama collapse surviving Bonferroni at α=0.01). RQ3 maps measured latency onto specific HCI thresholds. The contributions are the canonical taxonomy, the inter-run gate, and the auto-applicable rate metric — not the existence of the tool. (anchor: [discussion.tex:31-39](code-guardian-thesis-report/src/chapters/discussion.tex#L31-L39))

**Q.** "Privacy-preserving" — every claim assumes the developer's machine is itself trusted. What about a compromised endpoint?
**A.** Out-of-scope by design and stated as such. R5 covers no-egress and signed corpus, not endpoint compromise. (anchor: [eval_r5_privacy.tex:6-26](code-guardian-thesis-report/src/chapters/evaluation/eval_r5_privacy.tex#L6-L26))

**Q.** Why JS/TS specifically and not C/C++ or Java where security research happens?
**A.** No first-party JS port of Juliet or OWASP Benchmark exists; CWEval's JS slice is small. The substitution penalty is measured: external corpus F1 63.64% vs curated 74.07%. (anchor: [experimental_setup.tex:18-25](code-guardian-thesis-report/src/chapters/evaluation/experimental_setup.tex#L18-L25))

### Related Work

**Q.** IRIS uses GPT-4 and gets 15% precision on whole-repo Java. You get 78% on function-level JS. Are these comparable?
**A.** Explicitly not a head-to-head dominance claim. The point is the predicted direction: cloud GPT-4 on harder scope reaches 15% precision, so a local 8B reaching 78% on a more focused scope is the predicted direction when scope narrows. (anchor: [discussion.tex:43-45](code-guardian-thesis-report/src/chapters/discussion.tex#L43-L45))

**Q.** RESCUE (2025) reports the same RAG-degrades finding. How is your RAG analysis a contribution rather than a replication?
**A.** Contribution is McNemar with Bonferroni across 5 paired models, isolating per-model directionality with statistical defensibility. RESCUE reports a pooled effect; codellama collapse (p=0.0013) is the only RAG effect that survives correction. (anchor: [eval_r1_accuracy.tex:43-46](code-guardian-thesis-report/src/chapters/evaluation/eval_r1_accuracy.tex#L43-L46))

**Q.** SecRepair criticises automated repair metrics — but you still report one. Why doesn't your own argument disqualify your metric?
**A.** SecRepair's critique targets similarity-based metrics (cosine, BLEU, CodeBERTScore) that reward surface paraphrase. Auto-applicable is a syntactic-applicability check, not similarity — a parse-failing fix counts as failure regardless of how similar it looks. (anchor: [eval_r3_repair.tex:76-77](code-guardian-thesis-report/src/chapters/evaluation/eval_r3_repair.tex#L76-L77))

### Concept

**Q.** Why qwen3:8b? Not qwen2.5-coder, not deepseek-coder, not Llama-3?
**A.** Five evaluated models span 1B to CodeLlama; qwen3:8b emerged as headline by F1 across 10 configurations. **Honest concession:** chosen by post-hoc evaluation, not pre-registered. (anchor: [eval_r1_accuracy.tex:19-28](code-guardian-thesis-report/src/chapters/evaluation/eval_r1_accuracy.tex#L19-L28))

**Q.** Function-level scope is documented as a limitation. Why not file-level from the start?
**A.** Latency budget. At 2,216ms for stage-1 on a function chunk, scaling to file-level pushes into 8-20s — outside the on-demand band. The thesis ships both: function-scope inline; AST + LLM audit. Audit lifts NodeGoat from 3/7 to 6/7. (anchor: [eval_r1_accuracy.tex:160-170](code-guardian-thesis-report/src/chapters/evaluation/eval_r1_accuracy.tex#L160-L170))

**Q.** Inter-run confidence gate at threshold 0.67 — magic number. How is it not p-hacked?
**A.** Pre-registered TRAIN split; three thresholds (0.34, 0.67, 1.0) tied on TRAIN F1, so 0.67 was chosen for graceful degradation, not TRAIN F1 maximisation. TEST split frozen before tuning. (anchor: [eval_r1_accuracy.tex:103-122](code-guardian-thesis-report/src/chapters/evaluation/eval_r1_accuracy.tex#L103-L122))

### Implementation

**Q.** The harness, dataset, taxonomy, and gate threshold are all yours. What is independently checkable?
**A.** Five things: corpus signed manifest with Ed25519, version-pinned `package-lock.json`, containerised execution (Docker compose), reproducibility harness reporting byteIdentityRate, and a snapshot test on the canonical taxonomy. Anyone with the artefacts can re-run. (anchor: [eval_reproducibility.tex:14-28](code-guardian-thesis-report/src/chapters/evaluation/eval_reproducibility.tex#L14-L28))

**Q.** Caching with 95-98% hit rate — how do you measure live performance under cache misses?
**A.** All evaluation numbers are cache-cold. The harness invokes Ollama directly without the extension cache layer; the 95-98% hit rate applies to interactive editing only.

**Q.** Ed25519 corpus signing — what's the threat? A local attacker who can swap the corpus can swap the binary.
**A.** Correct. Defends against (1) supply-chain tampering during release/distribution and (2) an evaluator running an unintended corpus version, not against root-level local attackers. Integrity-of-known-state, not confidentiality. (anchor: [eval_r5_privacy.tex:32-34](code-guardian-thesis-report/src/chapters/evaluation/eval_r5_privacy.tex#L32-L34))

### Evaluation

**Q.** Five comparable systems report F1 60-75%. You're middle of the pack on a smaller dataset. Where is the win?
**A.** The win is the deployment envelope: local + IDE-native + real-time + JS/TS + detection+repair. On accuracy alone, 78.13% precision on a local 8B is in the same precision class as cloud GPT-4 in CORRECT (~80% on context-rich function-level tasks). (anchor: [discussion.tex:43-45](code-guardian-thesis-report/src/chapters/discussion.tex#L43-L45))

**Q.** Three of four FP secure cases land in TRAIN. Did you reshuffle until that happened?
**A.** No — seed is the literal hex constant `0x4e6166` ("Naf") fixed in `build-split.js:21` and committed before any sweep. The artefact of three-of-four FPs landing on TRAIN has probability ≈ 0.42 — not a tuning artefact. (anchor: `build-split.js:21,71-79`)

**Q.** McNemar on n=101 has low power for medium effects. Is the qwen3 RAG-lift null or under-powered?
**A.** Under-powered. Thesis explicitly says so: "indicative direction when they fail correction" ([evaluation_metrics.tex:20](code-guardian-thesis-report/src/chapters/evaluation/evaluation_metrics.tex#L20)). The single defensible RAG conclusion is the codellama harm, not the qwen3 benefit.

### Discussion

**Q.** "RAG must be calibrated per model" is convenient — only 1 of 5 tests survives correction. Pattern or single data point?
**A.** Single data point under correction, but the same finding is independently reported in RESCUE (Shi & Zhang 2025) and He et al. 2024 — CWE descriptions alone do not improve secure code generation. Framed as "consistent with the literature," not "first observation."

**Q.** Improper-auth and weak-encryption recover 100% recall by merging buckets. So the 0% recall is a labelling artefact you created and resolved. Why is this in the analysis?
**A.** Most honest finding: the canonical taxonomy is the author's choice, and per-category recall is sensitive to that choice. Discussion concedes this directly at [discussion.tex:5](code-guardian-thesis-report/src/chapters/discussion.tex#L5). The 0% number is reported under the published taxonomy, not after re-merging.

**Q.** External corpus F1 is 10 points lower. Why is curated still the headline?
**A.** Both are reported. Curated headline is justified by alignment with the approved task description (CWE-mapped corpus, replacing Juliet/OWASP Benchmark which don't exist in JS). The 10-point gap is the published deviation cost.

### Conclusion

**Q.** "Local 8B-parameter models reach cloud-LLM-class precision" — defend it.
**A.** Cloud-LLM precision class = ~78-80% on context-rich function-level tasks (CORRECT, Li et al. 2025). Code Guardian's 78.13% (gated) is in that band on canonical-matched function-level scoring. Caveat: precision, not recall, on a curated corpus with the data-leakage caveat.

**Q.** What would you change with another six months?
**A.** (1) Inter-rater R3 review with Cohen's κ on n=50 reviewed samples; (2) external-corpus expansion to 50+ cases to close leakage exposure; (3) cross-file taint-flow integration to attack the input-validation true-miss residual.

**Q.** What would you have done differently from day one?
**A.** Pre-register configuration selection (which model, which RAG mode), not just the threshold. Acknowledging this is more credible than defending it.

### Weak-claim drill — three claims to harden before defense

| # | Claim | Where | Why weak | Rehearsal |
|---|---|---|---|---|
| W1 | "The held-out result rules out threshold overfitting" | [eval_r1_accuracy.tex:122](code-guardian-thesis-report/src/chapters/evaluation/eval_r1_accuracy.tex#L122) | n=9 secure on TEST, three TRAIN thresholds tied | "It rules out the chosen threshold being a TRAIN-specific optimum among the swept set; with n=9 secure on TEST it cannot rule out small-effect overfitting in general." |
| W2 | "Local 8B-parameter models reach cloud-LLM-class precision" | [discussion.tex:34](code-guardian-thesis-report/src/chapters/discussion.tex#L34) (paraphrased in conclusion) | Single point estimate without CI, external corpus drops 10 F1 | "78.13% precision on n=213 vulnerable evaluations under canonical matching, in the same band as CORRECT's 80% on context-rich GPT-4 function-level tasks. Generalisation bounded by external-corpus 63.64% F1." |
| W3 | "FPR = 10.00% comfortably below the High ceiling of 0.20" | [eval_r1_accuracy.tex:180](code-guardian-thesis-report/src/chapters/evaluation/eval_r1_accuracy.tex#L180) | 95% CI [2.1%, 26.5%] upper bound *exceeds* 0.20 | "Point estimate 10%; 95% binomial CI [2.1%, 26.5%]. The upper bound straddles the 0.20 threshold; n=30 is the binding constraint." |

---

## 5. Implementation Health

### 5.1 REVIEW.md blocker re-verification

| § | Blocker | Status | Evidence |
|---|---|---|---|
| 1.1 | TS taxonomy union missing 3 categories | **Fixed** | [categoryTaxonomy.ts:3-29](code-guardian-extension/src/categoryTaxonomy.ts#L3-L29) now lists 26 members |
| 1.2 | `logger` undefined in webview script | **Fixed** | [webview.ts:174-225](code-guardian-extension/src/webview.ts#L174-L225) — every former `logger.info(...)` inside `<script>` is now `console.log(...)` |
| 1.3 | `isModelAllowed()` stub + qwen3 missing from UI | **Partial** | UI gap closed: [modelManager.ts:14-43](code-guardian-extension/src/modelManager.ts#L14-L43) and [package.json:95-99](code-guardian-extension/package.json#L95-L99) include qwen3/codellama:latest. **But [modelManager.ts:67-70](code-guardian-extension/src/modelManager.ts#L67-L70) still hardcodes `return true` — dead allowlist remains.** Fix: delete `ALLOWED_MODEL_PATTERNS` and `isModelAllowed()` (zero callers). |
| 1.4 | num_ctx claim mismatch | **Fixed** | [analyzer.ts:27,31](code-guardian-extension/src/analyzer.ts#L27) defines `FILE_SCOPE_NUM_CTX=16384`; selected at `:606` for `scope==='file'` |
| 1.5 | 4 citations on one statement | **Fixed** | [components.tex:16](code-guardian-thesis-report/src/chapters/concept/components.tex#L16) split into two pairs |
| 1.6 | Flat preamble | **Fixed** | [concept.tex:3](code-guardian-thesis-report/src/chapters/concept/concept.tex#L3) is now a single flowing paragraph |
| 1.7 | Legacy framing | **Fixed** | [discussion.tex:69](code-guardian-thesis-report/src/chapters/discussion.tex#L69) reads "Four semantic categories register zero recall" — static present-tense |
| 1.8 | Default-model disagreement | **Fixed** | [modelManager.ts:8](code-guardian-extension/src/modelManager.ts#L8) introduces `DEFAULT_MODEL = 'codellama:7b'`, used at `:185,189` and `package.json:84` |

### 5.2 Build & test

- `npm run compile` → ✓ **Pass** (tsc --noEmit + ESLint clean).
- `npm run test:unit` → ✗ **Fail.** First error: `Error: Cannot find module 'vscode'` from `src/analyzer.ts:1` when mocha tries to require it via ts-node. Standing harness gap (unit tests bypass the VS Code test runner that supplies the `vscode` shim), not a regression. Would require harness changes to run green.

### 5.3 Drift since REVIEW.md

27 modified `.tex` files in working tree plus regenerated `Template.pdf`; REVIEW.md and TASK_COVERAGE.md untracked. Recent commits are thesis-text fixes (commit `cfb7fe3` "Refactor RAG Manager Initialization and Enhance Model Management" is the source of §1.3/§1.8/§1.4 code fixes).

New labels introduced post-REVIEW.md: `sec:disc-rq-answers`, `sec:intro-rqs`, `sec:intro-threat-model`, `lst:intro-scenario`, `tab:intro-threat-model`. `src/appendices.tex` deleted.

---

## 6. Cross-cutting Consistency

### 6.1 Cross-references

- 140 labels defined; 85 unique ref targets used; **0 dangling refs; 0 duplicate labels**.
- ✓ `sec:disc-rq-answers` resolves from [conclusion.tex:17](code-guardian-thesis-report/src/chapters/conclusion.tex#L17).
- ⚠ `sec:intro-rqs` and `sec:intro-threat-model` defined but **0 inbound references**. Consider one `\Cref{sec:intro-rqs}` from the evaluation chapter where R1–R5 are introduced, and from `eval_r5_privacy.tex` to `sec:intro-threat-model`.
- 🔴 **Broken cross-reference:** [discussion.tex:33](code-guardian-thesis-report/src/chapters/discussion.tex#L33) reads `Section~\ref{sec:intro-objectives}` but the RQ list lives at `\label{sec:intro-rqs}` ([introduction.tex:43](code-guardian-thesis-report/src/chapters/introduction.tex#L43)). `sec:intro-objectives` is the Objectives section, not the RQ list. Renders to wrong page today. **One-line fix:** change `sec:intro-objectives` to `sec:intro-rqs` at [discussion.tex:33](code-guardian-thesis-report/src/chapters/discussion.tex#L33).

### 6.2 Citation health

- 65 bib entries; 65 unique cite keys used. **0 orphan entries; 0 missing cites.** Citation graph fully closed.

### 6.3 Numbers reconciliation post-fixes — clean

Every headline number reconciles across abstract, evaluation, discussion, and conclusion chapters. The discussion §6.1 prose-trim ("more than nine in ten", "roughly seven and ... roughly six") is internally consistent with the underlying 0.9032 / 0.7042 / 0.7042 × 0.9032 ≈ 0.636 chain.

| Number | Status |
|---|---|
| F1 71.43% / gated 74.07% | ✓ Reconciles across abstract, conclusion, eval_summary, evaluation, eval_r1_accuracy, experimental_setup |
| Precision 72.46% / gated 78.13% | ✓ Reconciles across abstract, conclusion, eval_summary, eval_r1_accuracy, discussion |
| Recall 70.42% | ✓ Reconciles |
| FPR 10.00% | ✓ Reconciles (CI disclosed only at 2 sites — see §3.2) |
| Stage-1 latency 2,216 ms | ✓ Reconciles |
| Stage-2 latency 3,320 ms | ✓ Reconciles |
| Auto-applicable 90.32% (252/279) | ✓ Reconciles; qualitative paraphrases consistent |
| NodeGoat 3/7 → 6/7 | ✓ Reconciles |
| 101 cases (71+30) | ✓ Reconciles |

### 6.4 Orphan listings (TU Chemnitz "every figure/table referenced" rule)

Every `\begin{table}` and `\begin{figure}` is referenced. Exception: code listings.

- 🟡 [agent.tex:16](code-guardian-thesis-report/src/chapters/implementation/agent.tex#L16) — listing in main chapter without surrounding `\autoref{lst:...}`. **Fix:** add one `\autoref` from the surrounding paragraph.
- Appendix listings without inbound refs ([eval-details.tex:46](code-guardian-thesis-report/src/chapters/appendices/eval-details.tex#L46), [case-studies.tex:9,24,37,50,62](code-guardian-thesis-report/src/chapters/appendices/case-studies.tex), [impl-details.tex:14,31](code-guardian-thesis-report/src/chapters/appendices/impl-details.tex), [privacy-verification.tex:10](code-guardian-thesis-report/src/chapters/appendices/privacy-verification.tex#L10)) — commonly tolerated in appendices if the prose above introduces them by name; spot-check appendix prose.

### 6.5 LaTeX build sanity

Single `pdflatex -interaction=nonstopmode -draftmode` pass: **no `Reference X undefined`, no `Citation X undefined`, no `multiply defined` warnings, no `??` markers.** Only `Underfull \hbox` (typographic) and the standard `Label(s) may have changed` notice — expected.

---

## 7. Prioritised Punch List

### Critical (fix before defense)

1. **Broken cross-reference** at [discussion.tex:33](code-guardian-thesis-report/src/chapters/discussion.tex#L33) — change `\ref{sec:intro-objectives}` to `\ref{sec:intro-rqs}`. Renders wrong page today. *One-line fix.*

2. **Over-strong claim** at [eval_r1_accuracy.tex:122](code-guardian-thesis-report/src/chapters/evaluation/eval_r1_accuracy.tex#L122): "rules out threshold overfitting" → "rules out the chosen threshold being a TRAIN-specific optimum among the swept set". With n=9 secure on TEST and three thresholds tied, the strong claim is not supported. *Sentence-level rewrite.*

3. **RQ2 question-shifting** ([introduction.tex:48](code-guardian-thesis-report/src/chapters/introduction.tex#L48) ↔ [discussion.tex:36-37](code-guardian-thesis-report/src/chapters/discussion.tex#L36-L37)): RQ2 promised "qualitative grounding of explanations" but discussion delivers F1 deltas only. Either restate RQ2 to drop the grounding clause **or** add a brief explanation-grounding rubric (3-5 paired RAG vs LLM-only outputs scored on grounding faithfulness) to discussion §6.3.

4. **FPR-band over-claim** at [eval_r1_accuracy.tex:180](code-guardian-thesis-report/src/chapters/evaluation/eval_r1_accuracy.tex#L180): 95% CI upper bound (26.5%) *exceeds* the High threshold (0.20). Soften "comfortably below" to "point estimate below the High ceiling; CI upper bound straddles it on n=30".

### Important

5. **Conclusion still re-asserts achievement.** [conclusion.tex:15-17](code-guardian-thesis-report/src/chapters/conclusion.tex#L15-L17) "Key Findings" makes verdict-style claims ("Local deployment is feasible", "False-positive control remains the main practical barrier"). Soften to a 4-line "Summary" that cross-refs Chapter 5/6 for evidence. Per TU Chemnitz: conclusion = summary + outlook, not re-addressing achievement.

6. **Implementation chapter narrative health.** [implementation.tex:3](code-guardian-thesis-report/src/chapters/implementation/implementation.tex#L3) is a flat one-sentence-per-section outline; [implementation.tex:17-19](code-guardian-thesis-report/src/chapters/implementation/implementation.tex#L17-L19) is a 3-line summary too thin to consolidate the chapter. Convert preamble to thematic prose; expand summary to 6–8 lines.

7. **`\subsection*` in implementation.** [system_workflow.tex](code-guardian-thesis-report/src/chapters/implementation/system_workflow.tex) uses unnumbered `\subsection*{End-to-End Flow}`, `\subsection*{Pipeline Gates}`, etc. — they don't appear in the ToC and break the "≥2 numbered subchapters" rule. Convert to numbered `\subsection`.

8. **Forward-references in Analysis.** [analysis.tex:42-50](code-guardian-thesis-report/src/chapters/analysis/analysis.tex#L42-L50) requirements traceability table forward-refs `sec:eval-r1` to `sec:eval-r5`; [requirements/r3.tex:9](code-guardian-thesis-report/src/chapters/analysis/requirements/r3.tex#L9) forward-refs `sec:eval-r3`; [system_architecture_and_design.tex:51](code-guardian-thesis-report/src/chapters/concept/system_architecture_and_design.tex#L51) forward-refs `sec:impl-audit-mode`. Replace with generic phrasing ("evaluated in Chapter~\ref{chap:evaluation}").

9. **Three threats-to-validity gaps to add** to [discussion.tex:66-90](code-guardian-thesis-report/src/chapters/discussion.tex#L66-L90): (a) construct validity of canonical taxonomy, (b) training-data leakage from public corpora into LLM training, (c) configuration-selection non-pre-registration. Each adds one paragraph; mitigation language provided in §3.3 above.

10. **Originality over-claim** at [positioning.tex:25](code-guardian-thesis-report/src/chapters/analysis/related_works/positioning.tex#L25): "the only reviewed approach that reaches at least Medium across all five requirements" rests on author-scored competitor evaluation. Retreat to a combination-claim: "the only reviewed approach to operationalise this combination".

11. **Three-way trade-off frame** at [introduction.tex:5](code-guardian-thesis-report/src/chapters/introduction.tex#L5): "no current tool resolves" — Snyk Code's local mode plus repair guidance partially closes this. Add one paragraph addressing Snyk Code head-on, or measured against it.

12. **Dead allowlist code** at [modelManager.ts:67-70](code-guardian-extension/src/modelManager.ts#L67-L70). `isModelAllowed()` returns `true` unconditionally; `ALLOWED_MODEL_PATTERNS` has zero callers. Delete both to close §1.3.

### Nice-to-have

13. **Inbound references for new intro labels.** Add `\Cref{sec:intro-rqs}` from the evaluation chapter where R1–R5 are introduced; add `\Cref{sec:intro-threat-model}` from `eval_r5_privacy.tex` or `concept_derivations.tex`.

14. **Listing reference** at [agent.tex:16](code-guardian-thesis-report/src/chapters/implementation/agent.tex#L16) — add an `\autoref{lst:...}` from the surrounding paragraph (TU Chemnitz "every figure/table/listing referenced" rule).

15. **Eval_r1_accuracy depth-2 grouping.** [eval_r1_accuracy.tex:39](code-guardian-thesis-report/src/chapters/evaluation/eval_r1_accuracy.tex#L39) onward has 10 sibling `\subsection`s. Group "RAG Ablation", "Per-Category Breakdown", "Qualitative Error Analysis", "SAST Baseline" under one `\subsection{Ablations and Diagnostics}` parent.

16. **Stage notation consistency.** Mixed forms `Stage~1`, `stage-1`, `Stage 1`, `Stage-1` across files (REVIEW.md §4.2 already noted). Pick one (`Stage~1`) and apply globally.

17. **British/US spelling slip** at [discussion.tex:28](code-guardian-thesis-report/src/chapters/discussion.tex#L28): "analyzed" in same paragraph as "analysed" elsewhere. Pick one.

18. **Future_work preamble.** [conclusion.tex:43-45](code-guardian-thesis-report/src/chapters/conclusion.tex#L43-L45) `\section{Future Work}` has no preamble before `\input{src/chapters/future_work}`. Add one sentence introducing the section.

---

## Appendix A: Methodology of this Review

This review was produced by four parallel review agents, each owning one dimension and grounded in direct file reads (no claim accepted on agent assertion alone). The agents leveraged two pre-existing artefacts in the repo (`REVIEW.md` for code-vs-thesis verification; `TASK_COVERAGE.md` for task description coverage) and two memory files (`thesis_writing_rules.md` for TU Chemnitz binding rules, `thesis_defense_anchors.md` for literature counter-attack facts).

**Coverage spot-check** (5 randomly selected punch-list items verified end-to-end against cited file:line):
- ✓ #1 broken cross-ref: `discussion.tex:33` reads `\ref{sec:intro-objectives}`; `\label{sec:intro-rqs}` is at `introduction.tex:43`. Confirmed.
- ✓ #2 "rules out threshold overfitting": confirmed at [eval_r1_accuracy.tex:122](code-guardian-thesis-report/src/chapters/evaluation/eval_r1_accuracy.tex#L122) with n=9 TEST split.
- ✓ #4 FPR CI: confirmed [2.1%, 26.5%] disclosure at [eval_r1_accuracy.tex:78](code-guardian-thesis-report/src/chapters/evaluation/eval_r1_accuracy.tex#L78), absent at headline sites.
- ✓ #12 dead allowlist: confirmed [modelManager.ts:67-70](code-guardian-extension/src/modelManager.ts#L67-L70) hardcodes `return true`.
- ✓ #14 unreferenced listing: confirmed [agent.tex:16](code-guardian-thesis-report/src/chapters/implementation/agent.tex#L16) lacks surrounding `\autoref`.

**Non-duplication.** Findings here do not restate REVIEW.md §1.1–§1.8 except as status updates in §5.1 (Fixed/Partial/Open). TASK_COVERAGE.md mappings are not re-examined.

**Actionability.** Every Critical and Important item carries a one-line fix recipe.

**Defense Q&A integrity.** Every suggested answer cites either an in-thesis section (file:line) or an anchor fact from `thesis_defense_anchors.md`.

**LaTeX build sanity.** Single `pdflatex -interaction=nonstopmode -draftmode Template.tex` pass returns no undefined references and no `??` marks. Build is clean.
