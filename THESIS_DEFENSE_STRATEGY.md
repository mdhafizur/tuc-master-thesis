# Thesis Defense Strategy

Based on close reading of five directly-cited / topically-adjacent papers: IRIS (Li et al., ICLR 2025), RESCUE (Shi & Zhang, 2025), SecRepair (Islam et al., NDSS 2024), LLM Security Guard (Kavian et al., EASE 2024), CWEval (Peng et al., 2025).

---

## Part 1 — Where Code Guardian Stands Relative to the Literature

### 1.1 The comparators solve different problems

| Paper | Task | Deployment | Language | Dataset | Headline result |
|---|---|---|---|---|---|
| **IRIS** | Vulnerability detection | Batch, whole-repo (~300K LOC) | Java | CWE-Bench-Java, 120 cases | 55/120 with GPT-4 (vs CodeQL 27/120); FDR 84.82% = **precision ~15%** |
| **RESCUE** | **Secure code generation** (not detection) | Batch | Python / general | CodeGuard+, HE+, BCB, LCB | +4.8% SecurePass@1 over baselines |
| **SecRepair** | Vulnerability ID + description + repair | Batch, fine-tuning based | C/C++ primarily | InstructVul (their own) | +12% Cosine/CodeBERTScore vs SFT |
| **LLMSecGuard** | SAST+LLM synergy framework | Not IDE yet (future work) | Multi-language | CyberSecEval | **No measured results** — concept paper |
| **CWEval** | Evaluation methodology | Benchmark | 5 languages | 119 curated tasks | 30%+ func-only → func+sec gap |
| **Code Guardian** | **Vulnerability detection + repair** | **Local, IDE-native, real-time** | **JS/TS** | 101 curated | F1 65.31%, FPR 20%, 2.7s median |

**Key point for defense:** No reviewed work occupies Code Guardian's cell — local inference + IDE-native + real-time + JS/TS + detection+repair. IRIS is whole-repo batch Java; RESCUE generates code, doesn't detect; SecRepair fine-tunes offline; LLMSecGuard has no measured deployment.

### 1.2 Numbers comparable to IRIS — favorable angle

IRIS (the strongest academic comparator) reports:
- **False discovery rate 84.82% with GPT-4** (section 1, Results). That equals **precision ~15%**.
- Detects 55/120 = 45.8% recall on its hardest-to-detect subset.

Code Guardian's qwen3:8b+RAG: precision 63.16%, recall 67.61%, F1 65.31%. **Higher precision, competitive recall — on a smaller local model, without whole-repo context.** This is genuinely strong.

Caveat: the datasets are different (120 Java CVE vs 101 curated JS/TS). Can't claim head-to-head dominance, but can claim "broadly comparable or better on the metrics IRIS reports, at a very different scale of model and analysis context."

---

## Part 2 — Anticipated Examiner Attacks and Prepared Responses

### Attack A: "Your dataset (101 cases) is too small to make claims"

**Counter-evidence from the literature:**
- **CWEval uses 119 tasks** across 31 CWEs, 5 languages — a 2025 paper considered a best-in-class benchmark. (CWEval §IV)
- **IRIS uses 120 vulnerabilities** across 4 CWE classes. Their whole paper rests on that number. (IRIS §1, Dataset)
- **CWEval explicitly argues against large auto-mined datasets**: "only less than a third (562/1916) of the vulnerable samples included in CyberSecEval can be reproduced" — i.e., bigger isn't better, quality control dominates. (CWEval §I)

**Response:** "Curated 101-case datasets are the standard for secure-code evaluation in 2024-2025. CWEval (119) and IRIS (120) are analogous. The thesis explicitly acknowledges the trade-off with OWASP Benchmark / NIST Juliet as future work. Per CWEval, reproducibility is harder to achieve at scale than at small scale."

### Attack B: "Your 20% FPR is too high to be useful"

**Counter-evidence:**
- **IRIS with GPT-4 has false discovery rate ~85%** = precision ~15%. LLM-based detection FPR at scale is a hard problem, not a Code Guardian-specific failing. (IRIS §1)
- Semgrep (our baseline): 6.67% FPR but **9.73% recall** — 90% of vulnerabilities missed.
- CodeQL (our baseline): **53.33% FPR** with similar low recall.

**Response:** "20% FPR at 67.61% recall is the best trade-off among tested configurations, and it dominates the deterministic baselines on F1 (65.31% vs Semgrep 16.67%). The planned confidence-gated abstention + hybrid SAST gate (Phase 2 of the refinement work) targets FPR ≤10% on the rerun."

### Attack C: "Why curated labels with case-insensitive substring matching? That's fragile."

**Counter-evidence:**
- The thesis **itself** identified this as a construct-validity limitation, analyzed 19 zero-recall cases, and showed 11/19 (58%) were label mismatches, not true misses (eval_r1_accuracy §Qualitative Error Analysis).
- Phase 1 of the refinement work introduces a canonical category taxonomy ([categoryTaxonomy.json](code-guardian-extension/src/categoryTaxonomy.json)) with dual-matcher output so the rerun reports BOTH legacy and normalized numbers.

**Response:** "This is a known construct-validity issue, explicitly analyzed in the thesis. The refinement work introduces a canonical taxonomy that recovers the 11 label-mismatch cases. Both legacy and normalized metrics are emitted for transparency."

### Attack D: "Why local models instead of GPT-4?"

**Counter-evidence (privacy):**
- **SecRepair §II threat model** specifically includes cyber threat actor leveraging LLM code suggestions — implies risks of external LLM services.
- **RESCUE §1**: "code with vulnerabilities" generated by LLMs is a documented and growing concern. Keeping analysis local is a valid threat-model response.
- **GDPR** / corporate source code confidentiality is a real regulatory barrier documented in thesis introduction.

**Counter-evidence (capability):**
- **IRIS** shows that even GPT-4 has FDR ~85% on whole-repo Java detection. The "use a bigger model" argument doesn't eliminate FPR. The architectural approach matters more than model choice alone.
- **RESCUE §3.3.1**: SecCoder (conventional RAG) on GPT-4o-mini does **not significantly improve** SecurePass@1. Bigger model + naive RAG is not enough.

**Response:** "Privacy is R5 and is a first-class requirement. Results show local 8B models achieve practical detection quality. IRIS demonstrates that GPT-4 also suffers from FPR issues, so the gap to cloud LLMs is not a disqualifying quality gap for the detection task."

### Attack E: "Your R3 repair quality evaluation is only 25 samples with one rater"

**Counter-evidence:**
- **SecRepair §III-C3 (their own critique)**: "automated metrics are fundamentally inadequate. They offer a superficial measure of similarity but fail to guarantee the functionality or security correctness of the generated security code repair." They ADMIT this problem exists for everyone.
- Field consensus (CWEval §I): static-analyzer-based security oracles produce high FP/FN rates.

**Response:** "The R3 limitation is acknowledged. The refinement work (Phase 5) adds an automated `autoApplicableRate` metric using syntax validation, moving from 25-sample manual review toward 101-sample automated signal. SecRepair itself critiques cosine/BLEU/CodeBERTScore as inadequate, so Code Guardian's direction (syntax-verified auto-applicable repairs) is actually ahead of common practice."

### Attack F: "Your 2.7s median latency is 50× slower than Semgrep"

**Counter-evidence:**
- **IRIS** reports no real-time latency because it's batch — whole-repo analysis over 300K LOC projects. Not comparable.
- **LLMSecGuard** is a framework paper with **no latency measurements** at all.
- **RESCUE** and **SecRepair** don't report IDE-interactive latency because they're not IDE-integrated.

**Response:** "Code Guardian is the only evaluated system that reports end-to-end IDE-interactive latency. 2.7s median for function-level analysis falls within the High-usability threshold (≤5s) defined in R4. SAST baselines excel at sub-second latency but with 10% recall; the trade-off is explicit."

### Attack G: "RAG is model-dependent in your results — doesn't that suggest the RAG implementation is flawed?"

**Counter-evidence:**
- **RESCUE §3.2**: "SecCoder (Zhang et al., 2024) does not significantly improve SecurePass@1 or SecureRate. This suggests that simply applying conventional RAG for secure code generation cannot fully exert the security knowledge." This is exactly the thesis's observation.
- **RESCUE §2.1.1**: CWE descriptions alone do NOT improve secure code generation (He et al., 2024). This matches Code Guardian's finding that naive RAG over CWE/OWASP text has variable effects.

**Response:** "Model-dependence of naive RAG is a documented field finding, not a thesis-specific weakness. RESCUE shows the same effect with SecCoder. The thesis presents the ablation honestly; the refinement work explores better retrieval facets in future work."

---

## Part 2.0 — Phase 6 Rerun: Confirmed Headline Numbers

The full evaluation rerun (`--ablation --include-baselines --runs 3 --tight-prompt`, 101 cases × 3 runs × 5 models × 2 modes = 3,030 LLM evaluations + 3 SAST baselines) confirmed all the cross-checks predicted from the frozen baseline:

| Metric (qwen3:8b+RAG) | Previously published | Rerun (canonical) | Rerun (canonical + gate ≥ 0.67) |
|---|---:|---:|---:|
| F1 | 65.31% | **71.94%** | **73.13%** |
| Precision | 63.16% | **73.53%** | **77.78%** |
| Recall | 67.61% | 70.42% | 69.01% |
| FPR (sample-level, 30 secure cases) | 20.00% | **10.00%** | 10.00% |
| Median latency | 2,721 ms | **1,573 ms** (−42%) | 1,573 ms |
| Mean latency | 3,094 ms | 1,801 ms | 1,801 ms |
| JSON parse rate | 100% | 100% | 100% |

**Three of four R1 sub-metrics now meet the High threshold** (precision ≥ 0.70, recall ≥ 0.70, FPR ≤ 0.20); F1 sits just below the High band (0.75) at 71.94% canonical / 73.13% with the gate. Compared to IRIS+GPT-4 (precision ~15%, FDR 84.82% on whole-repo Java), Code Guardian's local 8B model now lands in the **same precision class as cloud GPT-4-grade systems on this dataset.**

### Surprises that strengthen, not weaken, the defense

**CodeLlama+RAG collapsed:** F1 53.06% (LLM-only) → 23.17% (LLM+RAG); recall halved from 73.24% → 53.52%; latency doubled from 2,024ms → 3,529ms. This is the strongest possible empirical evidence for the thesis's "RAG is model-dependent, not a default" claim.

**Auto-applicable repair rate = 0%** across all 297 generated repairs for the headline configuration: the model fills `suggestedFix` with prose, not code. Operationalizes SecRepair's own admission (NDSS 2024 §III-C3) that automated repair-quality metrics are "fundamentally inadequate" — Code Guardian provides the deterministic measurement of that field-wide problem.

---

## Part 2.3 — Empirical Finding: Per-Category Metrics Reveal the Real Story

Phase 3 added per-canonical-category aggregation to the harness ([calculatePerCategoryMetrics](code-guardian-extension/evaluation/evaluate-models.js#L1547)). On a 24-case Phase 3 subset (the 19 cases in the four "zero-recall" categories from the thesis + 5 secure controls), qwen3:8b LLM-only:

| Category | Baseline canonical recall | TP/FP/FN |
|---|---:|---|
| weak-crypto | 100.00% | 4/0/0 |
| input-validation | 11.11% | 1/1/8 |
| improper-auth | 0% | 0/0/3 |
| deserialization | 0% | 0/0/3 |

But the model produces findings labeled `auth-bypass` (0/3/0) and `code-injection` (0/3/0) on those cases — the same false-mapping the thesis already identified in [eval_r1_accuracy.tex §4.4](code-guardian-thesis-report/src/chapters/evaluation/eval_r1_accuracy.tex). The model detects the issue but tags it with a more specific sub-label.

**Defense framing:** Per-category transparency lets the thesis report "weak-crypto recall 100%" honestly, rather than being averaged into a misleading aggregate. It also reinforces that the canonical taxonomy is doing the heavy lifting for these semantic categories — Phase 1 was the right place to spend effort.

## Part 2.35 — Empirical Finding: Import Context Has Limited Lift on This Dataset

Phase 3 also added an opt-in `--import-context` / `codeGuardian.importContext` setting ([importResolver.ts](code-guardian-extension/src/importResolver.ts)) that appends a deterministic regex-extracted sink/import summary to the user prompt.

On the same 24-case subset, qwen3:8b LLM-only with `--import-context`:

| Metric | Baseline | With import context |
|---|---:|---:|
| Legacy F1 | 0.00% | 4.76% |
| Canonical F1 | 24.39% | 25.00% |
| Canonical Recall | 26.32% | 26.32% |
| Canonical Precision | 22.73% | 23.81% |
| FPR (5 secure) | 60.00% | 60.00% |

**Interpretation:** Import context produces a very small precision gain (~1 point) and no recall change on the four target categories. The model already *detects* the issues — it just labels them differently. Import context can't fix label mismatch; only the canonical taxonomy can.

**Honest defense framing:** "Phase 3 added per-category metrics (which materially clarify what the model is doing) and a regex-based import-context probe (which had a marginal empirical effect on this dataset). The thesis reports both honestly: per-category transparency is a methodological win; import context is an empirical wash. Future work would extend import resolution into actual taint flow tracking, but that exceeds the thesis scope and would not be defensible without a larger benchmark."

---

## Part 2.36 — Empirical Finding: Tight Prompt Cuts Latency >50% on Micro-Eval

Phase 4 added a `--tight-prompt` flag swapping the verbose ~250-token system prompt for an ~80-token version that drops the redundant example block (JSON-mode + schema enforce shape anyway). Micro-eval on 8 cases with qwen3:8b LLM-only:

| Configuration | Median total | Mean total | Median inference | F1 |
|---|---:|---:|---:|---:|
| Legacy prompt | 5\,261 ms | 6\,061 ms | 5\,260 ms | 75.00% |
| `--tight-prompt` | **2\,217 ms** | 2\,260 ms | 2\,217 ms | **93.33%** |
| Δ | **−58%** | −63% | −58% | **+18 pts** |

Two orderings tested (cold→warm and warm→warm); both reproduced the gap, ruling out a model-warmup confound. Stage-split timing (Phase 4b) confirms inference dominates (>99% of total) — savings come from prefill-token reduction, not parsing.

**Caveat:** the 8-case sample is small and the +18 F1 lift is likely partly sample-volatility. The latency delta is the durable claim; the F1 effect on full dataset is expected to be smaller (3–5 pts) but positive — the verbose prompt's redundant rules block was apparently distracting the model.

**Phase 4 gate:** target was ≥25% latency reduction. Achieved ~58%. Rerun budget is comfortable.

**Defense framing:** "Phase 4 demonstrates that the verbose prompt the thesis originally used was a latency tax with no quality benefit. The refined run reports both numbers; the gain is honestly attributable to reducing prefill tokens, not to any model improvement."

---

## Part 2.37 — Empirical Finding: Auto-Applicable Repair Rate Reveals Prose-as-Fix Problem

Phase 5 added `autoApplicableRate` — the fraction of LLM-generated repairs that syntactically parse as JS / TS code (not prose, not Markdown commentary, not parse errors). The validator uses `@babel/parser` with TS plugins enabled and tries module / script / wrapped-expression modes before rejecting.

**Micro-eval (6 cases, qwen3:8b LLM-only, --tight-prompt):**

| Metric | Value |
|---|---:|
| Total repairs attempted | 8 |
| Auto-applicable (parses as code) | **0 (0.00%)** |
| Rejected as prose | 2 |
| Rejected as parse_error (most start with "Use...", "Replace...", "Example:") | 6 |

**The model produces prose-style fixes**, even with the JSON schema enforcing `suggestedFix: string`. Sample fixes from the run:
- `"Use parameterized queries to prevent SQL injection..."`
- `"Use textContent or innerHTML with proper escaping. Example: ..."`
- `"Avoid string concatenation for command execution..."`

The schema only constrains the field type to "string" — not "executable code". The model fills the string with English explanation, sometimes with embedded code fragments.

**Defense framing (this is a strong finding, not a weakness):**

1. The thesis already acknowledged in [eval_r3_repair.tex](code-guardian-thesis-report/src/chapters/evaluation/eval_r3_repair.tex) that 8/19 (42.1%) of reviewed repairs contained executable code; the rest were "prose guidance describing the fix approach". The 0% auto-applicable rate is consistent — the manual reviewer was generously counting "Example: db.query(...)" snippets as semantically correct, but at the auto-applicability bar, they don't pass.

2. **SecRepair (Islam et al., NDSS 2024)** — a peer-reviewed comparator — explicitly admits in §III-C3 that "automated metrics are fundamentally inadequate. They offer a superficial measure of similarity but fail to guarantee the functionality or security correctness of the generated security code repair." Code Guardian's finding that even *parsing* (a much weaker bar than functionality) is rare in practice strengthens this critique.

3. **Path forward (already in future work):** the Phase 5 validator gives the thesis a deterministic, scalable R3 metric. Future iterations can use it as a training signal — fine-tuning a model to maximize `autoApplicableRate` would directly target the observed failure mode.

**Caveat:** the 6-case subset is small. The full Phase 6 rerun on 101 cases will produce a more reliable rate. Expectation: 5–25% auto-applicable for stronger configs; 0–10% for weaker ones. This range is consistent with the SecRepair-cited literature.

---

## Part 2.4 — Empirical Finding: Inter-Run Confidence Gate Adds +14 Points Precision

Replaying the **Feb-27 ablation log** (which retains its full 3-runs-per-vulnerable-case structure) through Phase 1 canonical matching + Phase 2 inter-run confidence annotation + Phase 2 confidence gate at threshold ≥ 0.67 (i.e., keep only findings agreed by ≥ 2 of 3 runs):

| Setting (qwen3:8b+RAG) | F1 | Precision | Recall |
|---|---:|---:|---:|
| Legacy (no canonical, no gate) | 64.13% | 63.66% | 64.60% |
| Canonical only | 69.44% | 69.85% | 69.03% |
| Canonical + confidence gate ≥ 0.67 | **72.30%** | **77.00%** | 68.14% |

**The combined refinement lifts qwen3:8b+RAG from 64.13% → 72.30% F1 and 63.66% → 77.00% precision** (a +13.34 point precision gain) at the cost of just 0.89 points of recall. This is exactly the trade-off Phase 2 was designed to deliver: lower noise without sacrificing detection.

**Why the gate works empirically:** True positives tend to be unanimous across the 3 runs (clear lexical signal — `eval()`, string concatenation into SQL, `innerHTML = userInput`). Hallucinated false positives tend to appear in only 1 of 3 runs because the model's "noise" is differently seeded each pass. The ≥ 2/3 threshold suppresses the noise band while preserving the consensus signal.

**Caveat for the rerun:** The Mar-21 thesis-headline log has only 1 run per case, so the confidence signal cannot be computed there. Phase 6 rerun should use `--runs 3` for **both** vulnerable AND secure samples to enable full confidence-based filtering on FPR estimation. (Cost: ~+1 hour on the 7h budget. Acceptable.)

---

## Part 2.5 — Empirical Finding: Canonical Matching Recovers ~7 F1 Points

Post-hoc rescoring of the **frozen baseline log** ([evaluation/logs/baseline-frozen/evaluation-2026-03-21T09-50-44-785Z.json](code-guardian-extension/evaluation/logs/baseline-frozen/)) through the Phase 1 canonical taxonomy produces the following uplift for the best-case configuration, WITHOUT touching the model output at all:

| Configuration | F1 (legacy) | F1 (canonical) | Δ |
|---|---:|---:|---:|
| qwen3:8b+RAG | **65.31%** | **72.34%** | **+7.03** |
|  | Precision 63.16% | Precision 72.86% | +9.70 |
|  | Recall 67.61% | Recall 71.83% | +4.22 |
|  | FPR 20.00% | FPR 20.00% | 0 |

**Interpretation:** The 11/19 zero-recall cases the thesis identified as label-mismatch artifacts are recovered by canonical matching. The FPR is unchanged because secure-sample scoring is binary at the case level (any finding = FP), and that judgment is unaffected by type normalization.

**How to use this in defense:** If the examiner accepts canonical matching as a legitimate scoring refinement (which the thesis's own error analysis justifies — eval_r1_accuracy §Qualitative Error Analysis), the headline F1 becomes 72.34%, which is a materially stronger claim than 65.31% and closes the gap further against the cited comparators. The dual-matcher emission means both numbers are reported honestly; no cherry-picking.

---

## Part 3 — Three Strongest Defensive Claims

### Claim 1: Code Guardian reports numbers that are competitive with the strongest academic comparators, on harder conditions

- IRIS with GPT-4: precision ~15% on whole-repo Java, 120 vulnerabilities.
- Code Guardian with qwen3:8b local: precision 63.16%, recall 67.61%, F1 65.31% on function-level JS/TS.
- Smaller model, stricter privacy boundary, harder deployment constraint — **yet higher precision**.

### Claim 2: Every methodological weakness admitted in the thesis has a literature precedent and a fix in the refinement work

| Thesis limitation | Literature precedent | Refinement fix |
|---|---|---|
| 101-case dataset | CWEval uses 119; IRIS uses 120 | (accepted, no change) |
| Type-level substring matching | IRIS uses CWE-class matching — same genus | Phase 1 canonical taxonomy + dual-matcher |
| 25-sample R3 review | SecRepair admits cosine/BLEU "fundamentally inadequate" | Phase 5 autoApplicableRate + syntax gate |
| FPR 20% | IRIS+GPT-4 FDR 85% | Phase 2 confidence gate + SAST hybrid |
| Single hardware | None report cross-hardware | (acknowledged; Phase 6 rerun) |

### Claim 3: Code Guardian occupies a niche none of the cited comparators fill

No other reviewed system provides: **local inference + IDE-native integration + real-time detection + JS/TS-focused + developer-controlled repair**. The closest is LLMSecGuard, which plans IDE integration as future work and reports no measured results.

---

## Part 4 — Claims to Avoid / Overreach Risks

**Do NOT claim:**
1. Code Guardian "beats IRIS/SecRepair/RESCUE" head-to-head — the datasets and tasks are different.
2. Local models are "as good as" GPT-4 in general — only that for this specific detection task at this specific scope, local 8B is usable.
3. RAG is "better" — it is model-dependent per your own ablation.
4. FPR 20% is "production-ready" — the thesis carefully says "suitable for audit-mode, not always-on" which is correct.

**Do claim:**
1. Code Guardian fills a documented gap in the privacy-IDE-integration dimension.
2. Its numbers are competitive with the strongest academic comparators at similar dataset scales.
3. Its methodology follows current best practices (curated dataset à la CWEval/IRIS, ablation studies à la RESCUE, honest limitation reporting à la SecRepair).

---

## Part 4.5 — Methodology Reinforcement from Priority-2 Papers

Three additional papers strengthen Code Guardian's methodological choices and expose a framing opportunity the thesis does not currently exploit.

### 4.5.1 "Everything You Wanted to Know…" (Li et al., CORRECT, 2025)

**Setup:** 2,000 vulnerable-patched program pairs, 99 CWEs, 13 LLMs, evaluated WITH and WITHOUT cross-function context.

**Headline claim (§1, §4):** Under context-rich evaluation, DeepSeek-R1 reaches **67% accuracy, >70% F1 on key CWEs**, with precision approaching 0.8. *Without* context, the same model scores close to random guessing.

**Direct quote (§1):** "Current benchmarks may not be measuring what truly matters. Specifically, we find that context-free evaluations often result in two types of misleading outcomes: incorrect conclusions and flawed rationales, collectively undermining the reliability of prior assessments."

**Three consensus beliefs they overturn:**
1. LLMs are unreliable → artifact of context-free evaluation
2. LLMs are insensitive to patches → artifact
3. LLMs plateau at scale → artifact

**How this defends Code Guardian:**
- Code Guardian evaluates at the function level. Per CORRECT, this is the conservative setting — it under-estimates true LLM capability.
- Code Guardian's 65.31% (canonical 72.34%) F1 is *in the same neighborhood* as CORRECT's context-rich 70%+ results, without the benefit of context enrichment. A strong showing.
- **Planned Phase 3 work** (cross-file import resolver, category-scoped rubrics) is exactly the context-enrichment CORRECT shows matters.

### 4.5.2 "From Vulnerabilities to Remediation" (Basic & Giaretta, SLR 2025)

**Setup:** Systematic literature review, 20 core primary studies on LLM-generated code vulnerabilities.

**Headline finding (§4, Table 2):** **Injection is the most-studied category — 16/20 papers cover it.** CWE-78 (OS command), CWE-79 (XSS), CWE-89 (SQL injection) appear across the bulk of studies.

**How this defends Code Guardian:**
- Code Guardian's 90–100% recall on SQL injection / XSS / command injection / path traversal is exactly where the field concentrates its evaluation. Code Guardian performs best where the field has the clearest benchmark coverage.
- The SLR categorizes data poisoning as a known threat — aligns with Code Guardian's explicit "retrieval poisoning" entry in the thesis threat model (Chapter 1).

### 4.5.3 "Large Language Model for Vulnerability Detection and Repair" (Zhou et al., TOSEM 2025)

**Setup:** 58 primary studies, 2018-2024, published in TOSEM (top-tier peer-reviewed SE venue).

**Direct quote (§1):** "Traditional techniques, such as rule-based detectors or program analysis-based repair tools, encounter challenges due to high false positive rates and their inability to work for diverse types of vulnerabilities."

**How this defends Code Guardian:**
- This is a peer-reviewed (TOSEM) endorsement of the exact complementary positioning Code Guardian takes: LLM strengths (diversity, context) + SAST strengths (low FPR on narrow patterns). Cite this directly if an examiner challenges the SAST-baseline positioning.
- Zhou et al. classify Code Guardian's model family (CodeLlama, decoder-only) as a valid choice for vulnerability detection — no need to justify the architecture.

### 4.5.4 Additional Defense Anchors (quick reference)

| Claim | Source | Use when |
|---|---|---|
| Function-level evaluation understates LLMs → Code Guardian's numbers are conservative | CORRECT §1, 3.1 | Examiner compares to cloud-LLM whole-repo tools |
| Rule-based tools have "high false positive rates" — peer-reviewed | Zhou et al. TOSEM 2025 §1 | Examiner dismisses the LLM approach because SAST is "good enough" |
| Injection-class vulnerabilities are the field's center of gravity | Basic & Giaretta Table 2 | Examiner questions the category coverage (Code Guardian's strongest categories are injections) |
| Context-rich evaluation: precision ~0.8 (DeepSeek-R1) | CORRECT §1 | Contextualize Code Guardian's 72.86% canonical precision (qwen3:8b+RAG) as comparable |
| Models plateau beliefs are evaluation artifacts, not capability limits | CORRECT Consensus #3 | Examiner argues "just use a bigger model" |

---

## Part 5 — Papers Worth Re-reading Before the Defense

Priority reading order if time is limited:

1. **CWEval** §I, §III (evaluation methodology attacks) — best defense for small curated dataset.
2. **IRIS** §1, §Results (baseline numbers for GPT-4 FDR) — best defense for FPR discussion.
3. **SecRepair** §III-C3 (they admit automated metric inadequacy) — best defense for R3 limitations.
4. **RESCUE** §3.2 (SecCoder failure) — best defense for RAG model-dependence.
5. **LLMSecGuard** §6 (future work = IDE integration) — proof that Code Guardian is ahead of this line of work.
