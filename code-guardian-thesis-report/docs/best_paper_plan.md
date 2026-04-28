# Best-Paper Refinement Plan

**Goal:** Elevate the thesis from "defensible at master's bar" to "no examiner concern survives". Close every Major (M) and Minor (m) item from the reviewer report, leave no metric without a measured value, and remove every reliance on tuning that touched the test set.

**Calendar.** Today: 2026-04-27. Defense: ≈ 2026-05-14. Working days available: ≈ 14.

**Compute budget.** ≈ 90 minutes of additional Ollama time across all phases. The full 7-hour 5-model evaluation is **not** rerun.

**Hard truth up front.** "Best paper without any issues" is contestable for a workshop or thesis-writing-contest standard. Top-tier conference (ICSE / ASE / FSE) would need a larger corpus, multi-language extension, or a cross-file context model — out of scope here and named as future work.

---

## Phase 0 — Hard Blockers (½ day, 30 s compute)

| # | Item | Source concern | Effort | Compute |
|---|---|---|---|---|
| A1 | Run `evaluation/privacy/prompt-injection-test.js --model qwen3:8b`; backfill `schemaValidRate` / `leakFreeRate` / `detectionSurvivesRate` | m7 | 5 min | 30 s |
| A2 | Manually verify every entry in `evaluation/realworld/nodegoat-vulnerabilities.json` against actual NodeGoat tutorial pages; correct any wrong file paths | M1 | 1 hr | — |
| A3 | Re-compute NodeGoat recall after A2 path corrections (no Ollama needed; recompute against existing findings JSON) | M1 | 30 min | — |

**Gate:** every numerical placeholder in the thesis is replaced by a measured value. **No defense scheduled until Phase 0 is green.**

---

## Phase 1 — Schema Tightening for Repairs (½ day, 10 min compute)

The 0 % auto-applicable rate is M2, the second most-attackable result in the thesis. The fix is a contract change.

| # | Action |
|---|---|
| B1 | Tighten the `suggestedFix` schema: change from `string` to `{code: string, language: 'javascript'\|'typescript'}` and update the system prompt to "Return only executable code in `code`; do NOT include explanations." |
| B2 | Update `MODEL_RESPONSE_SCHEMA` in [evaluate-models.js](../code-guardian-extension/evaluation/evaluate-models.js) and the extension's analyzer schema |
| B3 | Re-run 30-case sample on `qwen3:8b+RAG` with the new schema |
| B4 | Re-compute auto-applicable rate via `repair-validator.js` on the new sample |
| B5 | Update [eval_r3_repair.tex](../src/chapters/evaluation/eval_r3_repair.tex), [eval_summary.tex](../src/chapters/evaluation/eval_summary.tex), and [discussion.tex](../src/chapters/discussion.tex) with the new rate |

**Expected outcome.** A non-zero auto-applicable rate. If it stays at zero, the design conclusion shifts from "the schema needs tightening" to "the model cannot follow code-only instructions" — both are publishable, but the contract change must be attempted.

**Gate:** R3 has a measured outcome under a tightened contract; the answer to "what does the IDE quick-fix surface deliver?" stops being "0 %".

---

## Phase 2 — Parity Reruns (1 day, ≈ 70 min compute)

Close the configuration parity gap on the external corpus and NodeGoat, and finish the resource sample at the headline configuration.

| # | Action | Compute |
|---|---|---|
| C1 | Expand canonical taxonomy in [src/categoryTaxonomy.json](../code-guardian-extension/src/categoryTaxonomy.json) with `session-fixation`, `vulnerable-dependency`, `weak-validation`, `information-exposure` (the four classes that collapse into `other` on NodeGoat) | — |
| C2 | Re-run NodeGoat under headline configuration: `qwen3:8b+RAG`, 3 runs, confidence gate ≥ 0.67, expanded taxonomy. Use a `--rerun-with-rag` flag on `run-realworld.js` | ≈ 30 min |
| C3 | Re-run external 15-case corpus under headline configuration | ≈ 25 min |
| C4 | Re-run 30-case resource sample under `qwen3:8b+RAG` | ≈ 12 min |
| C5 | Update [eval_r1_realworld](../src/chapters/evaluation/eval_r1_accuracy.tex#sec:eval-r1-realworld), [eval_r1_external_corpus](../src/chapters/evaluation/eval_r1_accuracy.tex#sec:eval-r1-external-corpus), and [eval_r4_resources](../src/chapters/evaluation/eval_r4_usability.tex#sec:eval-r4-resources) with the new headline-config numbers |

**Gate:** every measurement uses the same headline configuration the thesis claims as the recommended default. M3 closed; M1 quantitatively addressed by the taxonomy expansion + headline rerun.

---

## Phase 3 — Statistical Hardening (1 day, no compute)

Address M5 and M6 in one pass: held-out validation of the confidence threshold and Bonferroni-corrected significance for every claim.

| # | Action |
|---|---|
| D1 | Pre-register a 70/30 split of the curated 101 corpus by writing a deterministic split script and timestamping it in git **before** running anything. Store the split as `evaluation/datasets/split-2026-04-28.json` |
| D2 | Re-tune the confidence threshold on the dev split only (30 cases); re-evaluate on the 71-case test split |
| D3 | Add a new subsection in [eval_r1_accuracy.tex](../src/chapters/evaluation/eval_r1_accuracy.tex): "Held-Out Threshold Validation" reporting both dev and test numbers |
| D4 | Apply Bonferroni correction across all RAG-vs-no-RAG claims (one McNemar per model × mode = 5 tests, $\alpha = 0.05/5 = 0.01$). Update the Statistical Power paragraph. Soften every "RAG helps X" claim that does not survive correction |
| D5 | Add a "Statistical Validity" paragraph to [evaluation_metrics.tex](../src/chapters/evaluation/evaluation_metrics.tex) describing the corrected significance level and which claims survive |

**Gate:** no claim depends on tuning that touched the test set; significance language is calibrated to corrected p-values.

---

## Phase 4 — Cross-Hardware Reproducibility (½ day, 5 min compute)

Address M7. Borrow any non-Apple-Silicon machine for one short test.

| # | Action |
|---|---|
| E1 | Provision a second host: a Linux x86 box (lab machine, peer's laptop), an EC2 t3.xlarge, or a Docker container on Windows. Pull `qwen3:8b` |
| E2 | Run `reproducibility.js --cases 5 --runs 3 --model qwen3:8b` on the second host |
| E3 | Add a "Cross-Hardware" paragraph + table row to [eval_reproducibility.tex](../src/chapters/evaluation/eval_reproducibility.tex) reporting the second host's `byteIdentityRate` / `setIdentityRate` |

**Expected outcome.** byteIdentityRate is likely < 100 % on a different platform (this is normal for LLM inference on heterogeneous hardware); setIdentityRate is likely still 100 % — the more meaningful metric.

**Gate:** the reproducibility claim is no longer Apple-Metal-specific.

---

## Phase 5 — User-Facing Validation for R4 (1–2 days, 0 compute)

Address M8. R4 currently rests on HCI latency thresholds; one structured walkthrough is enough to elevate it from "inferred" to "measured".

| # | Action |
|---|---|
| F1 | Recruit 3–5 developers (peers, classmates, your DM-able network). 30 min each, remote screen-share or in-person |
| F2 | Standardised script with three tasks: (1) accept inline diagnostic on a known SQLi case, (2) review and apply a quick-fix repair, (3) run a workspace scan and interpret the dashboard |
| F3 | Capture: think-aloud transcripts, time-on-task, 5-point Likert ratings on perceived helpfulness / latency / trust, free-text feedback |
| F4 | Add a "R4 Walkthrough Study" subsection to [eval_r4_usability.tex](../src/chapters/evaluation/eval_r4_usability.tex). $n = 3$–$5$ is honest and acceptable for a master's thesis when framed as a "structured walkthrough", not a "user study" |
| F5 | Add raw quotes (anonymised) to a new appendix |

**Gate:** R4 has at least one piece of human-derived evidence; the "no user study" criticism downgrades from a major to a minor concern.

---

## Phase 6 — Methodology Polishing (½ day, 0 compute)

Address m4 (single-rater R3) and m2 (taxonomy authored by author).

| # | Action |
|---|---|
| G1 | Expand R3 manual review from 25 to 50 samples |
| G2 | If a second rater is available: compute Cohen's $\kappa$ or Krippendorff's $\alpha$. If not: explicitly state "single-rater review with 50 samples" and report agreement against the auto-applicable signal as a triangulation proxy |
| G3 | Have one external colleague (any technical reviewer) audit the 23 canonical-taxonomy classes. Record any vetoes or alternative groupings as supplementary notes |
| G4 | Add a "Curator Bias and Review" paragraph to the Limitations section of [discussion.tex](../src/chapters/discussion.tex) acknowledging held-out validation (Phase 3) and external taxonomy review (G3) |

**Gate:** curator bias is acknowledged with at least two mitigations; R3 review is double-sized.

---

## Phase 7 — Discussion Chapter Strengthening (1 day, 0 compute)

Address F3 (lean Discussion) and synthesise across requirements.

| # | Action |
|---|---|
| H1 | Add a "Cross-Requirement Synthesis" subsection (~1 page): how R1 results, R3 limitations, and R4 latency interact in practice. Use the deployment-profile table from the conclusion as the spine |
| H2 | Add a "When Code Guardian Is And Isn't Useful" paragraph: situations where the function-scope detector adds value (single-file, well-defined sinks) and situations where it does not (cross-file, framework patterns, authorisation flows) |
| H3 | Soften the conclusion's deployment-profile language: replace "Recommended default" with "indicated by measurement for this hardware profile" |
| H4 | Add a "Comparison to Commercial SAST" paragraph in Limitations: why Snyk Code, Veracode, Fortify were not benchmarked (cost, licensing, scope) |
| H5 | Add a "Threats to Validity" subsection consolidating: curator bias (G4), single hardware (E3), small statistical power (D4), single-rater R3 (G1), no user study covered by walkthrough (F1) |
| H6 | Update the Prompt-Injection Resistance paragraph in [eval_r5_privacy.tex](../src/chapters/evaluation/eval_r5_privacy.tex) with the real measured rates from A2 |

**Gate:** Discussion is the strongest, not the leanest, chapter — every counterargument has a paragraph.

---

## Phase 8 — Reorganisation & Artefact Release (½ day, 0 compute)

Polish presentation and prepare reproducibility assets.

| # | Action |
|---|---|
| I1 | Move the R5 5-criterion verification table to Appendix D; promote the egress-harness PASS result to the headline R5 result (m3, m8) |
| I2 | Move R3 manual review samples (n = 50 after G1) to an appendix |
| I3 | Move dataset-detail tables to Appendix B; main eval chapter retains only the headline tables |
| I4 | Tag the repo: `git tag thesis-final-v1.0` and push |
| I5 | Archive a snapshot to Zenodo (free, gives a DOI). Cite the DOI in the thesis under "Artefact Availability" |
| I6 | Sign the released corpus tarball with the existing Phase A2 keypair; publish the public key in the thesis appendix |
| I7 | Verify all `evaluation/logs/*.json` are committed (or archived) and reachable from a single root README |

**Gate:** the artefact is citable, signed, and reproducible from a single command (`docker compose run evaluator`).

---

## Phase 9 — Defense Prep (2–3 days, 0 compute)

| # | Action |
|---|---|
| J1 | Final poster — A0 portrait, follows TUC defense template (one figure per requirement, headline numbers boxed, repository QR code) |
| J2 | Defense slides — ~30 slides, 5 sections (Motivation, Concept, Implementation, Evaluation, Closing), 2 backup slides per slide for examiner pushback |
| J3 | Self-test against the **5 hardest defense questions** (drawn from the reviewer report's M-section): NodeGoat 0/10, auto-applicable 0 %, external corpus parity, curator bias, statistical power. Have a 2-minute crisp answer per item |
| J4 | Mock defense with peers — at least one round with the strongest critic available |
| J5 | USB drive package: thesis PDF + signed corpus tarball + `evaluation/logs/` + `Dockerfile` + a single README with `docker compose run evaluator` instructions |
| J6 | One-page summary handout for the committee |

**Gate:** live presentation feels rehearsed; every M-level concern has a 2-minute canned answer.

---

## Definition of Done (DoD)

A change is "best-paper-ready" when:

1. The Major Concerns section of the reviewer report has zero unresolved items
2. The Minor Concerns section has at most two acknowledged-but-deferred items, both named as future work
3. Every metric named in the task description has a measured value reported in the headline configuration (no placeholders, no LLM-only fallbacks for headline numbers)
4. No claim depends on tuning that touched the test set
5. The Discussion chapter explicitly answers the top five examiner attack questions
6. The defense rehearsal hits every question without hesitation

---

## Risk Matrix

| Risk | Probability | Impact | Mitigation |
|---|---|---|---|
| Phase 1 schema fix does not lift auto-applicable rate above zero | Medium | High | Frame as "contract change attempted; result reported"; the design lesson is publishable either way |
| Cross-hardware repro test produces low byte-identity | Medium | Low | Expected and honest; setIdentityRate is the headline. This actually strengthens the thesis if reported correctly |
| Phase 5 walkthrough yields lukewarm feedback | Low | Medium | Verbatim transcripts in appendix; inject criticism into the Discussion's Limitations |
| Phase 2 reruns reveal worse numbers than current placeholders | Medium | High | Honestly report; a worse measured number is still better than an unmeasured one |
| 7-hour full rerun becomes necessary | Low | High | Phases 1–4 use small targeted runs only; if numbers diverge alarmingly, full rerun is a 1-day add not a 7-day add |

---

## Budget Summary

| Phase | Engineering | Compute | Critical |
|---|---|---|---|
| 0 — Hard Blockers | 0.5 day | 30 s | **Yes** |
| 1 — Schema Tightening | 0.5 day | 10 min | **Yes** |
| 2 — Parity Reruns | 1 day | 70 min | **Yes** |
| 3 — Statistical Hardening | 1 day | — | **Yes** |
| 4 — Cross-Hardware Repro | 0.5 day | 5 min | High value, low cost |
| 5 — Walkthrough Study | 1–2 days | — | High value |
| 6 — Methodology Polish | 0.5 day | — | High value |
| 7 — Discussion Strengthening | 1 day | — | **Yes** |
| 8 — Artefact Release | 0.5 day | — | Strongly recommended |
| 9 — Defense Prep | 2–3 days | — | **Yes** |
| **Total** | **≈ 8–11 days** | **≈ 85 min** | |

Comfortably fits the 14-day window with one buffer day.

---

## Compression Strategy (if the calendar slips)

If you find yourself with **fewer than 7 days** to defense:

**Drop:**
- Phase 5 (walkthrough study) — defer to future work; explicitly limit R4 to latency
- Phase 4 (cross-hardware) — explicitly limit reproducibility claim to the locked profile in [eval_reproducibility.tex](../src/chapters/evaluation/eval_reproducibility.tex)
- Phase 6 (taxonomy external review) — explicitly disclose curator-only authorship in Limitations

**Keep (non-negotiable):**
- Phase 0 (prompt-injection real numbers, NodeGoat path verification)
- Phase 1 (auto-applicable schema fix)
- Phase 2 (parity reruns)
- Phase 7 (discussion expansion)
- Phase 9 (defense prep)

---

## Why This Is Realistic But Not Ambitious-Beyond-Master's

What this plan does **not** attempt:
- A larger corpus (>500 cases) — would need a 7-hour rerun
- Multi-language support beyond JS/TS — out of scope per [task_description.tex](../src/task_description.tex)
- Cross-file context modelling — explicitly named as future work
- Fine-tuning a model on security data — design choice ruled out in concept chapter
- A full controlled user study with $n \geq 20$ — out of scope for a master's thesis

What it does deliver:
- Every M-level concern from the reviewer report addressed
- Every metric the task description names measured under the headline configuration
- Held-out validation of the only tuned threshold
- Cross-hardware reproducibility evidence
- Real human feedback from $n \geq 3$ developers
- Citable, signed, reproducible artefact

This is the threshold for "publishable in a workshop" or "best master's thesis at the chair this year". Beyond that requires a fundamentally different scope.

---

## Schedule (suggested, working backwards from defense)

| Day | Date | Work |
|---|---|---|
| D-14 | 2026-04-30 | Phase 0 + Phase 1 |
| D-13 | 2026-05-01 | Phase 2 |
| D-12 | 2026-05-02 | Phase 3 |
| D-11 | 2026-05-03 | Phase 4 + Phase 5 (recruit) |
| D-10 | 2026-05-04 | Phase 5 (sessions) |
| D-9 | 2026-05-05 | Phase 5 (writeup) + Phase 6 |
| D-8 | 2026-05-06 | Phase 7 |
| D-7 | 2026-05-07 | Phase 8 |
| D-6 | 2026-05-08 | Buffer / catch-up |
| D-5 | 2026-05-09 | Phase 9 (slides) |
| D-4 | 2026-05-10 | Phase 9 (poster + USB) |
| D-3 | 2026-05-11 | Phase 9 (mock defense) |
| D-2 | 2026-05-12 | Final compile + print |
| D-1 | 2026-05-13 | Buffer |
| D 0 | 2026-05-14 | Defense |

---

*Plan generated 2026-04-27. Update by editing this file directly; track changes in git.*
