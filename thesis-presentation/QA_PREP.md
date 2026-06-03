# Q&A Attack-Prep — Code Guardian Defense

**Use:** rehearse 1–2 days before the defense. For each attack, the answer is structured:
1. **Frame** — one line that reframes the question into terms favourable to you.
2. **Anchor** — one specific number / source the examiner cannot wave away.
3. **Concede** — the smallest legitimate concession.
4. **Route** — which appendix slide you land on if pressed.

If you only memorise one thing per question, memorise the **anchor**. Everything else is supporting prose.

---

## CATEGORY A — DATASET & SELECTION BIAS

### A.1 — "Why only 101 cases? That's too small."

**Frame:** "Curated corpora are the field norm, not a workaround."

**Anchor:** CWEval (Peng et al., 2025) uses **119 curated tasks** across 31 CWEs in 5 languages — peer-comparable to my 101. Peng et al. further report that **only 562 / 1916 = 29.3 % of CyberSecEval vulnerable samples are reproducible** — i.e., larger auto-mined benchmarks are mostly noise.

**Concede:** Statistical power on rare-CWE sub-categories is bounded. I report exact-binomial CIs for that reason, not Gaussian.

**Route:** Appendix A4 — "Why a Curated Corpus."

---

### A.2 — "You curated the corpus yourself — that's selection bias."

**Frame:** "I addressed selection bias four ways, each independently verifiable."

**Anchor:** Four mitigations baked in: (1) **held-out 71 / 30 test split** with frozen TEST set keeps threshold tuning out of headline numbers, (2) **15-case external corpus** from OWASP NodeGoat, Juice Shop, and three named CVEs — independent of the curator, (3) **whole-project NodeGoat run** gives a project-level recall figure not bounded by sample selection, (4) **provenance bound into the Ed25519-signed manifest** — corpus cannot be silently rewritten.

**Concede:** A second, independent corpus selected by another researcher would be the next step.

**Route:** Appendix A4.

---

### A.3 — "Why not use Juliet / OWASP Benchmark / SecurityEval?"

**Frame:** "There is no JS/TS corpus that fits the threat model."

**Anchor:** Juliet is **C / C++ / Java only**. OWASP Benchmark is **Java only**. SecurityEval (Pearce 2022) is **small and partially synthetic with CWE labels that don't map cleanly to OWASP Top 10**. CWEval (2025) is the closest peer at 119 tasks — comparable scale to mine.

**Concede:** A future JS port of Juliet would be valuable infrastructure work for the field.

**Route:** Appendix A4 — left column.

---

### A.4 — "Why JS/TS specifically?"

**Frame:** "JS/TS is where the privacy gap is loudest and the SAST coverage is thinnest."

**Anchor:** JS/TS is the most-used language stack on GitHub (Octoverse 2024); injection vulnerabilities dominate field benchmarks — Basic & Giaretta 2025 report **16 / 20 reviewed studies cover injection**, which is where Code Guardian reaches **90–100 % recall** (SQL injection, XSS, command injection, path traversal). I evaluate where the field's benchmark signal is strongest.

**Concede:** Generalization to compiled / statically-typed languages requires re-validation.

---

### A.5 — "Where exactly did the dataset come from, and are you allowed to use it?"

**Frame:** "Every case traces to an authoritative public source, and the licensing is clean end-to-end."

**Anchor:** Provenance is documented per-case in `SOURCES.md` and bound into the **Ed25519-signed manifest**. Sources and their licences: **OWASP NodeGoat & Juice Shop → MIT**; **3 named CVEs (CVE-2022-24999, CVE-2021-23337, CVE-2022-24771) → public NIST NVD disclosures**; **OWASP Top 10 / cheat sheets → CC-BY-SA 4.0**; **CWE (MITRE) and NVD → public domain**; **curated synthetic cases → my own work, MIT**. Composition: 11 real-project snippets, ~25 OWASP-pattern cases, ~35 CWE-tagged synthetic, 30 hand-picked secure negatives — plus a 15-case external corpus, each with an upstream URL and commit/version.

**Concede:** The external public sources are almost certainly in the models' pre-training data, so I read those numbers as case studies, not population estimates — the curated split carries the headline claims.

**Route:** Appendix A4 — "Why a Curated Corpus."

---

### A.6 — "You built the 26-category taxonomy AND the ground-truth labels — a generous label-matcher inflates your own recall."

**Frame:** "The taxonomy is a deterministic, published, frozen artefact — not a per-result judgement call I make during scoring."

**Anchor:** The canonical mapping lives in `src/categoryTaxonomy.json` as **26 ordered regex rules**, pinned by a **snapshot test** (`category-taxonomy.snapshot.test.js`) so it cannot drift between runs. Ground-truth labels are **not mine to invent** — each case carries a CWE/OWASP identifier traceable in `SOURCES.md`. Crucially, **every run emits per-canonical-category counts**, so an external reviewer can re-bucket the raw findings under a *different* taxonomy and re-score without consulting me. The mapping was frozen before the evaluation, alongside the held-out 71/30 split — there is no degree of freedom left at scoring time to tune recall.

**Concede:** A second, independent labeler applying the CWE tags would remove the last bit of single-author subjectivity — that's named as future work.

**Route:** Appendix A1/A2 — per-category counts; Appendix A4 — corpus provenance.

---

## CATEGORY B — DETECTION ACCURACY (R1)

### B.1 — "20 % FPR is too high for production deployment."

**Frame:** "10 % FPR is competitive with strong work, and the confidence gate halves it."

**Anchor:** My headline is **FPR = 10.0 %** at F1 = 71.43 % (ungated). With the inter-run confidence gate ≥ 0.67 the rate stays at 10 % while precision rises to 78.13 %. For comparison, **IRIS + GPT-4 (Li et al., ICLR 2025) reports false discovery rate = 84.82 %** on whole-repo Java — i.e., precision ~15 %. My 78.13 % precision under the gate is in a different league for the constraint set.

**Concede:** On the held-out test split the configuration shows FPR = 0 % but at lower recall — there's a precision/recall trade I expose, not hide.

**Route:** Slide 15.

---

### B.2 — "F1 = 71 % isn't impressive — GPT-4 hits >90 % on similar tasks."

**Frame:** "GPT-4 hits 90 % cloud-side. My constraint set is local-only, zero-egress, and on consumer hardware."

**Anchor:** CORRECT (Li et al., 2025) shows context-rich LLM eval reaches **F1 > 70 %, precision ~80 %** even with cross-function context — and that **function-level evaluation under-estimates LLM capability**. My 71.43 % F1 / 72.46 % precision is function-level, no cloud, on an 8B-q4 model — that's a strong showing under handicap. Frontier cloud models always win raw F1; the thesis competes on the constraint set.

**Concede:** A published-numbers comparison to GPT-4 on similar JS corpora would be a one-paragraph post-defense addendum.

**Route:** Appendix A5 — "Why No Cloud-LLM Baseline."

---

### B.3 — "Your confidence gate is just inflated precision."

**Frame:** "It's a precision/recall trade made *visible*, not hidden."

**Anchor:** Gate at ≥ 0.67 (≥ 2-of-3 agreement): **F1 71.43 → 74.07 %**, **precision 72.46 → 78.13 %**, **recall 70.42 → 70.42 % (unchanged)**. The gate suppresses seed-dependent noise that appears in 1-of-3 runs without rejecting any consensus signal. Both gated and ungated numbers are reported in the thesis — readers pick the bar.

**Concede:** The gate is correlated with the consensus filter — under deterministic decoding they collapse. Real consensus signal requires seed rotation (acknowledged as future work).

**Route:** Appendix A6 — "Why R2 Reports 100 % Inter-Run Agreement."

---

### B.4 — "Why is qwen3:8b your headline and not a bigger model?"

**Frame:** "8B-q4 is the largest model that fits the consumer-laptop privacy envelope."

**Anchor:** qwen3:8b-q4 runs in ~6 GB VRAM — fits a 16 GB Apple Silicon laptop alongside VS Code, Ollama, and the developer's normal workload. A 70B model would require 40+ GB; that moves the threat model from "developer laptop" to "developer workstation," shrinking the deployable population. The on-demand latency budget (≤ 5 s) is also bounded by 8B-class inference.

**Concede:** A 70B local-server deployment is a deployment topology I don't evaluate — would interest air-gapped enterprise users.

---

## CATEGORY C — RAG & RQ2

### C.1 — "Your RAG sometimes makes things worse — isn't that a flawed design?"

**Frame:** "Model-dependence is the documented field finding, not a Code Guardian artefact."

**Anchor:** **RESCUE (Shi & Zhang, 2025)** reports that conventional RAG "does not significantly improve SecurePass@1 or SecureRate." **He et al. 2024**, cited by RESCUE, shows CWE descriptions alone do NOT improve secure code generation. My data: qwen3:8b + RAG gains **+3.91 F1**; codellama + RAG loses **−29.89 F1**. The codellama effect is the only one that survives Bonferroni at α = 0.01 (**McNemar p = 0.0013**). Treating RAG as a per-model design choice — not a default — is the disciplined finding.

**Concede:** Adaptive per-model RAG gating driven by this finding is in future work.

**Route:** Slide 16.

---

### C.2 — "Why didn't you fine-tune the model on the RAG corpus instead?"

**Frame:** "Fine-tuning crosses the privacy envelope at training time."

**Anchor:** Fine-tuning requires either centralized training data (privacy-incompatible with the threat model) or per-customer local fine-tuning (operationally infeasible for a VS Code extension). Retrieval is a runtime pattern that keeps both training and inference local. The thesis's scope is **system orchestration + prompt engineering, not model training** — fixed in Chapter 1.

**Concede:** Per-deployment LoRA fine-tuning on a developer's private codebase is a logical extension if the privacy contract is updated.

---

### C.3 — "What's in your RAG store?"

**Frame:** "CWE patterns, OWASP-top-ten exemplars, and curated real-world fix patches — all signed."

**Anchor:** ~N entries across 14 CWE categories, embedded via Ollama, stored in HNSWlib (vector store), retrieved top-k at inference. Corpus is **Ed25519-signed** so the manifest cannot be silently mutated. *(Fill in N from the actual rag store size in src/ragManager.ts at defense time.)*

**Concede:** Per-organization custom RAG additions are a UX I haven't built — that's where most enterprise value would come from.

---

## CATEGORY D — REPAIR (R3)

### D.1 — "Single reviewer, n = 25 — that's not a real evaluation."

**Frame:** "Manual review is the qualitative complement. Headline R3 is the fully automated auto-applicable rate."

**Anchor:** Headline R3 = **90.32 % auto-applicable (252 / 279, n = 279)**, **fully objective, validator-driven**, no human in the loop. Manual review on n = 25 is the *secondary* metric — semantic correctness 89.5 %, combined correctness 68 %. **SecRepair (Islam et al., NDSS 2024) §III-C3 explicitly admits** that automated metrics for repair quality are "fundamentally inadequate" — i.e., the field has no consensus metric. My auto-applicable rate is a step forward against that critique.

**Concede:** Inter-rater agreement on the 25-sample subset is the obvious next step — explicitly listed in future work.

**Route:** Appendix A3 — "Why the Single-Reviewer Manual Review Is Bounded."

---

### D.2 — "How do you know the repairs are actually secure?"

**Frame:** "Two-stage validator + Quick-Fix gate keeps developer judgment in the loop."

**Anchor:** Repair is **opt-in**: every applied patch is developer-confirmed via VS Code's Quick Fix UI — there are no silent rewrites. The validator parses output with @babel/parser (rejects prose, rejects malformed JS). The semantic correctness of 89.5 % is *under manual review* by someone who knows the CWE. A misclassified fix at most reaches the developer's screen with full context; it doesn't auto-commit.

**Concede:** Adversarial fix-quality testing (does the "fix" introduce a *different* vulnerability) is not in scope.

---

### D.3 — "Your repair rate looks too high. What's the catch?"

**Frame:** "Auto-applicable measures parseability, not security. I report both bars."

**Anchor:** **Auto-applicable 90.32 %** = "output parses as valid JS/TS" — a syntactic bar. **Semantic correctness 89.5 %** (manual, n = 25) = "fix actually addresses the CWE." **Combined correctness 68 %** (manual) = fix-rate (76 %) × semantic correctness (89.5 %) per the R3 level mapping (Section 5.6.3). The sub-metrics are: strategy-aligned 94.7 %, directly executable 42.1 % — the low executability is why the *headline* repair number is the parse-level auto-applicable rate, not the executable rate. The two-tier report is deliberate — a reader picks the bar that matches their workflow. The auto-applicable figure was 0 % in an earlier validator pass before the @babel/parser config was fixed — that history is documented in evaluation.tex.

**Concede:** A third metric — "does the fix break existing tests" — is the right next instrument, requires test infrastructure I don't have for the curated corpus.

---

## CATEGORY E — USABILITY & LATENCY (R4)

### E.1 — "2.2 s is too slow to be interactive."

**Frame:** "2.2 s is the on-demand band — that's where I claimed it would land."

**Anchor:** I commit to **three latency bands in Chapter 2** before evaluation: real-time ≤ 500 ms (SAST only), interactive ≤ 1.5 s, on-demand ≤ 5 s. qwen3:8b + RAG at 2,216 ms is **comfortably inside on-demand**. For interactive workflows, **gemma3:1b + RAG (1,019 ms)** and **qwen3:4b (1,328 ms)** qualify — I show users have a choice. Real-time is a deliberate design out-of-scope.

**Concede:** Streaming partial results to break the real-time band is in future work.

**Route:** Slide 18.

---

### E.2 — "How does this work on Windows / Linux / Apple Silicon?"

**Frame:** "All Ollama-supported platforms; tested primarily on Apple Silicon."

**Anchor:** Ollama supports macOS, Linux, Windows. Headline numbers were measured on an Apple Silicon M-series with 16 GB unified memory. Container is **Node 20.19.0-alpine** for the reproducibility harness — runs identically on any Docker-capable host.

**Concede:** Per-platform latency calibration (cuda vs metal vs cpu) is not in the thesis.

---

## CATEGORY F — PRIVACY (R5)

### F.1 — "100 % leakFreeRate sounds suspiciously perfect."

**Frame:** "It's measured on a finite harness — and I'm explicit about the harness's scope."

**Anchor:** leakFreeRate = 100 % (12/12) on **12 hand-crafted prompt-injection cases** that *attempt* to exfiltrate via the model. Be ready for the stricter reading the thesis itself reports: **strict leakFreeRate = 83.3 % (10/12)**, where two pure-injection cases returned *empty* responses rather than a verified refusal — the 100 % headline means no observed leak, not a proof. The figure is empirical, not a security proof. Network-level verification is separate — I report **zero non-loopback transmission across the full 303-invocation corpus run**, observed via host firewall logs. The corpus signature (Ed25519) is a third independent privacy arm.

**Concede:** A red-team-grade audit (rather than my 12 cases) would be a larger evaluation. I deliberately frame the figure as harness-bounded.

---

### F.2 — "Couldn't the model still leak via the RAG retrieval?"

**Frame:** "RAG is read-only from a signed local store — no inbound channel."

**Anchor:** RAG entries are pre-built, signed with Ed25519, loaded at extension activation. Retrieval is read-only and local — it never makes a network call at inference time. The vulnerability data refresh fetches **public NVD/OWASP/CWE metadata only**, on a 24h cache, and never includes user code. The threat model in Chapter 4 enumerates the channels and I verify each.

**Concede:** A compromised RAG manifest (signed by an attacker who's already on the developer's machine) is out of scope — that's an endpoint-compromise threat model.

---

### F.3 — "How do you verify privacy actually holds at runtime?"

**Frame:** "Three independent arms: loopback bind, network observation, signed corpus."

**Anchor:** (1) Ollama bound to **127.0.0.1** at extension activation (verifiable in process listing). (2) Host-level network observation confirms **zero non-loopback packets** during the corpus run. (3) RAG corpus manifest signature verified at load (Ed25519). Three independent arms means a single failure doesn't silently break the contract.

---

## CATEGORY G — METHODOLOGY & STATISTICAL DISCIPLINE

### G.1 — "Bonferroni is conservative — are you over-correcting?"

**Frame:** "I report both raw McNemar p-values and Bonferroni-corrected ones. Readers decide."

**Anchor:** Across all paired RAG comparisons, **only codellama's −29.89 F1 effect survives Bonferroni at α = 0.01** (McNemar p = 0.0013, family-adjusted). The other 4 effects don't — and I say so explicitly. Bonferroni is *deliberately* conservative because the field is awash in cherry-picked single-pair comparisons.

**Concede:** Holm-Bonferroni or BH-FDR are less conservative alternatives — would be worth reporting as supplementary.

---

### G.2 — "Three runs is too few for any statistical claim."

**Frame:** "Three runs at temperature = 0, seed = 42 are byte-identical — they're not a Monte Carlo."

**Anchor:** Under deterministic decoding the three runs are intentionally identical — the consensus filter is an *inter-call-agreement* check, not stochastic averaging. Real Monte Carlo with seed rotation is **future work**, acknowledged in the thesis and in slide 22. My statistical claims (McNemar, exact-binomial) are at the case level (n = 101), not the run level.

**Concede:** I would expect more variance under seed rotation, especially on near-decision-boundary cases.

**Route:** Appendix A6.

---

### G.3 — "How did you pick the four-level threshold scales for R1–R5?"

**Frame:** "Fixed in Chapter 2 before evaluation, not after."

**Anchor:** Each R has a four-level acceptance scale (unacceptable / weak / acceptable / strong) tied to a specific metric, **set in Chapter 2 before any model was evaluated**. This is the thesis's commitment device — I can't move the goalposts mid-evaluation. The chapter cites prior work for the thresholds where available (e.g., latency bands draw on Nielsen 1993).

**Concede:** Thresholds are still author-set — independent calibration is future work.

---

## CATEGORY H — RELATED WORK

### H.1 — "Why didn't you compare against LLMSecGuard?"

**Frame:** "LLMSecGuard is a concept paper. My system is what they listed as future work."

**Anchor:** **LLMSecGuard (Kavian et al., EASE 2024)** is a 4-page framework paper with **no measured performance numbers**. Section 6 future work: "integrate LLMSecGuard into at least one popular IDE." Code Guardian has *delivered* what they propose: IDE-native, measured, reproducible.

---

### H.2 — "IRIS uses GPT-4 and gets better numbers."

**Frame:** "Different scale, different language, different threat model."

**Anchor:** **IRIS (Li et al., ICLR 2025)** evaluates on **whole-repo Java**, ~300K LOC average, **cloud GPT-4**. Reported **false discovery rate 84.82 %** — precision ~15 %. Code Guardian: function-level JS/TS, local 8B, **precision 72.46 % (78.13 % gated)**. Mine is a smaller scale by design (deployable on a laptop, not a server farm). The two systems answer different questions.

---

### H.3 — "Where does Code Guardian sit in the SAST + LLM literature?"

**Frame:** "On the complementarity track the recent SLR endorses."

**Anchor:** **Zhou et al. TOSEM 2025**: "traditional techniques, such as rule-based detectors or program analysis-based repair tools, encounter challenges due to high false positive rates and their inability to work for diverse types of vulnerabilities." A peer-reviewed SLR explicitly motivates the LLM + SAST complementary pattern — exactly what Code Guardian implements (the SAST baselines act as a deterministic floor; the LLM extends coverage).

---

## CATEGORY I — DEPLOYMENT & REAL-WORLD VALIDITY

### I.1 — "Only one real-world project (NodeGoat) — that's anecdotal."

**Frame:** "NodeGoat is the deliberate, curated end-to-end check — not the headline."

**Anchor:** Headline numbers come from the 101-case curated corpus + 15-case external set across NodeGoat, Juice Shop, and 3 CVEs. NodeGoat whole-project is the *integration test* — it proves the system works at project scale, not just per-file. Multi-project validation is explicitly future work (slide 22).

**Concede:** Diversity across project styles (React, Node, Express, NestJS) would shore up generalisation claims.

---

### I.2 — "Have developers actually used this?"

**Frame:** "Published to the VS Code Marketplace — usage analytics are out of scope by privacy contract."

**Anchor:** The extension is on the Marketplace with N installs *(check Marketplace stats at defense time)*. By design Code Guardian collects **zero telemetry** — there's no usage data because there's no exfiltration. Developer-study evaluation is future work; it requires a different IRB-equivalent setup.

**Concede:** Without telemetry the qualitative usage signal is anecdotal — I rely on Marketplace install counts and issue tracker activity.

---

## CATEGORY J — CONCEPTUAL / NOVELTY

### J.1 — "What's actually novel here?"

**Frame:** "The niche is unambiguously unoccupied."

**Anchor:** No reviewed system provides **all of**: local inference + IDE-native + real-time/on-demand latency + JS/TS + detection AND repair. Closest comparators each miss something: **IRIS** (batch, whole-repo, cloud GPT-4) · **RESCUE** (code generation task, batch) · **SecRepair** (batch fine-tuning, C/C++) · **LLMSecGuard** (concept paper, no IDE). Code Guardian is at the intersection.

---

### J.2 — "Why isn't this just a wrapper around Ollama?"

**Frame:** "Ollama is one of four subsystems. The thesis is the integration + the evaluation."

**Anchor:** The thesis contributes: (1) two-stage pipeline with **structured JSON contracts at every boundary**, (2) **RAG knowledge base with signed manifest**, (3) **vulnerability data integration** (NVD/OWASP/CWE), (4) **deterministic harness** (seed = 42, byte-identical runs), (5) **canonical-taxonomy matcher** (`src/categoryTaxonomy.json` maps model-emitted labels to a 26-class canonical bucket), (6) **empirical 303-invocation-per-config study** with statistical discipline. Ollama is the model runtime; everything else is the system.

---

## Quick reference card  ·  print and tape to the inside of your binder

| Anchor stat                  | Use when…                                                        |
|------------------------------|------------------------------------------------------------------|
| **71.43 % F1**               | Asked about detection accuracy                                   |
| **78.13 % precision (gated)**| Asked about FPR / false alarms                                   |
| **90.32 % auto-applicable**  | Asked about repair quality                                       |
| **2,216 ms median**          | Asked about latency / interactivity                              |
| **100 % leakFreeRate**       | Asked about privacy guarantee                                    |
| **−29.89 F1 (codellama RAG)**| Asked "is RAG always good"                                       |
| **84.82 % FDR (IRIS)**       | Asked "20 % FPR too high"                                        |
| **29.3 % CyberSecEval repr.**| Asked "101 is too small"                                         |
| **CWEval = 119 tasks**       | Asked "your dataset is small"                                    |
| **SecRepair §III-C3**        | Asked "single reviewer, n = 25 is weak"                          |
| **RESCUE 2025**              | Asked "your RAG hurts quality"                                   |
| **Zhou et al. TOSEM 2025**   | Asked "isn't SAST enough"                                        |
| **Ed25519-signed manifest**  | Asked "how is RAG provenance verified"                           |
| **McNemar p = 0.0013**       | Asked "statistical significance of codellama RAG drop"           |

## Two-minute Q&A budget

In a 2-minute window you can answer **2–3 questions max**. If pressed for time:
- Always restate the question briefly in your reframe (buys you 5 seconds and confirms understanding).
- Always end with "happy to elaborate on appendix slide X" — signals you have more.
- Never apologise. Never say "good question." Just answer.
