# Thesis & Code Review

Section-by-section review of the Code Guardian thesis (`code-guardian-thesis-report/`) and the VS Code extension (`code-guardian-extension/`).

Methodology: extract every verifiable claim from the thesis, then check each against the actual source code; cross-check all numerical claims across chapters; audit citations, prose style, and code quality. Every finding below was spot-checked by reading the cited file:line directly — agent-suggested findings that did not survive verification have been excluded (notes at end).

Verdicts: **MISMATCH** = thesis claim disagrees with code. **MATCH** = verified consistent. **ISSUE** = real defect independent of any thesis claim. **STYLE** = thesis prose-rule violation. **NOTE** = clarification, no action required.

---

## 1. Top-priority issues (act on these first)

### 1.1  MISMATCH — TS taxonomy type out of sync with JSON (HIGH)
- Thesis: `tech_stack.tex:41`, `evaluation_metrics.tex:11`, `discussion.tex:64` — claims **26 canonical vulnerability classes**.
- Code: [src/categoryTaxonomy.json](code-guardian-extension/src/categoryTaxonomy.json) declares **26** categories ✓, but [src/categoryTaxonomy.ts:3-26](code-guardian-extension/src/categoryTaxonomy.ts#L3-L26) `CanonicalCategory` union has only **23**.
- Missing from the union type: `session-fixation`, `weak-validation`, `vulnerable-dependency`.
- Effect: `ALL_CATEGORIES` is cast to `readonly CanonicalCategory[]` at [categoryTaxonomy.ts:39-40](code-guardian-extension/src/categoryTaxonomy.ts#L39-L40), but at runtime contains 3 strings the type system says cannot exist. `normalizeCategory()` is typed to never return them, so any downstream code that branches on category names will silently miss those three classes.
- Fix: add the three categories to the `CanonicalCategory` union type. One-line change.

### 1.2  ISSUE — `logger` is undefined inside the webview script (HIGH)
- Code: [src/webview.ts:174-225](code-guardian-extension/src/webview.ts#L174-L225). The string between `<script>` and `</script>` ends up running in the webview's browser context, where `logger` is **not defined** — only the host process has `getLogger()`. Calls like `logger.info('Webview script starting...')` at line 176 will throw `ReferenceError` and abort the script.
- Affected lines (all inside the template literal): 176, 178, 192, 209, 214 (and likely more).
- Fix: either replace with `console.log` inside the inlined script, or post messages to the host via `vscode.postMessage(...)` and log from there.

### 1.3  ISSUE — `isModelAllowed()` is a stub; allowlist regex is dead code (HIGH)
- Code: [src/modelManager.ts:9-35](code-guardian-extension/src/modelManager.ts#L9-L35) declares `ALLOWED_MODEL_PATTERNS` but [modelManager.ts:59-62](code-guardian-extension/src/modelManager.ts#L59-L62) hardcodes `return true` regardless of input.
- Code/thesis interaction: this matters because the thesis evaluates **qwen3:4b** and **qwen3:8b** ([experimental_setup.tex:54](code-guardian-thesis-report/src/chapters/evaluation/experimental_setup.tex#L54)), but `ALLOWED_MODEL_PATTERNS` only contains `qwen2.5-coder` patterns and `getModelInfo()` ([modelManager.ts:88-111](code-guardian-extension/src/modelManager.ts#L88-L111)) has no qwen3 branch — `qwen3` falls through to category "General" with a generic description.
- The package.json `enum` ([package.json:84-101](code-guardian-extension/package.json)) also offers no qwen3 selection — only `codellama:*`, `gemma3:*`, and `qwen2.5-coder:*`. A user installs the extension and cannot pick the headline-evaluated model from the settings UI without knowing to type a custom value.
- Fix options: (a) drop the dead allowlist and update `getModelInfo` + package.json `enum` to include qwen3 / gemma3 / codellama:latest as tested; (b) keep allowlist semantics and actually enforce them.

### 1.4  MISMATCH — Thesis claim about `num_ctx: 16384` is true only of the eval harness, not the runtime (MED)
- Thesis: [system_workflow.tex:47](code-guardian-thesis-report/src/chapters/implementation/system_workflow.tex) — *"Whole-file scope requests num_ctx: 16384"*.
- Code: `num_ctx: 16384` only appears in [evaluation/run-realworld.js:186](code-guardian-extension/evaluation/run-realworld.js#L186). It is **not** set anywhere in `src/analyzer.ts`. The runtime extension's whole-file analysis path lets Ollama default to `num_ctx=2048`, which is *much* smaller than the implementation chapter implies.
- Fix: either set `num_ctx: 16384` in `analyzeCodeWithLLM()` for non-function (file/selection) scope, or scope the thesis sentence to "the evaluation harness whole-project audit pipeline" so the implementation chapter doesn't claim a runtime behavior the IDE doesn't have.

### 1.5  STYLE — Citation rule violated, 4 citations on one statement (MED)
- File: [components.tex:16](code-guardian-thesis-report/src/chapters/concept/components.tex#L16) — single statement contains four `\cite{}` keys: `mitreCWE,owaspTop10_2021,nistNVD,mitreCVE`.
- Project rule (CLAUDE.md): max 2 citations per statement.
- Fix: split into two statements ("CWE/OWASP Top-10 \cite{mitreCWE,owaspTop10_2021}. NVD/CVE summaries \cite{nistNVD,mitreCVE}.") — both pairs already comply with the 2-cite rule.

### 1.6  STYLE — Flat-outline preamble (MED)
- File: [concept.tex:3](code-guardian-thesis-report/src/chapters/concept/concept.tex#L3) — *"Section ref{...} traces ... Section ref{...} describes ... Section ref{...} presents ... Section ref{...} provides ..."*.
- Project rule (CLAUDE.md): preambles should narrow from broad context to the specific topic in flowing prose, not be a flat one-sentence-per-subsection enumeration.
- Fix: rewrite as one paragraph that narrates the trajectory: derivation → components → strategies → architecture views.

### 1.7  STYLE — Legacy/iteration framing in discussion (MED)
- File: [discussion.tex:58](code-guardian-thesis-report/src/chapters/discussion.tex#L58) — *"the four semantic categories that **previously scored zero recall**"*. This describes a pre-change/post-change comparison about taxonomy re-binning, which the user's "no legacy / iteration history" rule explicitly disallows.
- Fix: rephrase as a static statement about the canonical taxonomy: *"under the canonical taxonomy four semantic categories register zero recall; the regex-based import/sink resolver does not detect new instances in those classes — it only re-bins existing labels."*

### 1.8  ISSUE — Default-model values disagree across config sources (MED)
- [package.json](code-guardian-extension/package.json) (line ~84): `codeGuardian.model` default = `"codellama:7b"`.
- [src/modelManager.ts:174](code-guardian-extension/src/modelManager.ts#L174): `config.get<string>('model', 'gemma3:1b')` — fallback if the setting is somehow absent.
- [src/modelManager.ts:178](code-guardian-extension/src/modelManager.ts#L178): `'gemma2:2b'` — fallback when `model === 'custom'` and `customModel` is empty (and `gemma2` isn't even in the allowlist; it's `gemma3`).
- These three defaults serialize three different opinions about the "right" baseline. None of them is the headline-evaluated model (`qwen3:8b`), which is consistent with §1.3.
- Fix: pick one default per scenario, hoist it to a single constant, share it with package.json via a sync step or a `default: DEFAULT_MODEL` reference.

---

## 2. Code-vs-thesis verifications (the rest)

| Claim | Source | Verdict | Notes |
|---|---|---|---|
| LRU cache: 100 entries, 30-min TTL | [components.tex:33](code-guardian-thesis-report/src/chapters/concept/components.tex#L33), [agent.tex:50](code-guardian-thesis-report/src/chapters/implementation/agent.tex), [impl-details.tex:53](code-guardian-thesis-report/src/chapters/appendices/impl-details.tex) | MATCH | [analysisCache.ts:18-22](code-guardian-extension/src/analysisCache.ts#L18-L22) |
| 800 ms debounce | [strategies.tex:11](code-guardian-thesis-report/src/chapters/concept/strategies.tex#L11), `system_workflow.tex:14`, `system_architecture_and_design.tex:53,67,86`, `agent.tex:50`, `impl-details.tex:47` | MATCH | [extension.ts:91](code-guardian-extension/src/extension.ts#L91) |
| 2,000-char function guard | `strategies.tex:13`, `system_workflow.tex:14`, `impl-details.tex:48` | MATCH | [extension.ts:101](code-guardian-extension/src/extension.ts#L101) |
| 20,000-char file guard | `strategies.tex:25`, `system_workflow.tex:14`, `impl-details.tex:49` | MATCH | [extension.ts:137](code-guardian-extension/src/extension.ts#L137) |
| 500 KB workspace skip | `strategies.tex:46`, `system_workflow.tex:14`, `impl-details.tex` | MATCH (caveat) | [workspaceScanner.ts:163](code-guardian-extension/src/workspaceScanner.ts#L163) uses `content.length > 500000` (chars), not bytes; for ASCII-heavy JS this is approximately 500 KB but for multi-byte content is a different threshold. |
| Two consensus passes default, configurable up to 5 | `system_workflow.tex:18`, `concept.tex:13`, `concept_derivations.tex:15`, `positioning.tex:120` | MATCH | [analyzer.ts:96-98](code-guardian-extension/src/analyzer.ts#L96-L98) `passes:2`, `seeds:[42,137,211,317,421]`, settings clamp 1–5 |
| Seeds {42, 137} for two passes | `system_architecture_and_design.tex:67` | MATCH | analyzer.ts:98 (CONSENSUS_DEFAULTS.seeds.slice(0, passes)) |
| Confidence semantics: 1.0 unanimous, 0.3 single-pass fallback | implicit in `system_workflow.tex:18` | MATCH | [analyzer.ts:21-23, 423, 431](code-guardian-extension/src/analyzer.ts#L21-L23) |
| Confidence gate ≥ 0.67 = "2 of 3 runs" | `system_workflow.tex:18`, `eval_r1_accuracy.tex:94`, headline gated row | MATCH (semantic) | The 0.67 threshold is meaningful only at 3 passes (2/3 = 0.67); the runtime default is 2 passes where confidence is binary {0.3, 1.0}. The thesis is consistent in marking 0.67 as the *evaluation* configuration, not the runtime default. |
| 30-second detection timeout, 15-second repair timeout | implicit; eval harness `timeoutMs=30000` | MATCH | [analyzer.ts:232 (30s), :543 (15s)](code-guardian-extension/src/analyzer.ts#L232) |
| RAG: HNSWLib, nomic-embed-text, chunk 1000 / overlap 200 | `tech_stack.tex:16`, `components.tex:16` | MATCH | [ragManager.ts:38-54](code-guardian-extension/src/ragManager.ts#L38-L54) |
| Top-k = 3 runtime, k = 5 evaluation | `components.tex:16`, `system_architecture_and_design.tex:67`, `experimental_setup.tex:6` | MATCH | [ragManager.ts:442](code-guardian-extension/src/ragManager.ts#L442) (k=3) and `evaluate-models.js:38` (`DEFAULT_RAG_K=5`) |
| 26 canonical vulnerability classes | `tech_stack.tex:41`, `evaluation_metrics.tex:11` | PARTIAL | JSON has 26 ✓; TS union has 23 (see §1.1) |
| Loopback allowlist `127.0.0.1, ::1, localhost, 0.0.0.0` | `privacy_enforcement.tex:19` | MATCH | [networkPolicy.ts:17-22](code-guardian-extension/src/networkPolicy.ts#L17-L22) |
| `enableExternalDataFetch` default false | `privacy_enforcement.tex:19`, `eval_r5_privacy.tex:35` | MATCH | [networkPolicy.ts:46](code-guardian-extension/src/networkPolicy.ts#L46), package.json |
| Ed25519 signature + SHA-256 manifest | `privacy_enforcement.tex:32` | MATCH | [corpusVerifier.ts:52, 146](code-guardian-extension/src/corpusVerifier.ts#L52) |
| `@babel/parser` syntax check on every suggestedFix | `repair_safety.tex:12`, `future_work.tex:13` | MATCH | [repairValidator.ts:41-55, 99-107](code-guardian-extension/src/repairValidator.ts#L41-L55) |
| 24-hour vulnerability-data cache | CLAUDE.md notes; not stated in thesis I could find | MATCH | [vulnerabilityDataManager.ts:71](code-guardian-extension/src/vulnerabilityDataManager.ts#L71) |
| Egress test monkey-patches `net.connect, dgram.send, dns.lookup, http.request, https.request` | `eval_r5_privacy.tex:45` | MATCH | [evaluation/privacy/test-egress.js:74,90,96,133](code-guardian-extension/evaluation/privacy/test-egress.js) |
| 101 cases (71 vulnerable + 30 secure) | `evaluation.tex:1`, `dataset_details.tex:4`, `eval_summary.tex`, `discussion.tex:45`, `conclusion.tex:12` | MATCH | `vulnerability-test-cases.generated.json` has 101 entries; `negatives-only.generated.json` has 30 |
| 15-case external corpus | `conclusion.tex:12`, `discussion.tex:45`, `dataset_details.tex` | MATCH | `external/external-test-cases.json` has 15 entries |
| 5 models tested: gemma3:1b, gemma3:4b, qwen3:4b, qwen3:8b, codellama:latest | `experimental_setup.tex:54` | MATCH (claim) but see §1.3 — UI/code only knows about 3 of these |
| 9 VS Code commands registered | implicit (CLAUDE.md mentions specific ones) | MATCH | package.json `contributes.commands` has 9 entries |

### Numbers cross-checked across chapters (Pass 3)

All headline numbers reconcile across chapters with **no inconsistencies found**: F1 71.43% / precision 72.46% / recall 70.42% / FPR 10.00%; gated F1 74.07% / precision 78.13%; stage-1 latency 2,216 ms; stage-2 latency 3,320 ms; auto-applicable 90.32% (252/279); NodeGoat 3/7 inline → 6/7 audit; 101 / 15 corpus sizes. The R1–R5 grade thresholds in `analysis/requirements/r*.tex` are correctly applied in the corresponding evaluation chapters.

**No stale `R6` or `R7` references** anywhere in the chapter sources. (Verified by exhaustive grep.)

---

## 3. Citations & bibliography

- 65 of 65 bib keys are cited at least once — **no orphaned entries**.
- All `\cite{}` keys resolve — **no broken references**.
- Citation style is uniformly `\cite{}` across all chapters — no mixing of `\citep`, `\citet`, `\autocite`.
- Only one rule violation found (§1.5, components.tex:16, 4 keys in one statement).
- Most-used references (top 5): `johnson2013don` (9), `ji2023hallucination` (6), `mitreCWE` (6), `christakis2016developers` (5), `islam2024secrepair` / `lewis2020rag` / `karpukhin2020dpr` / `owaspTop10_2021` (4 each). When you need an additional citation, prefer these over rarely-used ones (per CLAUDE.md rule).
- Three statements with empirical-sounding claims that lack a citation (consider adding):
  - [llm_vuln_detection.tex:74](code-guardian-thesis-report/src/chapters/analysis/related_works/llm_vuln_detection.tex#L74) — *"GitHub Copilot offers the best usability (R4) ... but fails on privacy (R5) since it requires cloud inference."*
  - [privacy_ide.tex:53](code-guardian-thesis-report/src/chapters/analysis/related_works/privacy_ide.tex#L53) — same Copilot/cloud claim restated.
  - [rag_secure_coding.tex:5](code-guardian-thesis-report/src/chapters/analysis/related_works/rag_secure_coding.tex#L5) — *"Recent secure-code generation research suggests that what is retrieved matters as much as retrieval itself."*

---

## 4. Prose & style (verified subset)

### 4.1 Long sentences (>40 words) — split into shorter units
- [system_workflow.tex:8](code-guardian-thesis-report/src/chapters/implementation/system_workflow.tex#L8) — entire opening paragraph is one ~240-word sentence chain. Top priority for split.
- [system_workflow.tex:18](code-guardian-thesis-report/src/chapters/implementation/system_workflow.tex#L18) — ~200-word "Four configurable gates …" sentence; break after each gate definition.
- [eval_r1_accuracy.tex:43](code-guardian-thesis-report/src/chapters/evaluation/eval_r1_accuracy.tex#L43) — McNemar / Bonferroni passage; split at *"With Bonferroni correction"*.
- [eval_r1_accuracy.tex:49](code-guardian-thesis-report/src/chapters/evaluation/eval_r1_accuracy.tex#L49) — *"Across configurations, retrieval augmentation has model-specific effects: …"* — split at the first semicolon.
- [agent.tex:40](code-guardian-thesis-report/src/chapters/implementation/agent.tex#L40) — *"The diagnostic adapter ... clamps indices ... ; when a function snippet is analysed, the previously-computed start-line offset is added ..."* — period after "bounds".
- [strategies.tex:62](code-guardian-thesis-report/src/chapters/concept/strategies.tex#L62) — confidence-as-first-class paragraph; redistribute into 2–3 short paragraphs.
- [concept_derivations.tex:9](code-guardian-thesis-report/src/chapters/concept/concept_derivations.tex#L9) — *"Running the LLM, retrieval pipeline, and analysis components entirely on local hardware keeps source code, intermediate representations, and analysis results on-device, supports R5, and enables fully offline operation when knowledge refresh is disabled."* — list-heavy; tighten.

### 4.2 Stage-notation inconsistency (LOW)
- Mixed forms across files: `Stage~1`, `stage-1`, `Stage 1`, `Stage-1`. Pick one (e.g. `Stage~1`) and use consistently. This is the only term inconsistency that survived audit.

### 4.3 Spelling
- Mostly British English (`analysed`, `recognise`, `centre`). One US slip in [discussion.tex:28](code-guardian-thesis-report/src/chapters/discussion.tex#L28) uses *"analysed"* in same paragraph as *"analyzed"* elsewhere — pick one.

---

## 5. Code review (issues independent of thesis claims)

| File:line | Severity | Category | Issue | Suggested fix |
|---|---|---|---|---|
| [webview.ts:174-225](code-guardian-extension/src/webview.ts#L174) | HIGH | BUG | `logger.info(...)` calls inside the inlined `<script>` body — `logger` is not in webview JS scope. | Replace with `console.log` inside inlined script; keep `getLogger()` for host-side calls only. |
| [categoryTaxonomy.ts:3-26](code-guardian-extension/src/categoryTaxonomy.ts#L3-L26) | HIGH | BUG | `CanonicalCategory` union type missing 3 categories that exist in JSON; runtime `ALL_CATEGORIES` casts violate the type. | Add `session-fixation \| weak-validation \| vulnerable-dependency` to the union. |
| [modelManager.ts:9-62](code-guardian-extension/src/modelManager.ts#L9-L62) | HIGH | DEAD-CODE | `ALLOWED_MODEL_PATTERNS` is dead — `isModelAllowed()` returns `true` unconditionally. The qwen3 line of models tested in the thesis is also missing from `getModelInfo()` and from package.json's enum. | Either delete the dead allowlist + add qwen3 to UI metadata, or implement the regex check. |
| package.json + [modelManager.ts:174,178](code-guardian-extension/src/modelManager.ts#L174-L178) | MED | DRIFT | Three different default models across config layers (`codellama:7b` / `gemma3:1b` / `gemma2:2b`). | Single `DEFAULT_MODEL` constant; the `gemma2:2b` is almost certainly a typo for `gemma3` since `gemma2` is not in the allowlist. |
| [extension.ts:55-59](code-guardian-extension/src/extension.ts) | MED | BUG | RAG initialization is fired via `setTimeout(..., 100)` without awaiting — any rejection is swallowed; the extension proceeds in a race-prone state where commands invoked early may see `ragManager === null`. | Use a tracked promise (`ragInitPromise`) and have RAG-using commands `await` it. |
| [vulnerabilityDataManager.ts](code-guardian-extension/src/vulnerabilityDataManager.ts) | MED | MAINTAINABILITY | 2,517 lines for a single class. Also `User-Agent: VS-Code-Extension-CodeGuardian/1.0` is hardcoded but the package version is `1.0.24` — the UA will mislead any logs server-side. | Inject `package.json` version into UA; consider splitting CVE/CWE/OWASP fetchers into separate modules. |
| [ragManager.ts:882](code-guardian-extension/src/ragManager.ts#L882) | LOW | TYPO | `' Using legacy method ...'` — leading space before the message. | Trim the leading space and consider whether the "legacy wrapper" comment is still accurate or can be deleted entirely (no callers in src/ — verify). |
| [extension.ts:374-375](code-guardian-extension/src/extension.ts) | LOW | INFO-LEAK | Error strings collected during workspace traversal include full file paths and are later forwarded into LLM context. Local Ollama is fine, but if `ollamaHost` is ever pointed at a non-loopback (the setting is freely configurable), paths leave the machine. | Sanitize paths to repo-relative before injecting into prompts. |
| [analysisCache.ts:49-55](code-guardian-extension/src/analysisCache.ts#L49-L55) | LOW | NOTE | SHA-256 truncated to 16 chars (~64 bits). Cache key collision probability becomes non-negligible at ~4B entries; with `maxSize=100`, this is fine, but a comment explaining the trade-off would prevent future cargo-cult lengthening. | One-line comment justifying the truncation. |
| [logger.ts](code-guardian-extension/src/logger.ts) | LOW | LOGGING-CONVENTION | Logger has only 4 levels (DEBUG, INFO, WARN, ERROR). Global CLAUDE.md specifies 6 (fatal, error, warn, info, debug, trace). Not a blocker for the thesis, but worth noting if you ever publish the extension. | Optional. |

---

## 6. Items I could not verify from local files (need user confirmation)

- **Ollama 0.17.1, Node.js v20.19.5** ([experimental_setup.tex:55](code-guardian-thesis-report/src/chapters/evaluation/experimental_setup.tex#L55)) — not derivable from the repo. Only verifiable from the evaluation runtime. Confirm these match what was actually installed when the headline runs were produced.
- **Apple M4 Max (16 cores, 64 GB RAM)** ([experimental_setup.tex:56](code-guardian-thesis-report/src/chapters/evaluation/experimental_setup.tex#L56)) — same.
- **nomic-embed-text: 768-dim, 137M params** ([tech_stack.tex:18](code-guardian-thesis-report/src/chapters/implementation/tech_stack.tex#L18)) — external fact about the model; please cite the model card or HF page (only `langchainDocs` and `ollamaDocs` currently appear in the surrounding citations).
- **External corpus = 15 cases drawn from NodeGoat, Juice Shop, and three named CVEs** — file count is 15 ✓, but I did not enumerate which CVEs are which; check that the corpus's `source` field actually distinguishes those three sources as claimed.

---

## 7. Agent findings I rejected (false positives)

For transparency — these were flagged by automated review but discarded after I read the source:

- *"analyzer.ts:518 — `'='.repeat(50)` syntax error"* — line 518 is inside a multi-line block comment explaining repair-schema design, not executable code.
- *"ragManager.ts:518 — string repeat syntax issue"* — `'='.repeat(50)` is valid JavaScript and used correctly.
- *"analyzer.ts:356 — uses `console.warn` instead of logger"* — line 356 actually calls `logger.warn(...)`. The agent misread.
- *"R6 / R7 stale references found"* — exhaustive grep confirms zero occurrences in any `.tex` file.
- *"All evaluation numbers reconcile cleanly"* — verified via cross-chapter check; no inconsistencies detected, this is genuinely clean.

---

## Summary

**Hard blockers (fix before defense):** §1.1 (taxonomy type drift, breaks runtime correctness), §1.4 (thesis claim about `num_ctx` doesn't hold in the runtime), §1.5 (citation rule violation).

**Should-fix:** §1.2, §1.3, §1.6, §1.7, §1.8, plus §4.1 long sentences.

**Nice-to-have:** §4.2 stage notation, §4.3 spelling, §5 LOW-severity items, §3 missing citations.

**Clean:** All headline numbers reconcile across chapters; no R6/R7 stale references; no broken `\ref{}`; no orphaned bib entries; consistent `\cite{}` style; R1–R5 grade thresholds are correctly applied throughout the evaluation chapters; privacy-enforcement claims (loopback allowlist, signed corpus, egress test) all match the code.
