# Code Guardian — How the Extension Works

A complete technical walkthrough of the **Code Guardian** VS Code extension: what it does, how every layer is built, which technology is used for what, and how a piece of code travels from a keystroke to an inline security warning with a one-click fix.

> **In one sentence:** Code Guardian is a privacy-preserving VS Code extension that detects and repairs security vulnerabilities in JavaScript/TypeScript using a **local** LLM (via [Ollama](https://ollama.com)), enriched with **Retrieval-Augmented Generation (RAG)** over a signed security-knowledge base — with no code ever leaving the developer's machine.

---

## 1. What the extension does

Code Guardian adds four capabilities to the editor:

1. **Real-time detection** — as you type in a `.js`/`.ts` file, the enclosing function is analyzed in the background and exploitable vulnerabilities are surfaced as inline warnings (yellow squiggles).
2. **One-click repair** — every finding offers a lightbulb action that rewrites the whole enclosing function with a secure version, shown either applied directly or as a side-by-side diff preview.
3. **Workspace-wide auditing** — a "Security Dashboard" scans every file, fuses a deterministic AST scanner with the LLM, computes a 0–100 security score (A–F grade), and renders heatmap-style results.
4. **Interactive AI copilot** — a streaming chat webview for "analyze this selection" and "ask questions about this codebase/folder/file."

Everything runs locally. The only network connection in the default configuration is to the loopback Ollama server at `http://localhost:11434`.

---

## 2. Technology stack at a glance

| Concern | Technology | Used for |
|---|---|---|
| Extension runtime | **VS Code Extension API** `^1.98.0`, TypeScript `5.8.3` (strict) | Editor integration, commands, diagnostics, webviews |
| LLM inference | **Ollama** (`ollama` npm `^0.5.14`) | Local LLM detection + repair, structured JSON output, streaming chat |
| RAG / vectors | **LangChain** `^1.0.2` (`@langchain/core`, `/community`, `/ollama`, `/textsplitters`) + **HNSWlib** (`hnswlib-node` `^3.0.0`) | Knowledge-base chunking, embeddings, vector similarity search |
| Embeddings | `nomic-embed-text` via Ollama | Local vectorization of security knowledge |
| Code parsing | **TypeScript compiler API** (`ts.createSourceFile`) | Function extraction, AST sink detection |
| Repair validation | **@babel/parser** | Syntax-checking LLM repairs (`autoApplicable` flag) |
| Crypto / integrity | Node `crypto` | SHA-256 cache hashing, Ed25519 corpus signature verification |
| External data (opt-in) | Node `https` (no axios) | NVD / OWASP / CWE / GitHub / OSV refresh |
| UI rendering | **Marked.js** (bundled in `media/`) | Markdown rendering inside webviews |
| Build / bundle | **esbuild** `^0.25.0` | Single CJS bundle → `dist/extension.js` |
| Lint / quality | **ESLint** `^9` + `eslint-plugin-security` | Static checks |
| Tests | **Mocha** + `ts-node`, `@vscode/test-electron`, **c8** | Unit + integration tests, coverage |
| Packaging / CI | **@vscode/vsce**, GitHub Actions | VSIX packaging, publish on tag push |
| Reproducible eval | **Docker** + docker-compose (`node:20-alpine` + `ollama/ollama`) | Containerized evaluation harness |

**Runtime dependencies are deliberately minimal** — only 7 packages: the LangChain quartet, `hnswlib-node`, `ollama`, and `langchain` itself. There is no `axios` (HTTP uses Node built-ins) and no `marked` npm dependency (`marked.min.js` ships as a webview asset under `media/`).

---

## 3. The six-layer architecture

The extension is organized as six layers. Source files live in [src/](../src/).

```
┌──────────────────────────────────────────────────────────────┐
│ L1  User Interface   diagnostics · lightbulb · status bar      │
│                       dashboard & analysis webviews            │
├──────────────────────────────────────────────────────────────┤
│ L2  Extension Core   extension.ts — activation, commands,      │
│                       debounce engine, lifecycle               │
├──────────────────────────────────────────────────────────────┤
│ L3  Intelligence     analyzer.ts · analysisCache.ts            │
│                       ragManager.ts · workspaceScanner.ts      │
│                       projectMapBuilder.ts                     │
├──────────────────────────────────────────────────────────────┤
│ L4  External Data    vulnerabilityDataManager.ts (NVD/OWASP/   │
│                       CWE/GitHub/OSV) · networkPolicy.ts gate  │
├──────────────────────────────────────────────────────────────┤
│ L5  AI Processing    modelManager.ts (Ollama discovery)        │
│                       ollama.chat (inference, in analyzer.ts)  │
├──────────────────────────────────────────────────────────────┤
│ L6  Presentation     webview.ts · dashboardWebview.ts          │
│                       media/ (CSS, JS, Marked.js)              │
└──────────────────────────────────────────────────────────────┘
```

---

## 4. Layer 2 — Extension core ([extension.ts](../src/extension.ts))

The entry point. `activate(context)` wires everything together:

- **Lazy RAG init.** RAG is heavy (loads the vector store), so it's initialized through a memoized `initializeRAGIfNeeded()` that shares a single in-flight `ragInitPromise`. Activation fires it as `void initializeRAGIfNeeded()`, but command handlers `await` it so the first real use gets a fully loaded knowledge base. The *same* initializer is injected into both the analyzer path and the quick-fix path so they share one `RAGManager`.
- **Diagnostics collection.** `vscode.languages.createDiagnosticCollection('codeSecurity')` holds all findings.
- **Status bar.** A clickable item shows `🧠 RAG: ON` / `📝 RAG: OFF`, bound to the toggle command.
- **Command registration.** Nine commands, all prefixed `codeSecurity.` (see §11).
- **Quick-fix provider.** `provideFixes()` is registered as a `CodeActionProvider` for JS/TS.

### The real-time debounce + in-flight engine

This is the most carefully engineered part of the core, because Ollama runs on a serial GPU queue — stacking parallel requests caused 30s timeouts on later passes.

- `DEBOUNCE_DELAY = 800` ms after the last keystroke.
- Per-document state is tracked in `docAnalysisStates: Map<uri, {inFlight, queued?}>`.
- `runAnalysisLoop()` implements **per-document serial coalescing**: if an analysis is already running for a document, the newest snapshot just overwrites `state.queued` (latest-wins). When the running call finishes, it drains the queued snapshot. This guarantees at most one Ollama request per document at a time.
- `onDidChangeTextDocument` filters to JS/TS and the active editor's document, then on fire extracts the enclosing function via `getEnclosingFunction` and skips functions longer than 2000 chars.

`deactivate()` disposes the cache cleanup timer and the logger.

---

## 5. Layer 5 — AI processing: Ollama integration

### [modelManager.ts](../src/modelManager.ts) — discovery & selection

This module manages **which** model and **where** Ollama is — it does *not* run inference itself.

- Uses the `ollama` npm client (`ollama.list()`, `ollama.pull()`).
- `DEFAULT_MODEL = 'codellama:7b'` (kept in sync with `package.json`).
- `getCurrentModel()` resolves in order: env var `CODE_GUARDIAN_MODEL` (test hook) → `codeGuardian.model` setting → `customModel` if `'custom'` → default.
- `getOllamaHost()` reads `codeGuardian.ollamaHost` (default `http://localhost:11434`).
- `showModelSelector()` is a rich QuickPick that groups installed models by category, shows recommended-but-not-installed models with a download icon (offering to copy `ollama pull <name>` to the clipboard), and validates custom model names.
- ~29 model tags are supported across families: Qwen 2.5-Coder (0.5B–32B), Qwen 3 (1.7B–32B), Gemma 3, CodeLlama (7B–70B), DeepSeek-Coder, WizardCoder, StarCoder2, StableCode. The **thesis headline configuration is `qwen3:8b` + RAG**.

### Where inference actually happens — [analyzer.ts](../src/analyzer.ts)

The `ollama.chat(...)` calls live in the analyzer. Two modes:

- **Structured detection/repair** — `format: <JSON schema>`, `temperature: 0`, fixed `seed`, `num_ctx` sized to scope. Constrained decoding is essential: bare `format: 'json'` only forces *valid* JSON and lets models invent field names (CodeLlama might emit `{message, severity, line, column}`), so a `DETECTION_SCHEMA` pins both shape and field names.
- **Streaming chat** — `stream: true` for the conversational webview, posting incremental chunks for live markdown rendering.

---

## 6. Layer 3 — Intelligence & analysis (the detection brain)

### [analyzer.ts](../src/analyzer.ts) — two-stage, multi-pass consensus pipeline

This is the core engine. Key data type: `SecurityIssue` (`message`, 1-based `startLine`/`endLine`, optional `suggestedFix`, `confidence` 0–1, `detectionSource: 'llm'|'sast'|'hybrid'|'ast'`, `autoApplicable`).

`analyzeCodeWithLLM(code, model, ragManager, scope)` is the orchestrator called by both real-time and workspace paths:

1. **Cache check first** — `getAnalysisCache().get(code, model, ragEnabled)`. On hit, returns immediately (no LLM call).
2. **Stage 1 prompt build** — a terse detection system prompt ("Detect exploitable security vulnerabilities… return ONLY a JSON array… `[]` if secure"). If `importContext` is enabled, a deterministic import/sink summary is appended.
3. **RAG enrichment** — if a `ragManager` exists, both prompts pass through `ragManager.generateEnhancedPrompt(prompt, code)`, which injects the top-3 relevant knowledge chunks.
4. **Multi-pass consensus** — runs `consensusPasses` (default 2) calls to `singleAnalysisPass` **in parallel** with distinct seeds `[42, 137, 211, ...]`, then filters.
5. **Confidence gate** — optional `minConfidence` threshold drops low-confidence findings.
6. **Stage 2 (file scope only)** — generates repairs per issue, tags `autoApplicable`. Real-time (`'function'` scope) **skips Stage 2** — repairs are lazily generated by the lightbulb instead, to avoid an extra Ollama call per keystroke.

**A single pass (`singleAnalysisPass`)**:
- Calls `ollama.chat` with the `DETECTION_SCHEMA`, wrapped in a `Promise.race` against a **30s timeout**.
- A tolerant parsing pipeline strips markdown fences, falls back to extracting the `[...]` substring, and a `toIssue()` coercer normalizes the chaos of model field names (`startLine`/`lineStart`/`start_line`/`line` all map to one shape).
- Errors are typed (`CONNECTION`, `TIMEOUT`, `PARSE`, `MODEL_NOT_FOUND`, `RATE_LIMIT`). Retryable ones use **exponential backoff** (`maxAttempts: 3`, `baseDelay: 1000ms`, `maxDelay: 5000ms`). Friendly messages guide the user (e.g. "start Ollama", "Open Settings").

**Consensus filtering (`applyConsensusFilter`)**: two findings are "the same" if their line ranges overlap *and* they share a vulnerability keyword (SQL injection, XSS, command injection, SSRF, prototype pollution, …) or ≥3 significant words. A finding survives when `agreementCount >= minAgreement`, taking `confidence = agreementCount / passCount`. A recall-preserving fallback returns the primary pass at low confidence if consensus would drop everything.

**Repair generation**: `generateFunctionRepair()` rewrites the **entire enclosing function** (not just the flagged lines) using a `{code, language}` schema — function granularity avoids context-echo and dropped-wrapper failures. `sanitizeRepair()` strips fences, un-escapes JSON, removes echoed surrounding lines, and re-aligns indentation.

### [analysisCache.ts](../src/analysisCache.ts) — LRU cache

Avoids redundant LLM calls. Singleton with `maxSize: 100`, `maxAge: 30min`, cleanup every 5min.

- **Cache key** = `sha256(`${code}:${model}:${mode}`)` truncated to 16 hex chars, where `mode` is `rag-on`/`rag-off`. Changing the code, model, or RAG toggle busts the entry.
- Classic LRU: an `accessOrder` array moves hits to the tail; eviction shifts the head.
- `getStats()` reports live hit/miss/eviction rates and powers the "View Cache Statistics" command.

### [ragManager.ts](../src/ragManager.ts) — Retrieval-Augmented Generation

Builds and queries a local security-knowledge vector index. Built entirely on **LangChain**:

- **Vector store**: `HNSWLib` from `@langchain/community/vectorstores/hnswlib` (HNSWlib-node native index).
- **Embeddings**: `OllamaEmbeddings` with model `nomic-embed-text`, pointed at the local Ollama host — embeddings are generated locally, same privacy posture as inference.
- **Chunking**: `RecursiveCharacterTextSplitter` (`chunkSize: 1000`, `chunkOverlap: 200`).

**Build flow** (`initializeKnowledgeBase`): verify on-disk corpus integrity (see §8) → load `knowledge-base.json` → if empty, pull from `VulnerabilityDataManager` and convert each entry to `SecurityKnowledge` (or fall back to 3 hardcoded baseline entries offline) → load or build the HNSW index and save it to `security-knowledge/vector-store`.

**Query** (`searchRelevantKnowledge(query, k=3)` → `vectorStore.similaritySearch`): the headline consumer `generateEnhancedPrompt` searches with the prompt + code snippet, retrieves the top 3 docs, and appends a "RELEVANT SECURITY KNOWLEDGE" block (title, severity, CWE/OWASP, content). On no-hit or error it returns the prompt unchanged (graceful degradation).

**Maintenance**: `syncFromDynamicSources()` re-fetches 7 source categories and does a single bulk `rebuildVectorStore()` at the end — HNSWlib has no per-item deletion, so updates/prunes always trigger a full rebuild.

### [workspaceScanner.ts](../src/workspaceScanner.ts) — concurrent workspace scan

Powers the dashboard. Discovers files via `findFiles('**/*.{js,jsx,ts,tsx}', '**/node_modules/**')` and processes them in fixed batches of `CONCURRENCY = 3` using `Promise.all`, with `AbortController` cancellation, a re-entrancy guard, a 500 KB file-size cap, and an `onProgress` callback.

**Audit mode** (`enableAuditMode`, default on) fuses two stages:
- **Stage 0 (deterministic)** — `buildProjectMap()` from [projectMapBuilder.ts](../src/projectMapBuilder.ts) walks the whole project with the TypeScript AST and flags syntactic sinks: `eval`/`Function` (CWE-95), `exec`/`spawn` (CWE-78), weak crypto MD5/SHA1 (CWE-327), Mongo `$where` (CWE-943), mass assignment (CWE-915), ReDoS regexes (CWE-1333), dynamic `require` (CWE-22). These are `detectionSource: 'ast'`, confidence 1.0.
- **Stage 1 (semantic)** — the LLM analyzer per file.
- `mergeIssues()` unions them; overlapping same-line findings become `detectionSource: 'hybrid'` (AST wins as deterministic).

**Scoring**: issues are weighted (critical×10, high×5, medium×2, low×1), normalized per 1000 LOC; `score = max(0, 100 - weightedPerKLOC×5)`; grade A≥90, B≥80, C≥70, D≥60, else F.

### Supporting context helpers

- [functionExtractor.ts](../src/functionExtractor.ts) — `getEnclosingFunction()` uses the TypeScript compiler API to find the **innermost** function-like node around the cursor and return its exact `vscode.Range` (what the quick-fix replaces wholesale).
- [importResolver.ts](../src/importResolver.ts) — opt-in regex-based extractor that surfaces import/sink/category hints (data-driven from `importResolver.json`) for categories where the dangerous API isn't lexically obvious.
- [sastBridge.ts](../src/sastBridge.ts) — `fuseSastWithLlm()` promotes an LLM finding to `hybrid`/confidence 1.0 when an external SAST tool agrees on both line range and canonical category.

---

## 7. Layer 4 — External data sources ([vulnerabilityDataManager.ts](../src/vulnerabilityDataManager.ts))

Fetches and normalizes security knowledge from external sources into one `VulnerabilityData` shape. Uses raw Node `https` (no axios), and **every outbound call is gated through `networkPolicy.assertEgressAllowed()`**.

Seven fetchers, aggregated via `Promise.allSettled`:
1. **CWE** — large curated in-code database (~15 definitions: CWE-79, 89, 22, 352, 502, 94/95, 327, 78, …).
2. **OWASP Top-10** — 2021 A01–A10 entries.
3. **NVD CVEs** — live `services.nvd.nist.gov/rest/json/cves/2.0` (when egress enabled).
4. **JavaScript vulns** — curated patterns + GitHub Security Advisories (`api.github.com/advisories?ecosystem=npm`) + OSV (`api.osv.dev/v1/query` for express, lodash, axios, jsonwebtoken, …).
5. **OWASP cheat sheets**, 6. **CAPEC patterns**, 7. **Node.js security patterns**.

Data is cached to `vulnerability-data/*.json` with a **24-hour expiry** — but under zero-egress (default), the on-disk cache is treated as valid regardless of age, since it's the only source of truth. The shipped bundle totals ~171 entries ("165+").

---

## 8. Privacy & security enforcement (Requirement R5)

Privacy is enforced in code, not just by policy:

- **[networkPolicy.ts](../src/networkPolicy.ts)** is the single egress chokepoint. `assertEgressAllowed(url)` allows a request **only** if the host is loopback (`localhost`/`127.0.0.1`/`::1`/`0.0.0.0`, i.e. Ollama) **or** the user explicitly opted in via `enableExternalDataFetch` (default **false**). Otherwise it throws `EgressBlockedError`. By default the only reachable endpoint is `localhost:11434`.
- **[corpusVerifier.ts](../src/corpusVerifier.ts)** defends against RAG retrieval poisoning. `verifyCorpus()` checks every knowledge file's SHA-256 against a signed manifest and verifies an **Ed25519** detached signature (`crypto.verify`). The public key ships in [keys/corpus-public.pem](../keys/); the private key is held off-repo. Gated by `requireSignedCorpus` (default **true**) — RAG refuses to load a tampered corpus.
- **Local-only inference and embeddings** — both the LLM and `nomic-embed-text` run via local Ollama. Code never leaves the machine.
- **Adversarial privacy harnesses** in `evaluation/privacy/` monkey-patch `net`/`http`/`dns` to assert the only outbound socket is loopback Ollama, hash source bytes to detect leaks, and test prompt-injection resistance.

---

## 9. Layer 1 & 6 — UI and presentation

### Diagnostics & quick fixes

- [diagnostic.ts](../src/diagnostic.ts) — `analyzeAndReportDiagnosticsFromText()` turns `SecurityIssue[]` into `vscode.Diagnostic` warnings. It **clamps** hallucinated line numbers to the actual snippet length and applies a `lineOffset` so a function's local lines map back to absolute document lines. Each diagnostic carries `source = 'CodeGuardian'` and `code = 'codeSecurity.fixSuggestion'` (the marker the lightbulb matches).
- [actions.ts](../src/actions.ts) — the `CodeActionProvider`. For each finding it offers **"Apply Secure Fix"** and **"Preview Secure Fix (diff)"**. Because the diagnostic's column may not land on the AST node, `getOrGenerateFunctionRepair()` tries several candidate cursor positions until `getEnclosingFunction` resolves, then calls `generateFunctionRepair`. Repairs are cached so Preview→Apply reuses one LLM call. Apply uses `WorkspaceEdit.replace`; Preview opens the native `vscode.diff` from an in-memory `code-guardian-diff` provider (no temp files).
- [repairValidator.ts](../src/repairValidator.ts) — uses **@babel/parser** to syntax-check a repair (rejecting prose, trying module/script/expression parses) and set the `autoApplicable` flag.

### Webviews

- [webview.ts](../src/webview.ts) — the streaming analysis panel and the contextual Q&A panel. Markdown is rendered client-side with **Marked.js** (loaded from `media/marked.min.js` via `asWebviewUri`); `escapeHtml()` guards against injection; communication uses `acquireVsCodeApi()` message passing.
- [dashboardWebview.ts](../src/dashboardWebview.ts) — `getDashboardHTML()` returns a self-contained HTML page with a strict CSP (`script-src 'nonce-...'`), a grade-colored score card, a metrics grid, a CSS bar chart of severities, and a top-20 file list. Buttons post `rescan`/`export`/`settings`/`openFile` back to the host.
- [logger.ts](../src/logger.ts) — a singleton writing to a VS Code `OutputChannel('Code Guardian')` and mirroring to the Debug Console, with `DEBUG/INFO/WARN/ERROR` levels.

---

## 10. End-to-end flows

### Real-time detection (as you type)

```
keystroke → onDidChangeTextDocument (JS/TS, active doc)
  → debounce 800ms → getEnclosingFunction (TS AST)
  → runAnalysisLoop (serial per-doc, latest-wins)
  → analyzeCodeWithLLM(scope='function')
      → cache check (sha256) ─ hit? return
      → build detection prompt (+ optional import context)
      → RAG enrich (HNSW top-3) → ragManager.generateEnhancedPrompt
      → N parallel ollama.chat passes (seeds, schema, temp 0)
      → consensus filter + confidence gate
  → diagnostic.ts: clamp lines, set squiggles
  → lightbulb appears (repair generated lazily on click)
```

### One-click repair

```
lightbulb → provideFixes (matches code 'codeSecurity.fixSuggestion')
  → getOrGenerateFunctionRepair (try candidate positions)
  → getEnclosingFunction → generateFunctionRepair (ollama, {code,language} schema)
  → sanitizeRepair (fences, indentation) → repair cache
  → Apply: WorkspaceEdit.replace  |  Preview: vscode.diff
```

### Workspace dashboard

```
command → WorkspaceScanner.scan
  → Stage 0: buildProjectMap (TS AST sinks, confidence 1.0)
  → Stage 1: analyzeCodeWithLLM per file (batches of 3)
  → mergeIssues (ast ∪ llm → hybrid on overlap)
  → calculateSecurityScore + grade
  → dashboardWebview.getDashboardHTML
```

---

## 11. Commands & settings reference

**Commands** (palette prefix "Code Guardian:"):

| Command | Action |
|---|---|
| `analyzeSelectionWithAI` | Streaming AI analysis of the selection |
| `analyzeFullFile` | Full-file structured scan (≤20000 chars) |
| `contextualQnA` | Chat Q&A over files/folders |
| `selectModel` | Pick the Ollama model |
| `manageRAG` | View/add/rebuild/search the knowledge base |
| `toggleRAG` | RAG on/off |
| `updateVulnerabilityData` | Refresh NVD/OWASP/CWE/GitHub data |
| `viewCacheStats` | Cache hit/miss statistics |
| `workspaceDashboard` | Workspace security dashboard |

**Key settings** (`codeGuardian.*`):

| Setting | Default | Purpose |
|---|---|---|
| `model` | `codellama:7b` | Ollama model (enum of ~29 tags) |
| `ollamaHost` | `http://localhost:11434` | Ollama server URL |
| `enableRAG` | `true` | Toggle RAG enrichment |
| `consensusPasses` | `2` | Parallel detection passes |
| `consensusMinAgreement` | `2` | Passes that must agree |
| `minConfidence` | `0` | Confidence gate for diagnostics |
| `importContext` | `false` | Append import/sink summary to prompt |
| `enableExternalDataFetch` | `false` | Allow outbound NVD/OWASP/CWE fetches |
| `requireSignedCorpus` | `true` | Refuse tampered RAG corpus |
| `enableAuditMode` | `true` | AST+LLM hybrid in dashboard |

---

## 12. Build, test, and release

- **Bundling** — [esbuild.js](../esbuild.js) produces a single CJS bundle `dist/extension.js`. `vscode` and the native `hnswlib-node` are kept external. An `import.meta.url` banner/`define` shim lets ESM-authored LangChain code run in the CJS bundle. `--production` minifies and drops sourcemaps.
- **Type-checking** — `tsc --noEmit` (strict, ES2022, Node16). esbuild owns the actual build; `tsc` only type-checks and compiles tests.
- **Testing** — unit tests run under Mocha + `ts-node` (`src/test/**/*.test.ts`); integration tests run in a real VS Code instance via `@vscode/test-electron`; coverage via `c8`.
- **Makefile** wraps the npm scripts: `make compile`, `make dev` (watch), `make test`, `make evaluate`, `make package`, `make release-patch`.
- **CI/CD** — [.github/workflows/publish.yml](../.github/workflows/) triggers on a `v*.*.*` tag: validate version → lint + test (xvfb) → `vsce package` → `vsce publish` → GitHub Release.

---

## 13. Evaluation harness (thesis)

The `evaluation/` directory is a standalone Node.js harness (`evaluate-models.js`) backing the thesis requirements R1–R5:

- **Datasets** — the headline corpus `vulnerability-test-cases.generated.json` has **101 cases (71 vulnerable / 30 secure)** across CWE categories, with per-case provenance documented in `SOURCES.md` (Juliet/OWASP-Benchmark are C/Java-only, so CWE-mapped JS/TS corpora — Juice Shop, NodeGoat, lodash — are substituted).
- **Metrics** — micro-aggregated **precision / recall / F1** on canonical categories, plus accuracy, false-positive rate, JSON parse-success rate (R2), latency (R4), and repair auto-applicable rate (R3).
- **Statistical rigor** — McNemar test with Bonferroni correction for RAG ablation, deterministic 70/30 split, fixed-seed reproducibility runs.
- **SAST baselines** — head-to-head against CodeQL, Semgrep, and ESLint-security.
- **Real-world** — whole-project recall on OWASP NodeGoat.
- **Reproducibility** — [Dockerfile](../Dockerfile) + [docker-compose.yml](../docker-compose.yml) run the harness against a loopback-bound `ollama/ollama` container with external fetch disabled and `--network=none`-style isolation.

The thesis maps these to: **R1** accuracy, **R2** consistency (structured output), **R3** repair quality, **R4** usability (latency/IDE), **R5** privacy (local execution, zero egress).

---

## 14. Design principles summary

1. **Privacy first** — local LLM + local embeddings, egress chokepoint defaulting to zero, signed RAG corpus. Code never leaves the machine.
2. **Determinism where it counts** — `temperature: 0`, fixed seeds, AST-based Stage 0, canonical category taxonomy shared between extension and harness.
3. **Reliability over raw model output** — constrained JSON schemas, tolerant parsing, multi-pass consensus, retry with backoff, syntax-validated repairs.
4. **Performance** — LRU cache, 800ms debounce, serial per-document coalescing, batched concurrency, lazy RAG and lazy repair generation, windowed repair context.
5. **Graceful degradation** — works offline with bundled data; RAG failures fall back to standard prompts; missing models surface actionable guidance.
