# Session Handoff Notes (Thesis Report)

## Goal (confirmed)

This thesis is about a **privacy-preserving VS Code secure coding assistant** for **vulnerability detection + repair** using **local LLMs** and **optional RAG**.

The repository initially contained leftover text from an unrelated “Invox / MUC-4 / template-filling” project. That content has now been removed from the LaTeX sources; the thesis narrative is aligned to Code Guardian.

## Repository map

- Main thesis LaTeX entry: `Template.tex`
- Chapters root: `src/chapters/`
- Prototype implementation (VS Code extension): `code-guardian/`

### Code Guardian architecture (from source)

- Extension entry: `code-guardian/src/extension.ts`
  - Real-time analysis via debounced document changes (800ms)
  - Commands for analyze selection/file, workspace dashboard scan, model selection
  - Optional RAG is lazily initialized on first use
  - Quick-fix application requires user confirmation
- LLM analyzer: `code-guardian/src/analyzer.ts`
  - Calls Ollama locally; enforces “JSON array only” response format
  - Post-processes response to extract JSON array if model emits extra text
  - Retry w/ exponential backoff for transient failures
  - Analysis cache integration
- RAG: `code-guardian/src/ragManager.ts`
  - Local vector store: `@langchain/community/vectorstores/hnswlib` (HNSW)
  - Local embeddings via Ollama: `nomic-embed-text` (default)
  - Security knowledge is persisted under the extension path (e.g., `security-knowledge/`)
  - Knowledge sources are refreshed via `VulnerabilityDataManager` with offline fallback
- Vulnerability knowledge updates: `code-guardian/src/vulnerabilityDataManager.ts`
  - Caches OWASP + CVEs + CWE + JS security entries on disk
  - Fetches public vulnerability metadata over HTTPS (no source code sent)
  - Has a minimal baseline knowledge fallback for offline operation
- Workspace scanning + dashboard:
  - Scanner: `code-guardian/src/workspaceScanner.ts`
  - Dashboard UI: `code-guardian/src/dashboardWebview.ts`, `code-guardian/media/*`
- Evaluation harness:
  - Script: `code-guardian/evaluation/evaluate-models.js`
  - Datasets: `code-guardian/evaluation/datasets/*.json`
  - Metrics: precision/recall/F1, parse success rate, response time

## What is already aligned in LaTeX

The following thesis sections are already written for Code Guardian:

- `src/chapters/implementation/tech_stack.tex`
- `src/chapters/implementation/system_workflow.tex`
- `src/chapters/implementation/strategy.tex`
- `src/chapters/implementation/agent.tex`
- `src/chapters/implementation/user_interface.tex`
- `src/chapters/evaluation/*` (structure + placeholders for metrics/tables)
- `src/chapters/conclusion.tex`
- `src/chapters/future_work.tex`
- `src/chapters/appendices/impl-details.tex`
- `src/chapters/appendices/eval-details.tex`
- `src/abbreviations.tex`

## Bibliography status

- Bibliography database: `bibliography.bib` now contains 76 entries.
- Rendered bibliography: the current PDF build prints 73 references (only cited works; no `\\nocite{*}`).
- Citation keys have been cleaned up across chapters; `latexmk` builds without “missing citation” / “missing bib entry” warnings.
- Note: OAuth RFC entries (`rfc6749`, `rfc6819`, `rfc7636`) are present in the `.bib` but intentionally uncited; cite them only if the thesis text actually discusses OAuth/PKCE.

## What is still pending (typical next session work)

Most of the remaining work is not “rewrite” but “fill with measured results / final polish”:

### Populate evaluation results

- The results tables in:
  - `src/chapters/evaluation/s1_result.tex`
  - `src/chapters/evaluation/s2_result.tex`
  - `src/chapters/evaluation/s3_result.tex`
  - `src/chapters/evaluation/s4_result.tex`
  are intentionally left as `--` placeholders; fill them with measured values from running the evaluation harness in `code-guardian/evaluation/`.

### Compile and fix LaTeX

- Run a full PDF build and fix any missing references/figures:
  - `latexmk -pdf Template.tex`
- Optional: keep figures purely about Code Guardian (currently the write-up is mostly text-only in the implementation/evaluation sections).

### Optional: add external baselines

If you have Semgrep/CodeQL results, add them as additional baselines in the Evaluation chapter (otherwise keep the evaluation scoped to Code Guardian’s harness).

## Important narrative alignment notes (for later edits)

- The thesis claims “zero code exfiltration” and often implies “fully offline”.
  - Code Guardian analysis is local via Ollama (good).
  - Vulnerability knowledge updates may fetch public data from OWASP/NVD.
  - The write-up should present this clearly as:
    - analysis is always local and does not transmit source code; and
    - knowledge updates are optional, fetch only public data, then cached for offline use.

## Suggested next editing order

1. Run the evaluation harness (`code-guardian/evaluation/`) for the target model set and capture metrics.
2. Fill `src/chapters/evaluation/s1_result.tex`–`src/chapters/evaluation/s4_result.tex` tables.
3. Run `latexmk -pdf Template.tex` and resolve any LaTeX warnings/errors.

## Commands to validate locally

- Build LaTeX PDF: `latexmk -pdf Template.tex` (or your existing build task)
- Quick grep for leftover strings:
  - `rg -n "Invox|MUC-4|Whisper|template-filling" src/` (should be empty)
