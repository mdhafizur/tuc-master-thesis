# Thesis Sections — Review Needed

These sections were **not modified** by Claude and may need updates to align with the current state of the system and evaluation.

---

## 1. Introduction (`src/chapters/introduction.tex`)
- **Lines:** 82
- **Current state:** Covers motivation, problem statement, 3 research questions, threat model, contributions, methodology, chapter outline.
- **What to check:**
  - Requirements are now R1–R5 (was previously 7). Verify any references to requirement count.
  - Contributions list should mention: multi-pass consensus filtering, JSON-mode enforcement, two-stage repair pipeline, expanded secure dataset.
  - Research questions may need rewording to match the 5-requirement structure.

## 2. Conclusion (`src/chapters/conclusion.tex`)
- **Lines:** 86
- **Current state:** Summarizes outcomes, answers 3 research questions, deployment profiles table, limitations, future work.
- **What to check:**
  - Evaluation numbers are outdated (F1=63.76% → 65.31%, FPR=26.67% → 20.00%, parse rate=99.4% → 100%).
  - Should mention new engineering contributions (consensus filtering, two-stage repair, JSON mode).
  - Future work should reference: larger models, hybrid SAST+LLM pipeline, user study.
  - Deployment profiles table may need latency updates (median 1.5s → 2.7s).

## 3. Concept (`src/chapters/concept/concept.tex` + sub-files)
- **Lines:** 20 (intro only; delegates to sub-files)
- **Sub-files:** `concept_derivations.tex`, `components.tex`, `strategies.tex`, `system_architecture_and_design.tex`
- **What to check:**
  - Verify requirement references use R1–R5 (not old R1–R7 numbering).
  - Architecture description should reflect: multi-pass consensus, two-stage repair pipeline, JSON-mode decoding.
  - If RAG is described, confirm it matches the current model-dependent findings.

## 4. Implementation (`src/chapters/implementation/implementation.tex` + sub-files)
- **Lines:** 94 (intro; delegates to sub-files)
- **Sub-files:** `tech_stack.tex`, `system_workflow.tex`, `strategy.tex`, `user_interface.tex`, `repair_safety.tex`, `agent.tex`
- **What to check:**
  - Detection pipeline should now mention: consensus filtering (2 passes, different seeds), JSON-mode enforcement, seed=42 for determinism.
  - Repair section should describe the two-stage pipeline (detection prompt → repair prompt).
  - Temperature should be documented as 0 (not 0.1).
  - Verify requirement references use R1–R5.

## 5. Evaluation — Dataset Details (`src/chapters/evaluation/dataset_details.tex`)
- **Lines:** 77
- **Current state:** Describes 128 test cases (113 vulnerable, 15 secure).
- **What to update:**
  - Dataset is now **101 test cases (71 vulnerable, 30 secure)** after expanding secure samples.
  - The 15 new secure cases are sourced from OWASP Cheat Sheets, CWE mitigations, and Node.js security best practices.
  - Update the dataset composition table/numbers accordingly.
  - Mention that secure samples were doubled to improve FPR confidence intervals.

## 6. Evaluation — Metrics (`src/chapters/evaluation/evaluation_metrics.tex`)
- **Lines:** 58
- **Current state:** Defines precision, recall, F1, FPR, parse success, latency.
- **What to check:**
  - Likely fine as-is — metric definitions don't change.
  - Optionally add a note about consensus-filtered metrics if you report those separately.

## 7. Evaluation — Experimental Setup (`src/chapters/evaluation/experimental_setup.tex`)
- **Lines:** 177
- **Current state:** Documents 113+15 dataset, temperature=0.1, 5 models, 3 baselines, hardware.
- **What to update:**
  - Temperature is now **0** (not 0.1).
  - Add: **seed=42** for deterministic inference.
  - Add: **JSON-mode decoding** (`format: 'json'`) for structured output enforcement.
  - Dataset size changed: now **71 vulnerable + 30 secure = 101 total**.
  - Mention the `--limit` and `--model` flags added to the evaluation harness.

---

## Orphaned Files (not included in Template.tex)

These files exist on disk but are **not compiled** into the thesis. They can be deleted or archived:

- `src/chapters/analysis/requirements/r6.tex`
- `src/chapters/analysis/requirements/r7.tex`
- `src/chapters/evaluation/s1_result.tex`
- `src/chapters/evaluation/s2_result.tex`
- `src/chapters/evaluation/s3_result.tex`
- `src/chapters/evaluation/s4_result.tex`
- `src/chapters/evaluation/summary.tex` (replaced by `eval_summary.tex`)
- `src/chapters/future_work.tex` (if folded into conclusion)
