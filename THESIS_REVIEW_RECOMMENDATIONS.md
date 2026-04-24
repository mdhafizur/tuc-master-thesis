# Thesis Review Recommendations

Compiled from a full review of all chapters. Grouped by priority.

---

## High Priority

### 1. FPR confidence intervals not stated numerically
- **Location:** [eval_summary.tex:60-61](code-guardian-thesis-report/src/chapters/evaluation/eval_summary.tex#L60-L61), [eval_r1_accuracy.tex:252-254](code-guardian-thesis-report/src/chapters/evaluation/eval_r1_accuracy.tex#L252-L254)
- **Problem:** The 20% FPR from 30 secure samples has a 95% CI of roughly [7%, 39%]. The thesis acknowledges the small sample but never states the confidence interval numerically. FPR=100% configs similarly deserve a note that 30/30 flagged means the CI lower bound is ~88%.
- **Fix:** Add a sentence after the FPR results stating the exact binomial confidence interval for the best config and for the 100% cases. Example: "With $n=30$, the 95\% exact binomial confidence interval for 20\% FPR is [7.7\%, 38.6\%]."

### 2. R3 evaluation rigor is weak (n=25, no inter-rater reliability)
- **Location:** [eval_r3_repair.tex](code-guardian-thesis-report/src/chapters/evaluation/eval_r3_repair.tex) (entire section)
- **Problem:** Only 25 samples manually reviewed by a single rater. No inter-rater agreement reported. This is the least rigorous of the five requirement evaluations.
- **Fix:**
  - Add a paragraph in R3 explicitly stating this as a limitation: "All repair assessments were performed by a single reviewer. Inter-rater reliability was not measured, which limits the generalizability of the quality ratings."
  - In the eval_summary limitations section, add inter-rater reliability as a bullet.
  - In future work, mention that a two-rater protocol with Cohen's kappa would strengthen R3 evidence.

### 3. Pie-chart visual encoding in positioning table lacks legend
- **Location:** [positioning.tex:42-111](code-guardian-thesis-report/src/chapters/analysis/related_works/positioning.tex#L42-L111) (Table `positioning-r1r5`)
- **Problem:** The filled/half-filled/empty circle visual encoding is used without a legend. A reader encountering this table for the first time cannot decode the ratings.
- **Fix:** Add a legend row or footnote below the table explaining: full circle = High, three-quarter = Medium-High, half = Medium, quarter = Low, empty = Insufficient/None.

---

## Medium Priority

### 4. Result preview in introduction objectives section
- **Location:** [introduction.tex:107](code-guardian-thesis-report/src/chapters/introduction.tex#L107)
- **Problem:** The sentence "In this thesis run, `qwen3:8b` with RAG provides the strongest overall trade-off..." previews a specific quantitative result before the reader has context to evaluate it. This is unusual for an introduction.
- **Fix:** Either remove the sentence entirely, or soften to: "Chapter~\ref{chap:evaluation} identifies the strongest configuration among those tested and reports its trade-offs."

### 5. No strict vs. relaxed scoring comparison table
- **Location:** [eval_r1_accuracy.tex:249-250](code-guardian-thesis-report/src/chapters/evaluation/eval_r1_accuracy.tex#L249-L250)
- **Problem:** The corrected recall estimate (adding 11 label-mismatch cases back) is mentioned only in prose ("overall recall would increase by approximately 5 percentage points"). A table would make this finding much more visible and impactful.
- **Fix:** Add a small table after the error analysis showing side-by-side metrics for `qwen3:8b+RAG` under strict type-matching vs. relaxed sample-level matching (did the model flag *any* relevant issue?). Two rows, four columns (Precision, Recall, F1, FPR).

### 6. Latency mean inversion unexplained
- **Location:** [eval_r4_usability.tex:25-26](code-guardian-thesis-report/src/chapters/evaluation/eval_r4_usability.tex#L25-L26)
- **Problem:** For `qwen3:8b`, LLM-only mean latency (3,170ms) is *higher* than LLM+RAG mean (3,094ms), which is counterintuitive since RAG adds retrieval overhead. The medians show the expected pattern (2,593 < 2,721).
- **Fix:** Add a brief note: "The mean inversion for \texttt{qwen3:8b} (LLM-only mean slightly exceeds LLM+RAG mean) reflects a small number of high-latency outliers in the LLM-only run rather than a systematic effect; the median shows the expected pattern."

### 7. Future work formatting inconsistency
- **Location:** [future_work.tex](code-guardian-thesis-report/src/chapters/future_work.tex)
- **Problem:** The first part uses numbered bold items separated by `\medskip`, while the second part uses `\subsection*{Open Research Questions}` with bold items separated by `\medskip`. Mixing these styles within a single section looks inconsistent.
- **Fix:** Standardize to one format. Recommendation: use numbered bold items throughout (matching the first half), and introduce the open research questions with a paragraph rather than a subsection heading (since this content is already inside a `\section{Future Work}` in the conclusion chapter).

### 8. RESCUE R5 entry unexplained
- **Location:** [positioning.tex:92](code-guardian-thesis-report/src/chapters/analysis/related_works/positioning.tex#L92)
- **Problem:** RESCUE has "---" for R5 (Privacy) in the comparison table with no explanation.
- **Fix:** Add a table footnote: "--- indicates that the property was not evaluated or reported in the original work."

---

## Low Priority

### 9. Acronym package loaded but unused
- **Location:** [Template.tex:19](code-guardian-thesis-report/Template.tex#L19)
- **Problem:** `\usepackage{acronym}` is loaded but terms like SAST, LLM, RAG, FPR, CWE, OWASP are never formally defined via the acronym package. German university theses typically require a list of abbreviations.
- **Fix:** Either (a) define acronyms and add a list of abbreviations before Chapter 1, or (b) remove the package if not required by the thesis template.

### 10. Responsible Use section is brief
- **Location:** [conclusion.tex:71-73](code-guardian-thesis-report/src/chapters/conclusion.tex#L71-L73)
- **Problem:** For a privacy-focused thesis, the responsible use section is only 3 sentences. It could discuss evolving implications as local models improve, dual-use concerns (attacker using the tool to find vulnerabilities to exploit), or organizational governance considerations.
- **Fix:** Expand by 1-2 paragraphs. Possible additions:
  - As local models approach cloud-model quality, the privacy advantage grows but so does the potential for misuse (using the tool to identify rather than fix vulnerabilities).
  - Organizations deploying Code Guardian should establish policies for how LLM-generated findings are triaged and how repair suggestions are reviewed before merging.

### 11. No abstract visible in chapter files
- **Location:** Likely in [Template.tex](code-guardian-thesis-report/Template.tex) front matter
- **Action:** Verify an abstract exists. If missing, write one (typically 150-300 words covering problem, approach, key results).

### 12. Appendices not mentioned in thesis outline
- **Location:** [introduction.tex:109-117](code-guardian-thesis-report/src/chapters/introduction.tex#L109-L117)
- **Problem:** The thesis outline paragraph describes all main chapters but does not mention the appendices (prompt templates, case studies, eval details, privacy verification).
- **Fix:** Add a closing sentence: "Appendices provide supplementary material including prompt templates, detailed evaluation data, and privacy verification evidence."

### 13. R3 evaluation scale has 3 levels vs. 4 for R1/R2
- **Location:** [r3.tex](code-guardian-thesis-report/src/chapters/analysis/requirements/r3.tex)
- **Problem:** R1 has 4 levels (High/Medium/Low/Insufficient), R2 has 4 levels, but R3 has only 3 (High/Medium/Low). This asymmetry is unexplained.
- **Fix:** Either add a brief justification for why R3 uses fewer levels (e.g., "Repair quality is assessed qualitatively, making fine-grained distinctions less meaningful") or add a fourth level for consistency.

### 14. Debounce/guard values lack rationale
- **Location:** Concept chapter, strategies section
- **Problem:** The 800ms debounce delay and 2000-character function guard are stated as design parameters but the rationale for these specific values is not given. Are they empirically tuned, borrowed from VS Code conventions, or based on HCI literature?
- **Fix:** Add a brief justification. E.g., "The 800ms debounce follows common VS Code extension practice for balancing responsiveness against unnecessary re-analysis" or cite any source/experiment.

---

## Optional Enhancements (Not Required)

- **Cloud LLM comparison:** Running the same 101 test cases through a cloud model (GPT-4, Claude) would contextualize the "local model penalty." Could be added as a future work item if not feasible now.
- **Table style consistency:** Some tables use `tabularx`, others `tabular`, with varying font sizes and row spacing. A pass to standardize visual style would improve readability.
- **Hedging tightening:** A few places use soft language where the evidence is clear. E.g., "The model appears unable to reason about..." could be "The model fails to reason about..." when backed by 0% recall data.
