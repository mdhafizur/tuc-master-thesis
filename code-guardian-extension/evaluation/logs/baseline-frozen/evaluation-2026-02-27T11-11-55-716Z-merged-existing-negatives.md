# Code Guardian Merged Evaluation Report (Existing Runs + Negatives)

**Date:** 2026-02-27T11:11:55.717Z

**Method:** Post-hoc merge of existing reports (no rerun)

- Full run source: /Users/hafiz/personal/repos/tuc-master-thesis/code-guardian-extension/evaluation/logs/evaluation-2026-02-27T10-37-54-207Z-ablation-baselines.json
- Negatives run source: /Users/hafiz/personal/repos/tuc-master-thesis/code-guardian-extension/evaluation/logs/evaluation-2026-02-27T10-51-51-455Z-ablation-baselines.json
- Caveat: full run used `runs=3` and negatives run used `runs=1`; counts are merged as observed.

**Effective Combined Dataset:** 128 cases (113 vulnerable + 15 secure/negative)

## Merged Summary

| Model | Prompt Mode | Precision | Recall | F1 | Accuracy | FPR | Parse Rate | TP | FP | FN | TN |
|-------|-------------|-----------|--------|----|----------|-----|------------|----|----|----|----|
| qwen3:8b | LLM+RAG | 62.93% | 64.60% | 63.76% | 48.02% | 92.14% | 100.00% | 219 | 129 | 120 | 11 |
| qwen3:4b | LLM+RAG | 53.53% | 64.90% | 58.67% | 41.51% | 100.00% | 100.00% | 220 | 191 | 119 | 0 |
| qwen3:8b | LLM-only | 54.06% | 62.83% | 58.12% | 42.18% | 94.27% | 100.00% | 213 | 181 | 126 | 11 |
| gemma3:4b | LLM-only | 50.59% | 62.83% | 56.05% | 38.94% | 100.00% | 100.00% | 213 | 208 | 126 | 0 |
| qwen3:4b | LLM-only | 48.74% | 62.83% | 54.90% | 37.83% | 100.00% | 100.00% | 213 | 224 | 126 | 0 |
| gemma3:4b | LLM+RAG | 44.06% | 56.93% | 49.68% | 33.05% | 100.00% | 100.00% | 193 | 245 | 146 | 0 |
| CodeLlama:latest | LLM-only | 38.42% | 46.02% | 41.88% | 26.49% | 100.00% | 100.00% | 156 | 250 | 183 | 0 |
| gemma3:1b | LLM+RAG | 30.49% | 44.25% | 36.10% | 22.03% | 100.00% | 99.72% | 150 | 342 | 189 | 0 |
| gemma3:1b | LLM-only | 45.31% | 25.66% | 32.77% | 19.59% | 100.00% | 100.00% | 87 | 105 | 252 | 0 |
| CodeLlama:latest | LLM+RAG | 28.89% | 34.51% | 31.45% | 18.66% | 100.00% | 100.00% | 117 | 288 | 222 | 0 |
| semgrep | SAST baseline | 57.89% | 9.73% | 16.67% | 18.52% | 36.36% | 100.00% | 11 | 8 | 102 | 14 |
| codeql | SAST baseline | 15.71% | 9.73% | 12.02% | 10.06% | 89.39% | 100.00% | 11 | 59 | 102 | 7 |
| eslint-security | SAST baseline | 0.00% | 0.00% | 0.00% | 11.72% | 0.00% | 100.00% | 0 | 0 | 113 | 15 |

## Notes

- This merged report resolves the earlier FPR blind spot by adding secure negatives.
- It is suitable for comparative analysis without another full 2-hour run.
- For publication-grade final numbers, a single unified run on the 128-case dataset with one consistent runs-per-sample setting is still preferred.
