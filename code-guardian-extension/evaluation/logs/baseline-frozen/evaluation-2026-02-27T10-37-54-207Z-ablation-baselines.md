# Code Guardian Model Evaluation Report

**Date:** 2026-02-27T10:37:54.227Z

**Test Cases:** 113 (113 vulnerable, 0 secure/negative)

## Model Summary

| Model | Digest | Prompt Mode | Precision | Recall | F1 | FPR | Parse Rate | Mean Latency | Median Latency | Runs/Sample |
|-------|--------|-------------|-----------|--------|----|-----|------------|--------------|----------------|-------------|
| qwen3:8b | 500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41 | LLM+RAG | 63.66% | 64.60% | 64.13% | 100.00% | 100.00% | 1827ms | 1524ms | 3 |
| qwen3:4b | 359d7dd4bcdab3d86b87d73ac27966f4dbb9f5efdfcc75d34a8764a09474fae7 | LLM+RAG | 55.70% | 64.90% | 59.95% | 100.00% | 100.00% | 1390ms | 1087ms | 3 |
| qwen3:8b | 500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41 | LLM-only | 54.62% | 62.83% | 58.44% | 100.00% | 100.00% | 1909ms | 1548ms | 3 |
| gemma3:4b | a2af6cc3eb7fa8be8504abaf9b04e88f17a119ec3f04a3addf55f92841195f5a | LLM-only | 52.46% | 62.83% | 57.18% | 100.00% | 100.00% | 2290ms | 1932ms | 3 |
| qwen3:4b | 359d7dd4bcdab3d86b87d73ac27966f4dbb9f5efdfcc75d34a8764a09474fae7 | LLM-only | 50.47% | 62.83% | 55.98% | 100.00% | 100.00% | 1440ms | 1178ms | 3 |
| gemma3:4b | a2af6cc3eb7fa8be8504abaf9b04e88f17a119ec3f04a3addf55f92841195f5a | LLM+RAG | 45.63% | 56.93% | 50.66% | 100.00% | 100.00% | 2183ms | 1744ms | 3 |
| CodeLlama:latest | 8fdf8f752f6e80de33e82f381aba784c025982752cd1ae9377add66449d2225f | LLM-only | 39.90% | 46.02% | 42.74% | 100.00% | 100.00% | 1782ms | 1314ms | 3 |
| gemma3:1b | 8648f39daa8fbf5b18c7b4e6a8fb4990c692751d49917417b8842ca5758e7ffc | LLM+RAG | 31.91% | 44.25% | 37.08% | 100.00% | 99.71% | 1157ms | 881ms | 3 |
| gemma3:1b | 8648f39daa8fbf5b18c7b4e6a8fb4990c692751d49917417b8842ca5758e7ffc | LLM-only | 49.71% | 25.66% | 33.85% | 100.00% | 100.00% | 626ms | 333ms | 3 |
| CodeLlama:latest | 8fdf8f752f6e80de33e82f381aba784c025982752cd1ae9377add66449d2225f | LLM+RAG | 30.08% | 34.51% | 32.14% | 100.00% | 100.00% | 1836ms | 1347ms | 3 |
| semgrep | N/A | SAST baseline | 61.11% | 9.73% | 16.79% | 100.00% | 100.00% | 52ms | 52ms | 1 |
| codeql | N/A | SAST baseline | 17.74% | 9.73% | 12.57% | 100.00% | 100.00% | 146ms | 146ms | 1 |
| eslint-security | N/A | SAST baseline | 0.00% | 0.00% | 0.00% | 0.00% | 100.00% | 1ms | 1ms | 1 |

## Configuration

- **Evaluation Mode:** ablation
- **LLM Evaluation:** enabled
- **Prompt Modes:** LLM-only, LLM+RAG
- **Baseline Comparison:** enabled
- **Baseline Tools (requested):** codeql, semgrep, eslint-security
- **Baseline Tools (completed):** codeql, semgrep, eslint-security
- **Baseline Timeout:** 180000ms
- **RAG Strategy:** static_security_snippets
- **RAG k:** 5
- **Structured Output:** enabled
- **Thinking Mode:** disabled
- **Temperature:** 0.1
- **Num Predict:** 1000
- **Runs per Sample:** 3
- **Timeout:** 30000ms
- **Inter-request Delay:** 500ms
- **Dataset Path:** /Users/hafiz/personal/repos/tuc-master-thesis/code-guardian-extension/evaluation/datasets/all-test-cases.generated.json

## Execution Environment

- **OS:** darwin 25.3.0 (arm64)
- **Node.js:** v20.19.5
- **Ollama:** ollama version is 0.17.1
- **CPU:** Apple M4 Max (16 cores)
- **RAM (Total):** 64 GB
- **RAM (Free at Start):** 13.84 GB
- **GPU:** not captured by this script (Ollama backend dependent)
- **Started At:** 2026-02-27T08:36:19.191Z
- **Finished At:** 2026-02-27T10:37:54.207Z
- **Duration:** 7295016 ms

## Detailed Metrics

### qwen3:8b (LLM+RAG)

- **Requested Model:** qwen3:8b
- **Resolved Model:** qwen3:8b
- **Model Digest:** 500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41
- **Model Modified At:** 2026-02-25T11:19:39.425460804+01:00
- **True Positives:** 219
- **False Positives:** 125
- **False Negatives:** 120
- **True Negatives:** 0
- **Precision:** 63.66%
- **Recall:** 64.60%
- **F1 Score:** 64.13%
- **FPR:** 100.00%
- **Parse Rate:** 100.00%
- **Parse Failure Reasons:** none
- **Mean Latency:** 1827 ms
- **Median Latency:** 1524 ms
- **Line Accuracy:** 97.32%
- **Runs per Sample:** 3
- **RAG k:** 5

### qwen3:4b (LLM+RAG)

- **Requested Model:** qwen3:4b
- **Resolved Model:** qwen3:4b
- **Model Digest:** 359d7dd4bcdab3d86b87d73ac27966f4dbb9f5efdfcc75d34a8764a09474fae7
- **Model Modified At:** 2026-02-25T11:20:14.214022954+01:00
- **True Positives:** 220
- **False Positives:** 175
- **False Negatives:** 119
- **True Negatives:** 0
- **Precision:** 55.70%
- **Recall:** 64.90%
- **F1 Score:** 59.95%
- **FPR:** 100.00%
- **Parse Rate:** 100.00%
- **Parse Failure Reasons:** none
- **Mean Latency:** 1390 ms
- **Median Latency:** 1087 ms
- **Line Accuracy:** 92.04%
- **Runs per Sample:** 3
- **RAG k:** 5

### qwen3:8b (LLM-only)

- **Requested Model:** qwen3:8b
- **Resolved Model:** qwen3:8b
- **Model Digest:** 500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41
- **Model Modified At:** 2026-02-25T11:19:39.425460804+01:00
- **True Positives:** 213
- **False Positives:** 177
- **False Negatives:** 126
- **True Negatives:** 0
- **Precision:** 54.62%
- **Recall:** 62.83%
- **F1 Score:** 58.44%
- **FPR:** 100.00%
- **Parse Rate:** 100.00%
- **Parse Failure Reasons:** none
- **Mean Latency:** 1909 ms
- **Median Latency:** 1548 ms
- **Line Accuracy:** 95.58%
- **Runs per Sample:** 3
- **RAG k:** 0

### gemma3:4b (LLM-only)

- **Requested Model:** gemma3:4b
- **Resolved Model:** gemma3:4b
- **Model Digest:** a2af6cc3eb7fa8be8504abaf9b04e88f17a119ec3f04a3addf55f92841195f5a
- **Model Modified At:** 2026-02-25T11:23:23.073516066+01:00
- **True Positives:** 213
- **False Positives:** 193
- **False Negatives:** 126
- **True Negatives:** 0
- **Precision:** 52.46%
- **Recall:** 62.83%
- **F1 Score:** 57.18%
- **FPR:** 100.00%
- **Parse Rate:** 100.00%
- **Parse Failure Reasons:** none
- **Mean Latency:** 2290 ms
- **Median Latency:** 1932 ms
- **Line Accuracy:** 91.52%
- **Runs per Sample:** 3
- **RAG k:** 0

### qwen3:4b (LLM-only)

- **Requested Model:** qwen3:4b
- **Resolved Model:** qwen3:4b
- **Model Digest:** 359d7dd4bcdab3d86b87d73ac27966f4dbb9f5efdfcc75d34a8764a09474fae7
- **Model Modified At:** 2026-02-25T11:20:14.214022954+01:00
- **True Positives:** 213
- **False Positives:** 209
- **False Negatives:** 126
- **True Negatives:** 0
- **Precision:** 50.47%
- **Recall:** 62.83%
- **F1 Score:** 55.98%
- **FPR:** 100.00%
- **Parse Rate:** 100.00%
- **Parse Failure Reasons:** none
- **Mean Latency:** 1440 ms
- **Median Latency:** 1178 ms
- **Line Accuracy:** 93.51%
- **Runs per Sample:** 3
- **RAG k:** 0

### gemma3:4b (LLM+RAG)

- **Requested Model:** gemma3:4b
- **Resolved Model:** gemma3:4b
- **Model Digest:** a2af6cc3eb7fa8be8504abaf9b04e88f17a119ec3f04a3addf55f92841195f5a
- **Model Modified At:** 2026-02-25T11:23:23.073516066+01:00
- **True Positives:** 193
- **False Positives:** 230
- **False Negatives:** 146
- **True Negatives:** 0
- **Precision:** 45.63%
- **Recall:** 56.93%
- **F1 Score:** 50.66%
- **FPR:** 100.00%
- **Parse Rate:** 100.00%
- **Parse Failure Reasons:** none
- **Mean Latency:** 2183 ms
- **Median Latency:** 1744 ms
- **Line Accuracy:** 91.59%
- **Runs per Sample:** 3
- **RAG k:** 5

### CodeLlama:latest (LLM-only)

- **Requested Model:** CodeLlama:latest
- **Resolved Model:** CodeLlama:latest
- **Model Digest:** 8fdf8f752f6e80de33e82f381aba784c025982752cd1ae9377add66449d2225f
- **Model Modified At:** 2026-02-24T22:01:38.828690931+01:00
- **True Positives:** 156
- **False Positives:** 235
- **False Negatives:** 183
- **True Negatives:** 0
- **Precision:** 39.90%
- **Recall:** 46.02%
- **F1 Score:** 42.74%
- **FPR:** 100.00%
- **Parse Rate:** 100.00%
- **Parse Failure Reasons:** none
- **Mean Latency:** 1782 ms
- **Median Latency:** 1314 ms
- **Line Accuracy:** 91.89%
- **Runs per Sample:** 3
- **RAG k:** 0

### gemma3:1b (LLM+RAG)

- **Requested Model:** gemma3:1b
- **Resolved Model:** gemma3:1b
- **Model Digest:** 8648f39daa8fbf5b18c7b4e6a8fb4990c692751d49917417b8842ca5758e7ffc
- **Model Modified At:** 2026-02-22T10:02:01.827951066+01:00
- **True Positives:** 150
- **False Positives:** 320
- **False Negatives:** 189
- **True Negatives:** 0
- **Precision:** 31.91%
- **Recall:** 44.25%
- **F1 Score:** 37.08%
- **FPR:** 100.00%
- **Parse Rate:** 99.71%
- **Parse Failure Reasons:** non_json_content: 1
- **Mean Latency:** 1157 ms
- **Median Latency:** 881 ms
- **Line Accuracy:** 84.78%
- **Runs per Sample:** 3
- **RAG k:** 5

### gemma3:1b (LLM-only)

- **Requested Model:** gemma3:1b
- **Resolved Model:** gemma3:1b
- **Model Digest:** 8648f39daa8fbf5b18c7b4e6a8fb4990c692751d49917417b8842ca5758e7ffc
- **Model Modified At:** 2026-02-22T10:02:01.827951066+01:00
- **True Positives:** 87
- **False Positives:** 88
- **False Negatives:** 252
- **True Negatives:** 0
- **Precision:** 49.71%
- **Recall:** 25.66%
- **F1 Score:** 33.85%
- **FPR:** 100.00%
- **Parse Rate:** 100.00%
- **Parse Failure Reasons:** none
- **Mean Latency:** 626 ms
- **Median Latency:** 333 ms
- **Line Accuracy:** 77.85%
- **Runs per Sample:** 3
- **RAG k:** 0

### CodeLlama:latest (LLM+RAG)

- **Requested Model:** CodeLlama:latest
- **Resolved Model:** CodeLlama:latest
- **Model Digest:** 8fdf8f752f6e80de33e82f381aba784c025982752cd1ae9377add66449d2225f
- **Model Modified At:** 2026-02-24T22:01:38.828690931+01:00
- **True Positives:** 117
- **False Positives:** 272
- **False Negatives:** 222
- **True Negatives:** 0
- **Precision:** 30.08%
- **Recall:** 34.51%
- **F1 Score:** 32.14%
- **FPR:** 100.00%
- **Parse Rate:** 100.00%
- **Parse Failure Reasons:** none
- **Mean Latency:** 1836 ms
- **Median Latency:** 1347 ms
- **Line Accuracy:** 87.76%
- **Runs per Sample:** 3
- **RAG k:** 5

### semgrep (SAST baseline)

- **Requested Model:** semgrep
- **Resolved Model:** semgrep
- **Model Digest:** N/A
- **Model Modified At:** N/A
- **True Positives:** 11
- **False Positives:** 7
- **False Negatives:** 102
- **True Negatives:** 0
- **Precision:** 61.11%
- **Recall:** 9.73%
- **F1 Score:** 16.79%
- **FPR:** 100.00%
- **Parse Rate:** 100.00%
- **Parse Failure Reasons:** none
- **Mean Latency:** 52 ms
- **Median Latency:** 52 ms
- **Line Accuracy:** 100.00%
- **Runs per Sample:** 1
- **RAG k:** 0

### codeql (SAST baseline)

- **Requested Model:** codeql
- **Resolved Model:** codeql
- **Model Digest:** N/A
- **Model Modified At:** N/A
- **True Positives:** 11
- **False Positives:** 51
- **False Negatives:** 102
- **True Negatives:** 0
- **Precision:** 17.74%
- **Recall:** 9.73%
- **F1 Score:** 12.57%
- **FPR:** 100.00%
- **Parse Rate:** 100.00%
- **Parse Failure Reasons:** none
- **Mean Latency:** 146 ms
- **Median Latency:** 146 ms
- **Line Accuracy:** 100.00%
- **Runs per Sample:** 1
- **RAG k:** 0

### eslint-security (SAST baseline)

- **Requested Model:** eslint-security
- **Resolved Model:** eslint-security
- **Model Digest:** N/A
- **Model Modified At:** N/A
- **True Positives:** 0
- **False Positives:** 0
- **False Negatives:** 113
- **True Negatives:** 0
- **Precision:** 0.00%
- **Recall:** 0.00%
- **F1 Score:** 0.00%
- **FPR:** 0.00%
- **Parse Rate:** 100.00%
- **Parse Failure Reasons:** none
- **Mean Latency:** 1 ms
- **Median Latency:** 1 ms
- **Line Accuracy:** N/A%
- **Runs per Sample:** 1
- **RAG k:** 0


## Qualitative Case Studies (S4 Evidence)

Model under study: **qwen3:8b (LLM+RAG)**

### Case 1: TP - SQL Injection - SQL injection via string concatenation (OWASP Benchmark)

- **Type:** TP
- **Run:** 1
- **Outcome:** TP=1, FP=0, FN=0
- **Repair quality note:** Correctly detected vulnerability with actionable repair guidance.
- **Expected repair:** Use parameterized SQL queries or prepared statements.
- **Model repair suggestion:** Use parameterized queries or prepared statements to prevent SQL injection. Example: const query = 'SELECT * FROM products WHERE name LIKE ?'; db.all(query, [`%${searchTerm}%`], ......

### Case 2: FN - Insecure Deserialization - Unsafe deserialization in session handling

- **Type:** FN
- **Run:** 1
- **Outcome:** TP=0, FP=1, FN=1
- **Repair quality note:** Partially detected issues but still missed expected vulnerability classes.
- **Expected repair:** Use safe serializers or strict type/schema validation.
- **Model repair suggestion:** Use a safe deserialization library that can handle untrusted data without executing arbitrary code.

### Case 3: TP - SQL Injection - SQL injection via template literals (OWASP Benchmark)

- **Type:** TP
- **Run:** 1
- **Outcome:** TP=1, FP=0, FN=0
- **Repair quality note:** Correctly detected vulnerability with actionable repair guidance.
- **Expected repair:** Use parameterized SQL queries or prepared statements.
- **Model repair suggestion:** Use parameterized queries instead of template literals. Example: const sql = 'SELECT id, role FROM users WHERE username=? AND password=?'; connection.query(sql, [username, password...

### Case 4: TP - Cross-Site Scripting (XSS) - XSS via innerHTML assignment (OWASP Benchmark)

- **Type:** TP
- **Run:** 1
- **Outcome:** TP=1, FP=0, FN=0
- **Repair quality note:** Correctly detected vulnerability with actionable repair guidance.
- **Expected repair:** Escape/sanitize untrusted content and avoid unsafe DOM sinks.
- **Model repair suggestion:** Use textContent or sanitize input before using innerHTML.

## Post-Hoc Negatives Merge (No Rerun)

This section merges this full run (`113` vulnerable cases) with the existing negatives-only run
(`15` secure/negative cases) to include meaningful TN/FPR without running the full experiment again.

- Full run source: `/Users/hafiz/personal/repos/tuc-master-thesis/code-guardian-extension/evaluation/logs/evaluation-2026-02-27T10-37-54-207Z-ablation-baselines.json`
- Negatives source: `/Users/hafiz/personal/repos/tuc-master-thesis/code-guardian-extension/evaluation/logs/evaluation-2026-02-27T10-51-51-455Z-ablation-baselines.json`
- Merged report source: `/Users/hafiz/personal/repos/tuc-master-thesis/code-guardian-extension/evaluation/logs/evaluation-2026-02-27T11-11-55-716Z-merged-existing-negatives.md`
- Caveat: full run uses `runs=3` and negatives run uses `runs=1`; merged counts are post-hoc.

**Effective Combined Dataset:** `128` cases (`113` vulnerable + `15` secure/negative)

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
