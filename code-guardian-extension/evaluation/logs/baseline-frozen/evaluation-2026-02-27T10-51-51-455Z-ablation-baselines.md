# Code Guardian Model Evaluation Report

**Date:** 2026-02-27T10:51:51.457Z

**Test Cases:** 15 (0 vulnerable, 15 secure/negative)

## Model Summary

| Model | Digest | Prompt Mode | Precision | Recall | F1 | FPR | Parse Rate | Mean Latency | Median Latency | Runs/Sample |
|-------|--------|-------------|-----------|--------|----|-----|------------|--------------|----------------|-------------|
| gemma3:1b | 8648f39daa8fbf5b18c7b4e6a8fb4990c692751d49917417b8842ca5758e7ffc | LLM-only | 0.00% | 0.00% | 0.00% | 100.00% | 100.00% | 1036ms | 914ms | 1 |
| gemma3:1b | 8648f39daa8fbf5b18c7b4e6a8fb4990c692751d49917417b8842ca5758e7ffc | LLM+RAG | 0.00% | 0.00% | 0.00% | 100.00% | 100.00% | 1243ms | 1005ms | 1 |
| gemma3:4b | a2af6cc3eb7fa8be8504abaf9b04e88f17a119ec3f04a3addf55f92841195f5a | LLM-only | 0.00% | 0.00% | 0.00% | 100.00% | 100.00% | 1854ms | 1731ms | 1 |
| gemma3:4b | a2af6cc3eb7fa8be8504abaf9b04e88f17a119ec3f04a3addf55f92841195f5a | LLM+RAG | 0.00% | 0.00% | 0.00% | 100.00% | 100.00% | 1904ms | 1869ms | 1 |
| qwen3:4b | 359d7dd4bcdab3d86b87d73ac27966f4dbb9f5efdfcc75d34a8764a09474fae7 | LLM-only | 0.00% | 0.00% | 0.00% | 100.00% | 100.00% | 3394ms | 2131ms | 1 |
| qwen3:4b | 359d7dd4bcdab3d86b87d73ac27966f4dbb9f5efdfcc75d34a8764a09474fae7 | LLM+RAG | 0.00% | 0.00% | 0.00% | 100.00% | 100.00% | 1963ms | 1887ms | 1 |
| qwen3:8b | 500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41 | LLM-only | 0.00% | 0.00% | 0.00% | 26.67% | 100.00% | 818ms | 328ms | 1 |
| qwen3:8b | 500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41 | LLM+RAG | 0.00% | 0.00% | 0.00% | 26.67% | 100.00% | 628ms | 322ms | 1 |
| CodeLlama:latest | 8fdf8f752f6e80de33e82f381aba784c025982752cd1ae9377add66449d2225f | LLM-only | 0.00% | 0.00% | 0.00% | 100.00% | 100.00% | 1758ms | 1513ms | 1 |
| CodeLlama:latest | 8fdf8f752f6e80de33e82f381aba784c025982752cd1ae9377add66449d2225f | LLM+RAG | 0.00% | 0.00% | 0.00% | 100.00% | 100.00% | 1661ms | 1505ms | 1 |
| codeql | N/A | SAST baseline | 0.00% | 0.00% | 0.00% | 53.33% | 100.00% | 1030ms | 1030ms | 1 |
| semgrep | N/A | SAST baseline | 0.00% | 0.00% | 0.00% | 6.67% | 100.00% | 354ms | 354ms | 1 |
| eslint-security | N/A | SAST baseline | 0.00% | 0.00% | 0.00% | 0.00% | 100.00% | 8ms | 8ms | 1 |

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
- **Runs per Sample:** 1
- **Timeout:** 30000ms
- **Inter-request Delay:** 500ms
- **Dataset Path:** /Users/hafiz/personal/repos/tuc-master-thesis/code-guardian-extension/evaluation/datasets/negatives-only.generated.json

## Execution Environment

- **OS:** darwin 25.3.0 (arm64)
- **Node.js:** v20.19.5
- **Ollama:** ollama version is 0.17.1
- **CPU:** Apple M4 Max (16 cores)
- **RAM (Total):** 64 GB
- **RAM (Free at Start):** 21.51 GB
- **GPU:** not captured by this script (Ollama backend dependent)
- **Started At:** 2026-02-27T10:46:09.690Z
- **Finished At:** 2026-02-27T10:51:51.455Z
- **Duration:** 341765 ms

## Detailed Metrics

### gemma3:1b (LLM-only)

- **Requested Model:** gemma3:1b
- **Resolved Model:** gemma3:1b
- **Model Digest:** 8648f39daa8fbf5b18c7b4e6a8fb4990c692751d49917417b8842ca5758e7ffc
- **Model Modified At:** 2026-02-22T10:02:01.827951066+01:00
- **True Positives:** 0
- **False Positives:** 17
- **False Negatives:** 0
- **True Negatives:** 0
- **Precision:** 0.00%
- **Recall:** 0.00%
- **F1 Score:** 0.00%
- **FPR:** 100.00%
- **Parse Rate:** 100.00%
- **Parse Failure Reasons:** none
- **Mean Latency:** 1036 ms
- **Median Latency:** 914 ms
- **Line Accuracy:** 100.00%
- **Runs per Sample:** 1
- **RAG k:** 0

### gemma3:1b (LLM+RAG)

- **Requested Model:** gemma3:1b
- **Resolved Model:** gemma3:1b
- **Model Digest:** 8648f39daa8fbf5b18c7b4e6a8fb4990c692751d49917417b8842ca5758e7ffc
- **Model Modified At:** 2026-02-22T10:02:01.827951066+01:00
- **True Positives:** 0
- **False Positives:** 22
- **False Negatives:** 0
- **True Negatives:** 0
- **Precision:** 0.00%
- **Recall:** 0.00%
- **F1 Score:** 0.00%
- **FPR:** 100.00%
- **Parse Rate:** 100.00%
- **Parse Failure Reasons:** none
- **Mean Latency:** 1243 ms
- **Median Latency:** 1005 ms
- **Line Accuracy:** 100.00%
- **Runs per Sample:** 1
- **RAG k:** 5

### gemma3:4b (LLM-only)

- **Requested Model:** gemma3:4b
- **Resolved Model:** gemma3:4b
- **Model Digest:** a2af6cc3eb7fa8be8504abaf9b04e88f17a119ec3f04a3addf55f92841195f5a
- **Model Modified At:** 2026-02-25T11:23:23.073516066+01:00
- **True Positives:** 0
- **False Positives:** 15
- **False Negatives:** 0
- **True Negatives:** 0
- **Precision:** 0.00%
- **Recall:** 0.00%
- **F1 Score:** 0.00%
- **FPR:** 100.00%
- **Parse Rate:** 100.00%
- **Parse Failure Reasons:** none
- **Mean Latency:** 1854 ms
- **Median Latency:** 1731 ms
- **Line Accuracy:** 100.00%
- **Runs per Sample:** 1
- **RAG k:** 0

### gemma3:4b (LLM+RAG)

- **Requested Model:** gemma3:4b
- **Resolved Model:** gemma3:4b
- **Model Digest:** a2af6cc3eb7fa8be8504abaf9b04e88f17a119ec3f04a3addf55f92841195f5a
- **Model Modified At:** 2026-02-25T11:23:23.073516066+01:00
- **True Positives:** 0
- **False Positives:** 15
- **False Negatives:** 0
- **True Negatives:** 0
- **Precision:** 0.00%
- **Recall:** 0.00%
- **F1 Score:** 0.00%
- **FPR:** 100.00%
- **Parse Rate:** 100.00%
- **Parse Failure Reasons:** none
- **Mean Latency:** 1904 ms
- **Median Latency:** 1869 ms
- **Line Accuracy:** 100.00%
- **Runs per Sample:** 1
- **RAG k:** 5

### qwen3:4b (LLM-only)

- **Requested Model:** qwen3:4b
- **Resolved Model:** qwen3:4b
- **Model Digest:** 359d7dd4bcdab3d86b87d73ac27966f4dbb9f5efdfcc75d34a8764a09474fae7
- **Model Modified At:** 2026-02-25T11:20:14.214022954+01:00
- **True Positives:** 0
- **False Positives:** 15
- **False Negatives:** 0
- **True Negatives:** 0
- **Precision:** 0.00%
- **Recall:** 0.00%
- **F1 Score:** 0.00%
- **FPR:** 100.00%
- **Parse Rate:** 100.00%
- **Parse Failure Reasons:** none
- **Mean Latency:** 3394 ms
- **Median Latency:** 2131 ms
- **Line Accuracy:** 100.00%
- **Runs per Sample:** 1
- **RAG k:** 0

### qwen3:4b (LLM+RAG)

- **Requested Model:** qwen3:4b
- **Resolved Model:** qwen3:4b
- **Model Digest:** 359d7dd4bcdab3d86b87d73ac27966f4dbb9f5efdfcc75d34a8764a09474fae7
- **Model Modified At:** 2026-02-25T11:20:14.214022954+01:00
- **True Positives:** 0
- **False Positives:** 16
- **False Negatives:** 0
- **True Negatives:** 0
- **Precision:** 0.00%
- **Recall:** 0.00%
- **F1 Score:** 0.00%
- **FPR:** 100.00%
- **Parse Rate:** 100.00%
- **Parse Failure Reasons:** none
- **Mean Latency:** 1963 ms
- **Median Latency:** 1887 ms
- **Line Accuracy:** 100.00%
- **Runs per Sample:** 1
- **RAG k:** 5

### qwen3:8b (LLM-only)

- **Requested Model:** qwen3:8b
- **Resolved Model:** qwen3:8b
- **Model Digest:** 500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41
- **Model Modified At:** 2026-02-25T11:19:39.425460804+01:00
- **True Positives:** 0
- **False Positives:** 4
- **False Negatives:** 0
- **True Negatives:** 11
- **Precision:** 0.00%
- **Recall:** 0.00%
- **F1 Score:** 0.00%
- **FPR:** 26.67%
- **Parse Rate:** 100.00%
- **Parse Failure Reasons:** none
- **Mean Latency:** 818 ms
- **Median Latency:** 328 ms
- **Line Accuracy:** 25.00%
- **Runs per Sample:** 1
- **RAG k:** 0

### qwen3:8b (LLM+RAG)

- **Requested Model:** qwen3:8b
- **Resolved Model:** qwen3:8b
- **Model Digest:** 500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41
- **Model Modified At:** 2026-02-25T11:19:39.425460804+01:00
- **True Positives:** 0
- **False Positives:** 4
- **False Negatives:** 0
- **True Negatives:** 11
- **Precision:** 0.00%
- **Recall:** 0.00%
- **F1 Score:** 0.00%
- **FPR:** 26.67%
- **Parse Rate:** 100.00%
- **Parse Failure Reasons:** none
- **Mean Latency:** 628 ms
- **Median Latency:** 322 ms
- **Line Accuracy:** 50.00%
- **Runs per Sample:** 1
- **RAG k:** 5

### CodeLlama:latest (LLM-only)

- **Requested Model:** CodeLlama:latest
- **Resolved Model:** CodeLlama:latest
- **Model Digest:** 8fdf8f752f6e80de33e82f381aba784c025982752cd1ae9377add66449d2225f
- **Model Modified At:** 2026-02-24T22:01:38.828690931+01:00
- **True Positives:** 0
- **False Positives:** 15
- **False Negatives:** 0
- **True Negatives:** 0
- **Precision:** 0.00%
- **Recall:** 0.00%
- **F1 Score:** 0.00%
- **FPR:** 100.00%
- **Parse Rate:** 100.00%
- **Parse Failure Reasons:** none
- **Mean Latency:** 1758 ms
- **Median Latency:** 1513 ms
- **Line Accuracy:** 100.00%
- **Runs per Sample:** 1
- **RAG k:** 0

### CodeLlama:latest (LLM+RAG)

- **Requested Model:** CodeLlama:latest
- **Resolved Model:** CodeLlama:latest
- **Model Digest:** 8fdf8f752f6e80de33e82f381aba784c025982752cd1ae9377add66449d2225f
- **Model Modified At:** 2026-02-24T22:01:38.828690931+01:00
- **True Positives:** 0
- **False Positives:** 16
- **False Negatives:** 0
- **True Negatives:** 0
- **Precision:** 0.00%
- **Recall:** 0.00%
- **F1 Score:** 0.00%
- **FPR:** 100.00%
- **Parse Rate:** 100.00%
- **Parse Failure Reasons:** none
- **Mean Latency:** 1661 ms
- **Median Latency:** 1505 ms
- **Line Accuracy:** 100.00%
- **Runs per Sample:** 1
- **RAG k:** 5

### codeql (SAST baseline)

- **Requested Model:** codeql
- **Resolved Model:** codeql
- **Model Digest:** N/A
- **Model Modified At:** N/A
- **True Positives:** 0
- **False Positives:** 8
- **False Negatives:** 0
- **True Negatives:** 7
- **Precision:** 0.00%
- **Recall:** 0.00%
- **F1 Score:** 0.00%
- **FPR:** 53.33%
- **Parse Rate:** 100.00%
- **Parse Failure Reasons:** none
- **Mean Latency:** 1030 ms
- **Median Latency:** 1030 ms
- **Line Accuracy:** 100.00%
- **Runs per Sample:** 1
- **RAG k:** 0

### semgrep (SAST baseline)

- **Requested Model:** semgrep
- **Resolved Model:** semgrep
- **Model Digest:** N/A
- **Model Modified At:** N/A
- **True Positives:** 0
- **False Positives:** 1
- **False Negatives:** 0
- **True Negatives:** 14
- **Precision:** 0.00%
- **Recall:** 0.00%
- **F1 Score:** 0.00%
- **FPR:** 6.67%
- **Parse Rate:** 100.00%
- **Parse Failure Reasons:** none
- **Mean Latency:** 354 ms
- **Median Latency:** 354 ms
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
- **False Negatives:** 0
- **True Negatives:** 15
- **Precision:** 0.00%
- **Recall:** 0.00%
- **F1 Score:** 0.00%
- **FPR:** 0.00%
- **Parse Rate:** 100.00%
- **Parse Failure Reasons:** none
- **Mean Latency:** 8 ms
- **Median Latency:** 8 ms
- **Line Accuracy:** N/A%
- **Runs per Sample:** 1
- **RAG k:** 0


## Qualitative Case Studies (S4 Evidence)

Model under study: **gemma3:1b (LLM-only)**

### Case 1: FP - Secure Code - Parameterized Query (No Vulnerability)

- **Type:** FP
- **Run:** 1
- **Outcome:** TP=0, FP=1, FN=0
- **Repair quality note:** False alarm: model suggested repairs for a secure sample, indicating over-flagging behavior.
- **Expected repair:** N/A
- **Model repair suggestion:** Use parameterized queries or prepared statements to prevent SQL injection. Instead of directly embedding the `userId` into the query string, pass it as a separate parameter.

### Case 2: FP - Secure Code - textContent Usage (No Vulnerability)

- **Type:** FP
- **Run:** 1
- **Outcome:** TP=0, FP=1, FN=0
- **Repair quality note:** False alarm: model suggested repairs for a secure sample, indicating over-flagging behavior.
- **Expected repair:** N/A
- **Model repair suggestion:** Implement proper escaping or sanitization of the `userInput` before displaying it. Use a library like DOMPurify or a similar function to remove or encode potentially harmful charac...

### Case 3: FP - Secure Code - execFile with Array Arguments (No Vulnerability)

- **Type:** FP
- **Run:** 1
- **Outcome:** TP=0, FP=1, FN=0
- **Repair quality note:** False alarm: model suggested repairs for a secure sample, indicating over-flagging behavior.
- **Expected repair:** N/A
- **Model repair suggestion:** The code is vulnerable to command injection if the `dirName` input is not properly sanitized. The `execFile` function takes the command as a string. It's crucial to sanitize the in...

### Case 4: FP - Secure Code - bcrypt Password Hashing (No Vulnerability)

- **Type:** FP
- **Run:** 1
- **Outcome:** TP=0, FP=1, FN=0
- **Repair quality note:** False alarm: model suggested repairs for a secure sample, indicating over-flagging behavior.
- **Expected repair:** N/A
- **Model repair suggestion:** Implement a longer saltRounds value (e.g., 24 or more) and ensure the salt is generated and used for each password hash. Consider a salt generation strategy to prevent reuse.

