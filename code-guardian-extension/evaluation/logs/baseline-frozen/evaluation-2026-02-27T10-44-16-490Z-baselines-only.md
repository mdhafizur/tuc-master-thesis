# Code Guardian Model Evaluation Report

**Date:** 2026-02-27T10:44:16.492Z

**Test Cases:** 15 (0 vulnerable, 15 secure/negative)

## Model Summary

| Model | Digest | Prompt Mode | Precision | Recall | F1 | FPR | Parse Rate | Mean Latency | Median Latency | Runs/Sample |
|-------|--------|-------------|-----------|--------|----|-----|------------|--------------|----------------|-------------|
| codeql | N/A | SAST baseline | 0.00% | 0.00% | 0.00% | 53.33% | 100.00% | 992ms | 992ms | 1 |
| eslint-security | N/A | SAST baseline | 0.00% | 0.00% | 0.00% | 0.00% | 100.00% | 7ms | 7ms | 1 |

## Configuration

- **Evaluation Mode:** baselines-only
- **LLM Evaluation:** disabled
- **Prompt Modes:** LLM-only, LLM+RAG
- **Baseline Comparison:** enabled
- **Baseline Tools (requested):** codeql, semgrep, eslint-security
- **Baseline Tools (completed):** codeql, eslint-security
- **Baseline Timeout:** 180000ms
- **Baseline Tools (skipped):** semgrep (binary not available: semgrep)
- **RAG Strategy:** none
- **RAG k:** 0
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
- **Ollama:** Warning: could not connect to a running Ollama instance
Warning: client version is 0.17.1
- **CPU:** Apple M4 Max (16 cores)
- **RAM (Total):** 64 GB
- **RAM (Free at Start):** 21.86 GB
- **GPU:** not captured by this script (Ollama backend dependent)
- **Started At:** 2026-02-27T10:44:00.809Z
- **Finished At:** 2026-02-27T10:44:16.490Z
- **Duration:** 15681 ms

## Detailed Metrics

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
- **Mean Latency:** 992 ms
- **Median Latency:** 992 ms
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
- **Mean Latency:** 7 ms
- **Median Latency:** 7 ms
- **Line Accuracy:** N/A%
- **Runs per Sample:** 1
- **RAG k:** 0


## Qualitative Case Studies (S4 Evidence)

Model under study: **codeql (SAST baseline)**

### Case 1: FP - Secure Code - execFile with Array Arguments (No Vulnerability)

- **Type:** FP
- **Run:** 1
- **Outcome:** TP=0, FP=1, FN=0
- **Repair quality note:** False alarm without concrete fix guidance; likely low-confidence misclassification.
- **Expected repair:** N/A
- **Model repair suggestion:** No fix suggestion produced.

### Case 2: Mixed - Secure Code - Parameterized Query (No Vulnerability)

- **Type:** Mixed
- **Run:** 1
- **Outcome:** TP=0, FP=0, FN=0
- **Repair quality note:** Mixed outcome: includes both correct and incorrect detections.
- **Expected repair:** N/A
- **Model repair suggestion:** No fix suggestion produced.

### Case 3: Mixed - Secure Code - textContent Usage (No Vulnerability)

- **Type:** Mixed
- **Run:** 1
- **Outcome:** TP=0, FP=0, FN=0
- **Repair quality note:** Mixed outcome: includes both correct and incorrect detections.
- **Expected repair:** N/A
- **Model repair suggestion:** No fix suggestion produced.

### Case 4: FP - Secure Code - bcrypt Password Hashing (No Vulnerability)

- **Type:** FP
- **Run:** 1
- **Outcome:** TP=0, FP=1, FN=0
- **Repair quality note:** False alarm without concrete fix guidance; likely low-confidence misclassification.
- **Expected repair:** N/A
- **Model repair suggestion:** No fix suggestion produced.

