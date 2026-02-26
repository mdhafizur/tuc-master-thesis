# Code Guardian Evaluation Framework

This directory contains the comprehensive evaluation framework for testing and benchmarking different AI models used in Code Guardian.

## Overview

The evaluation framework assesses models on their ability to:
- Detect security vulnerabilities accurately
- Minimize false positives
- Respond quickly
- Return properly formatted JSON responses

## Files

### Datasets
- **`datasets/vulnerability-test-cases.json`** - Curated test cases covering 18 common vulnerability types:
  - SQL Injection
  - Cross-Site Scripting (XSS)
  - Command Injection
  - Path Traversal
  - Weak Cryptography
  - NoSQL Injection
  - Hardcoded Credentials
  - XML External Entity (XXE)
  - Insecure Random Numbers
  - Regular Expression DoS
  - JWT Verification Issues
  - Code Injection
  - Open Redirect
  - CSRF
  - Sensitive Data Exposure
  - Prototype Pollution
  - Race Conditions
  - Unsafe Reflection
  - Plus 2 secure code examples (for testing false positive rate)

### Scripts
- **`evaluate-models.js`** - Main evaluation script that tests models against the dataset
- **`generate-datasets.js`** - Generates extension-typed datasets from `code-guardian-evaluation/datasets`
- **`test-models.js`** - Quick model testing script (in parent directory)

### Output
- **`logs/`** - Evaluation results saved as JSON and Markdown reports

## Usage

### Prerequisites

1. Install and start Ollama:
```bash
ollama serve
```

2. Pull models you want to test:
```bash
ollama pull gemma3:1b
ollama pull qwen2.5-coder:1.5b
ollama pull qwen2.5-coder:3b
```

3. Optional baseline tools for SAST comparison:
- `semgrep`
- `codeql`
- `eslint` + `eslint-plugin-security`

### Running Evaluation

```bash
# From the project root
node evaluation/evaluate-models.js

# Or from the evaluation directory
cd evaluation
./evaluate-models.js
```

By default, `evaluate-models.js` auto-selects:
1. `datasets/vulnerability-test-cases.generated.json` (if it exists)
2. otherwise `datasets/vulnerability-test-cases.json`

You can explicitly pick a dataset file:

```bash
node evaluation/evaluate-models.js --dataset=datasets/vulnerability-test-cases.generated.json
```

Run LLM-only ablation (Base vs RAG):

```bash
npm run evaluate:ablation
```

Run full comparison (LLM + RAG+LLM + baselines):

```bash
npm run evaluate:comparison
```

Run baselines only:

```bash
node evaluation/evaluate-models.js --baselines-only --include-baselines
```

Select specific baseline tools:

```bash
node evaluation/evaluate-models.js --ablation --include-baselines --baseline-tools=codeql,semgrep,eslint-security
```

### Generate Dataset from External Sources

If you have the sibling repository folder `code-guardian-evaluation/`, you can generate extension-compatible datasets:

```bash
# From code-guardian-extension root
npm run datasets:generate
```

This writes:
- `evaluation/datasets/vulnerability-test-cases.generated.json`
- `evaluation/datasets/advanced-test-cases.generated.json`
- `evaluation/datasets/all-test-cases.generated.json`

The default generation policy is `external-only` (filters fallback/pattern-style samples).  
To also pull adversarial stress tests (while keeping the external-only filter for core sets):

```bash
npm run datasets:generate:adversarial
```

To include everything from the source manifests:

```bash
npm run datasets:generate:all
```

### Customizing Tests

Edit `datasets/vulnerability-test-cases.json` to:
- Add new test cases
- Modify expected vulnerabilities
- Test language-specific patterns

Edit `evaluate-models.js` to:
- Change models tested (line 243)
- Adjust timeout settings
- Modify scoring algorithms

## Metrics Explained

### Precision
- **Formula:** TP / (TP + FP)
- **Meaning:** Of all vulnerabilities detected, how many were actually correct?
- **High precision** = Few false positives (doesn't flag safe code as vulnerable)

### Recall
- **Formula:** TP / (TP + FN)
- **Meaning:** Of all actual vulnerabilities, how many did we detect?
- **High recall** = Few false negatives (catches most vulnerabilities)

### F1 Score
- **Formula:** 2 × (Precision × Recall) / (Precision + Recall)
- **Meaning:** Harmonic mean of precision and recall
- **Best overall metric** for model comparison

### Accuracy
- **Formula:** (TP + TN) / Total
- **Meaning:** Overall correctness across all test cases

### False Positive Rate
- **Formula:** FP / (FP + TN)
- **Meaning:** How often safe code is incorrectly flagged
- **Lower is better**

### Response Time
- **Average time** (in milliseconds) to analyze a code sample
- **Important for** real-time analysis features

### Parse Success Rate
- **Percentage** of responses that returned valid JSON
- **Critical for** extension integration

## Interpreting Results

### Example Output
```
🏆 Model Rankings (by F1 Score):

🥇 1. qwen2.5-coder:3b
   F1 Score:     87.50%
   Precision:    90.00%
   Recall:       85.00%
   Accuracy:     88.00%
   Avg Response: 1250ms
   Parse Rate:   95.00%

🥈 2. gemma3:1b
   F1 Score:     82.00%
   Precision:    85.00%
   Recall:       79.00%
   Accuracy:     83.00%
   Avg Response: 850ms
   Parse Rate:   92.00%
```

### What to Look For

**Best Overall Model:**
- Highest F1 score (balanced detection)
- High parse success rate (>90%)
- Acceptable response time (<2000ms for real-time)

**Best for Real-Time Analysis:**
- Response time <1000ms
- F1 score >75%
- Parse success >90%

**Best for Accuracy:**
- Highest precision (minimize false alarms)
- High recall (catch most vulnerabilities)
- Can tolerate slower response times

## Adding New Test Cases

1. Edit `datasets/vulnerability-test-cases.json`
2. Add a new object with this structure:

```json
{
  "id": "unique-id",
  "name": "Descriptive name",
  "code": "function example() { /* vulnerable code */ }",
  "language": "javascript",
  "expectedVulnerabilities": [
    {
      "type": "Vulnerability Type",
      "cwe": "CWE-XXX",
      "severity": "high|medium|low",
      "description": "Why this is vulnerable"
    }
  ],
  "expectedFix": "How to fix it"
}
```

3. For secure code examples:
```json
{
  "id": "secure-example-1",
  "name": "Secure implementation",
  "code": "function secure() { /* safe code */ }",
  "language": "javascript",
  "expectedVulnerabilities": [],
  "expectedFix": null
}
```

## Continuous Improvement

### Benchmark Your Changes
After modifying Code Guardian's prompts or RAG system:

1. Run evaluation before changes
2. Make your improvements
3. Run evaluation again
4. Compare F1 scores and other metrics

### Track Performance Over Time
Save evaluation reports with version tags:
```bash
node evaluation/evaluate-models.js > logs/eval-v1.0.6.log
```

## Troubleshooting

### "Failed to connect to Ollama"
- Ensure Ollama is running: `ollama serve`
- Check default port (11434) is accessible

### "Skipping [model] (not installed)"
- Pull the model: `ollama pull model-name`
- Verify with: `ollama list`

### Low Parse Success Rate
- Model may not be following JSON format consistently
- Consider adjusting temperature (lower = more consistent)
- Update system prompt for clearer instructions

### Slow Response Times
- Use smaller models for real-time analysis
- Reduce `num_predict` parameter
- Consider caching common patterns

## Contributing

To add support for new vulnerability types:
1. Research the vulnerability (OWASP, CWE)
2. Create representative test cases
3. Add to dataset with proper metadata
4. Test against multiple models
5. Document expected detection behavior

npm run evaluate -- --ablation --runs 3 --rag-k 5
