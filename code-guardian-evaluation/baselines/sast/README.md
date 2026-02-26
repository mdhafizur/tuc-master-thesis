# SAST Baseline for Code Guardian Evaluation

Static Application Security Testing (SAST) tools baseline for evaluating the Code Guardian VS Code extension performance.

## 🚀 Quick Start

```bash
# Install Semgrep and CodeQL
make install

# Run analysis on benchmark dataset
make test

# Analyze all evaluation datasets
make analyze-datasets

# Export metrics for Code Guardian comparison
make export-metrics

# View results
cat results/combined_analysis.json
```

## 📊 Available Commands

```bash
make help              # Show all available commands
make install           # Install Semgrep and CodeQL
make test             # Analyze benchmark dataset
make analyze          # Run complete analysis on custom directory
make analyze-datasets # Analyze all evaluation datasets (Python script)
make export-metrics   # Export baseline metrics for comparison
make verify           # Check tool installations
make clean            # Clean analysis results
```

## Dataset Integration

The SAST baseline now supports analyzing the complete Code Guardian evaluation datasets:

### Available Datasets
- **Benchmark Dataset**: 21 samples from OWASP Benchmark and adapted Juliet tests
- **Extended Dataset**: 28 samples from security research papers and CVE databases  
- **Adversarial Dataset**: 45 samples with obfuscation and prompt injection
- **Real-world Dataset**: 12 samples from actual CVE reports in popular JS/TS projects

### Dataset Analysis Commands

```bash
# Analyze all datasets (recommended)
make analyze-datasets

# Generate baseline metrics report
make export-metrics
```

### Dataset Analysis Results

After running dataset analysis, you'll get:

1. **Individual Dataset Reports**: `results/{dataset}_analysis_report.json`
   - Detection rates per sample
   - Tool-specific findings
   - CWE category breakdown
   - Detailed vulnerability mapping

2. **Summary Report**: `results/dataset_analysis_summary.json`
   - Overall detection rates across all datasets
   - Cross-dataset comparison
   - Tool performance summary

3. **Raw Tool Outputs**: `results/{dataset}_{tool}.{json|sarif}`
   - Semgrep JSON results
   - CodeQL SARIF results

## 🛠️ Tools Included

- **Semgrep 1.85.0**: Fast, rule-based security analysis
- **CodeQL**: GitHub's semantic code analysis platform

## ✨ Key Features

- ✅ Automated installation and setup
- ✅ Comprehensive security rule coverage
- ✅ Standardized JSON output formats
- ✅ Complete dataset integration
- ✅ Baseline metrics for Code Guardian comparison

## 📊 Baseline Metrics

The SAST baseline provides detection metrics for comparing against Code Guardian:

```json
{
  "semgrep": {
    "detection_rate": 0.85,
    "avg_latency_ms": 500
  },
  "codeql": {
    "detection_rate": 0.92, 
    "avg_latency_ms": 5000
  }
}
```

Metrics are exported to `/evaluation/metrics-data/sast/` for framework integration.

## 🚨 Vulnerability Coverage

Both tools detect these vulnerability types:

- Code injection vulnerabilities
- Command injection flaws  
- Path traversal issues
- Weak cryptography usage
- SSRF vulnerabilities
- Authentication weaknesses
- XSS vulnerabilities
- SQL injection flaws
- Prototype pollution
- Insecure deserialization

This baseline provides a foundation for comparing Code Guardian's performance against established SAST tools.
