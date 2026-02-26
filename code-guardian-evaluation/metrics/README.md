# Code Guardian Metrics Framework

A comprehensive evaluation framework that measures and compares security analysis tools across five key dimensions: accuracy, performance, repair quality, robustness, and usability.

## 🎯 Overview

This framework automatically discovers and evaluates security analysis tools using rigorous academic standards. It compares Code Guardian against baseline SAST tools (CodeQL, Semgrep) and provides detailed statistical analysis with multiple significance tests.

## 🏗️ Framework Architecture

```text
metrics/
├── dynamic_metrics_runner.py     # Main evaluation script with auto-discovery
├── metrics_orchestrator.py       # Coordinates all metric calculations  
├── statistical_tests.py          # Comprehensive statistical testing
├── accuracy/                     # Vulnerability detection analysis
│   └── accuracy_calculator.py    # Uses scikit-learn + scipy
├── latency/                      # Performance measurement
│   └── latency_calculator.py     # Uses numpy + scipy
├── repair-quality/               # Fix suggestion quality
│   └── repair_quality_calculator.py
├── robustness/                   # System stability testing
│   └── robustness_calculator.py
└── usability/                    # User experience metrics
    └── usability_calculator.py
```

## 📊 How Each Metric Works

### 1. 🎯 Accuracy Metrics (`accuracy/accuracy_calculator.py`)

**What it measures**: How accurately tools detect security vulnerabilities

**Implementation**: Uses scikit-learn and scipy for rigorous statistical analysis

**Key calculations**:
- **Precision**: `sklearn.metrics.precision_score()` with confidence intervals
- **Recall**: `sklearn.metrics.recall_score()` with confidence intervals  
- **F1-Score**: `sklearn.metrics.f1_score()` with confidence intervals
- **McNemar's Test**: `scipy.stats.mcnemar()` for tool comparison
- **Bootstrap CI**: `sklearn.utils.resample()` for reliability estimates

**Statistical tests included**:
- McNemar's test (primary)
- Chi-square test of independence
- Fisher's exact test
- Two-proportion z-test
- Confidence interval comparison

**Example data format**:
```json
{
  "sample_id": "test_001",
  "true_label": true,
  "predicted_label": true, 
  "confidence": 0.85,
  "vulnerability_type": "sql-injection"
}
```

### 2. ⚡ Latency Metrics (`latency/latency_calculator.py`)

**What it measures**: How fast tools analyze code and provide results

**Implementation**: Uses numpy and scipy for statistical analysis

**Key calculations**:
- **Percentiles**: `numpy.percentile()` for P50, P95, P99
- **Distribution Analysis**: `scipy.stats` for normality and comparison tests
- **Effect Sizes**: Cohen's d using pooled standard deviation
- **Correlation**: `scipy.stats.pearsonr()` with file size

**Statistical tests included**:
- Mann-Whitney U test (`scipy.stats.mannwhitneyu`)
- Wilcoxon signed-rank test (`scipy.stats.wilcoxon`)
- Kolmogorov-Smirnov test (`scipy.stats.ks_2samp`)

**Performance categories**:
- Fast: < 500ms
- Acceptable: 500ms - 1000ms  
- Slow: > 1000ms

**Example data format**:
```json
{
  "sample_id": "latency_001",
  "operation_type": "file_analysis",
  "latency_ms": 245.5,
  "file_size_bytes": 1024,
  "lines_of_code": 50
}
```

### 3. 🔧 Repair Quality Metrics (`repair-quality/`)

**What it measures**: Quality and effectiveness of suggested code fixes

**Key calculations**:
- **Repair Correctness**: `Correct Fixes / Total Fixes Attempted`
- **Code Quality Score**: Expert ratings on 1-5 scale
- **Completeness**: Whether fixes fully resolve vulnerabilities
- **Maintainability**: Code readability and maintainability scores

**Example data format**:
```json
{
  "sample_id": "repair_001",
  "repair_correct": true,
  "code_quality_rating": 4.2,
  "expert_rating": 4.0,
  "completeness_score": 0.9
}
```

### 4. 🛡️ Robustness Metrics (`robustness/`)

**What it measures**: System stability under stress and edge cases

**Key calculations**:
- **Success Rate**: `Successful Analyses / Total Analyses`
- **Error Recovery**: Graceful handling of failures
- **Memory Efficiency**: Resource usage patterns
- **Crash Frequency**: System failure rates

**Example data format**:
```json
{
  "sample_id": "stress_001",
  "success": true,
  "memory_usage_mb": 156.2,
  "error_handled": true,
  "processing_time_ms": 1200
}
```

### 5. 👥 Usability Metrics (`usability/`)

**What it measures**: Developer experience and tool ease-of-use

**Key calculations**:
- **Task Completion Rate**: `Completed Tasks / Total Tasks`
- **Time to Fix**: Average time for developers to apply fixes
- **User Satisfaction**: Survey ratings and feedback analysis
- **Learning Curve**: New user productivity metrics

**Example data format**:
```json
{
  "sample_id": "user_001",
  "task_completed": true,
  "completion_time_seconds": 45,
  "satisfaction_rating": 4.5,
  "errors_made": 1
}
```

## 📊 Statistical Analysis Framework

The framework implements comprehensive statistical testing using scipy and statsmodels:

### 1. 🎲 Bootstrap Confidence Intervals

**Implementation**: Uses `sklearn.utils.resample()` with 1000 bootstrap samples

**How it works**:
- Resamples detection results 1000 times with replacement
- Calculates precision, recall, F1-score for each sample
- Creates 95% confidence intervals using percentiles

**Example output**:
```text
Precision: 0.85 (95% CI: 0.78-0.92)
```

### 2. 🔬 McNemar's Test

**Implementation**: Uses `scipy.stats.mcnemar()` for paired tool comparison

**How it works**:
- Creates 2x2 contingency table of tool agreements/disagreements
- Uses chi-square test on disagreement cases
- Applies exact test for small samples (< 25 disagreements)

**Example output**:
```text
McNemar's test: χ² = 8.52, p = 0.003 (significant)
```

### 3. 📏 Expected Calibration Error (ECE)

**Implementation**: Custom implementation with confidence score binning

**How it works**:
- Groups predictions by confidence level (10 bins: 0-10%, 10-20%, etc.)
- Compares average confidence vs actual accuracy in each bin
- Lower ECE indicates better calibrated confidence scores

### 4. 📈 Multiple Testing Correction

**Implementation**: Bonferroni correction for multiple statistical tests

**How it works**:
- Adjusts significance level: α_corrected = α / number_of_tests
- Ensures overall Type I error rate remains at 5%
- Reports both individual and corrected p-values

## 🚀 How to Run Evaluations

### Quick Start

```bash
# Navigate to the metrics directory
cd evaluation/metrics

# Run evaluation for all discovered tools
python dynamic_metrics_runner.py

# Run evaluation for a specific tool
python dynamic_metrics_runner.py --tool code-guardian
python dynamic_metrics_runner.py --tool sast-semgrep
python dynamic_metrics_runner.py --tool sast-codeql

# List all available tools
python dynamic_metrics_runner.py --list-tools
```

### Example Output

```bash
🎯 Comprehensive Evaluation Completed!
==================================================

📈 Tool Rankings:
  1. code-guardian: 1.000
  2. sast-semgrep: 0.743  
  3. sast-codeql: 0.683

🔍 Key Findings:
  • code-guardian achieved the highest overall score (1.000)
  • code-guardian showed best accuracy performance (1.000)
  • Code Guardian shows strong performance in: accuracy, latency, robustness

📄 Reports saved to: ../evaluation_results/
```

## 🔧 Tool Discovery System

The framework automatically discovers tools from the `../metrics-data/` directory:

**Supported structures**:
- **Flat**: `metrics-data/code-guardian/` with JSON files
- **Nested**: `metrics-data/sast/semgrep/` for categorized tools

**Required files per tool**:
- `detection_data.json` - Vulnerability detection results
- `latency_data.json` - Performance timing data  
- `repair_data.json` - Fix suggestion quality data (optional)
- `robustness_data.json` - Stress test results (optional)
- `usability_data.json` - User interaction data (optional)

## 📈 Generated Reports

### JSON Reports
- **`comprehensive_evaluation_report.json`**: Complete results with statistical analysis
- **`{tool}_evaluation_report.json`**: Individual tool detailed results
- **`academic_summary.json`**: Research-ready findings with effect sizes
- **`statistical_significance_report.json`**: Detailed statistical test results

### CSV Reports  
- **`tools_summary_comparison.csv`**: High-level metrics comparison
- **`detailed_metrics_comparison.csv`**: Comprehensive metrics breakdown

### Academic Features
- **Statistical significance**: Multiple tests with Bonferroni correction
- **Effect sizes**: Cohen's d, Cohen's h, odds ratios
- **Confidence intervals**: Bootstrap and analytical methods
- **Power analysis**: Sample size adequacy assessment

## 🔧 Advanced Configuration

### Environment Variables
```bash
export METRICS_DATA_DIR="/custom/path/to/metrics-data"
export EVALUATION_RESULTS_DIR="/custom/path/to/results"
export LOG_LEVEL="DEBUG"  # DEBUG, INFO, WARNING, ERROR
```

### Programmatic Usage

```python
from dynamic_metrics_runner import DynamicMetricsRunner
from pathlib import Path

# Initialize with custom configuration
runner = DynamicMetricsRunner(
    metrics_data_dir=Path("../metrics-data"),
    output_dir=Path("../evaluation_results"),
    alpha=0.01  # More stringent significance level
)

# Run comprehensive evaluation
results = runner.run_comprehensive_evaluation()

# Access statistical results
statistical_analysis = results["statistical_analysis"]
accuracy_comparison = statistical_analysis["pairwise_comparisons"]["code-guardian_vs_sast-semgrep"]
print(f"McNemar p-value: {accuracy_comparison['accuracy_comparison']['statistical_tests']['mcnemar']['p_value']}")
```

## 🧪 Adding New Tools

1. **Create tool directory**: 
   ```bash
   mkdir ../metrics-data/new-tool-name
   ```

2. **Add data files** with proper JSON format:
   ```bash
   # Required
   touch detection_data.json latency_data.json
   # Optional  
   touch repair_data.json robustness_data.json usability_data.json
   ```

3. **Run evaluation**:
   ```bash
   python dynamic_metrics_runner.py --tool new-tool-name
   ```

The framework automatically discovers and evaluates any new tools following this structure.

## 🔬 Research Integration

### Academic Standards
- **Multiple statistical tests** with correction for multiple comparisons
- **Effect size reporting** with practical significance assessment  
- **Confidence intervals** using robust bootstrap methods
- **Power analysis** for sample size adequacy
- **Reproducible methodology** with detailed configuration logging

### Publication-Ready Output
- LaTeX-compatible statistical tables
- Research findings with p-values and effect sizes
- Methodology documentation for peer review
- Limitation analysis and future work recommendations

## ⚙️ Dependencies

### Core Dependencies
- **numpy**: Numerical computations and array operations
- **scipy**: Statistical tests and distributions
- **scikit-learn**: Machine learning metrics and resampling
- **pandas**: Data manipulation and analysis
- **statsmodels**: Advanced statistical modeling

### Graceful Degradation
The framework continues to work with reduced functionality if optional packages are missing:
- Missing `scipy`: Falls back to manual statistical implementations
- Missing `pandas`: Uses basic data structures
- Missing `statsmodels`: Uses scipy alternatives

## 🔍 Troubleshooting

### Common Issues

1. **No tools discovered**:
   ```bash
   ls -la ../metrics-data/*/detection_data.json
   # Verify JSON files exist and are properly formatted
   ```

2. **Statistical tests failing**:
   ```bash
   pip install scipy statsmodels  # Ensure statistical packages installed
   python -c "import scipy.stats; print('Scipy available')"
   ```

3. **Memory issues with large datasets**:
   ```bash
   # Use smaller bootstrap samples
   python dynamic_metrics_runner.py --bootstrap-samples 100
   ```

This framework provides a comprehensive, academically rigorous evaluation system for security analysis tools with automatic discovery, statistical significance testing, and publication-ready reporting.
