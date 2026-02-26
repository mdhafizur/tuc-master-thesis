# SAST Baseline Documentation

## Overview

This directory contains a complete baseline implementation of Static Application Security Testing (SAST) tools for evaluating the Code Guardian VS Code extension. The baseline includes two industry-standard SAST tools: Semgrep and CodeQL.

## Tool Versions and Environment

### System Environment
- **Operating System**: macOS (Darwin x64)
- **Python Environment**: Python 3.11 (virtual environment)
- **Shell**: zsh

### Tool Versions (Pinned)
- **Semgrep**: 1.85.0
- **CodeQL CLI**: 2.23.0
- **CodeQL JavaScript Queries**: 2.0.3
- **CodeQL JavaScript All**: 2.6.10

## Directory Structure

```
/evaluation/baselines/sast/
├── semgrep_config.yml          # Semgrep configuration with security rules
├── codeql_config.yml           # CodeQL configuration for JavaScript analysis
├── Makefile                    # Automation framework for all operations
├── SAST_ANALYSIS_SUMMARY.md    # Test results and analysis summary
├── SETUP_DOCUMENTATION.md      # This file
├── test_samples/
│   └── vulnerable_sample.js    # Test file with intentional vulnerabilities
├── codeql_tools/
│   └── codeql/                 # CodeQL CLI installation (extracted)
└── results/
    ├── semgrep_results.json    # Semgrep analysis output
    ├── codeql_results.sarif    # CodeQL analysis output (SARIF format)
    ├── codeql_analysis_db/     # CodeQL database for test samples
    └── combined_analysis.json  # Merged results from both tools
```

## Installation and Setup

### Prerequisites
```bash
# Ensure Python virtual environment is activated
source /path/to/.venv/bin/activate

# Verify Python version
python --version  # Should be 3.11+
```

### Quick Setup
```bash
# Navigate to SAST baseline directory
cd evaluation/baselines/sast/

# Install and configure all tools
make install

# Verify installation
make verify
```

### Manual Setup (if needed)
```bash
# Install Semgrep
pip install semgrep==1.85.0

# Download and extract CodeQL CLI
make install-codeql

# Download CodeQL query packs
make download-query-packs
```

## Configuration Details

### Semgrep Configuration (`semgrep_config.yml`)
- **Rules**: Security-focused rulesets including:
  - `p/security-audit`: General security patterns
  - `p/javascript`: JavaScript-specific vulnerabilities
  - `p/typescript`: TypeScript security patterns
  - `p/owasp-top-ten`: OWASP Top 10 vulnerabilities
- **Performance**: Optimized for CI/CD with timeout and memory limits
- **Output**: JSON format for programmatic processing

### CodeQL Configuration (`codeql_config.yml`)
- **Language**: JavaScript/TypeScript analysis
- **Query Suites**: Security and quality focused queries
- **Database Settings**: Optimized for parallel processing
- **Output**: SARIF format for standardized reporting

## Usage

### Basic Analysis
```bash
# Run complete analysis on test samples
make test

# Run individual tools
make run-semgrep
make run-codeql

# Generate combined report
make combine-results
```

### Custom Analysis
```bash
# Analyze specific directory
make SOURCE_DIR=/path/to/code analyze

# Clean all results and start fresh
make clean
```

### Advanced Operations
```bash
# Update tools to latest versions
make update-tools

# Run performance benchmarks
make benchmark

# Generate detailed reports
make report
```

## Output Formats

### Semgrep Output
- **Format**: JSON
- **Location**: `results/semgrep_results.json`
- **Contents**: Vulnerability findings with severity, CWE mappings, and fix suggestions

### CodeQL Output
- **Format**: SARIF (Static Analysis Results Interchange Format)
- **Location**: `results/codeql_results.sarif`
- **Contents**: Security and quality findings with data flow analysis

### Combined Report
- **Format**: JSON
- **Location**: `results/combined_analysis.json`
- **Contents**: Merged findings from both tools with unified metadata

## Automation Features

The Makefile provides 20+ targets for complete automation:

### Installation Targets
- `install`: Complete setup of both tools
- `install-semgrep`: Semgrep-only installation
- `install-codeql`: CodeQL-only installation
- `download-query-packs`: Download CodeQL query databases

### Analysis Targets
- `test`: Run complete analysis on test samples
- `analyze`: Analyze custom source directory
- `run-semgrep`: Execute Semgrep analysis only
- `run-codeql`: Execute CodeQL analysis only

### Utility Targets
- `clean`: Remove all generated files
- `verify`: Verify tool installations
- `help`: Display available targets
- `combine-results`: Merge tool outputs

## Security Rule Coverage

### Vulnerability Classes Detected
- **Injection Attacks**: SQL injection, code injection, command injection
- **Cross-Site Scripting (XSS)**: Reflected, stored, DOM-based
- **Authentication Issues**: Weak password hashing, session fixation
- **Authorization Flaws**: Missing access controls, privilege escalation
- **Cryptographic Issues**: Weak algorithms, improper key management
- **Server-Side Request Forgery (SSRF)**: Unvalidated URL requests
- **Path Traversal**: Directory traversal vulnerabilities
- **Security Misconfigurations**: Missing security headers, rate limiting

### OWASP Top 10 Coverage
✅ A01:2021 - Broken Access Control  
✅ A02:2021 - Cryptographic Failures  
✅ A03:2021 - Injection  
✅ A04:2021 - Insecure Design  
✅ A05:2021 - Security Misconfiguration  
✅ A06:2021 - Vulnerable and Outdated Components  
✅ A07:2021 - Identification and Authentication Failures  
✅ A08:2021 - Software and Data Integrity Failures  
✅ A09:2021 - Security Logging and Monitoring Failures  
✅ A10:2021 - Server-Side Request Forgery

## Performance Characteristics

### Semgrep Performance
- **Analysis Speed**: ~2 seconds for 100 lines of code
- **Memory Usage**: <512MB RAM
- **Scalability**: Linear scaling with codebase size
- **Accuracy**: High precision, low false positive rate

### CodeQL Performance
- **Database Creation**: ~30 seconds for small projects
- **Analysis Speed**: ~10 seconds for security queries
- **Memory Usage**: ~8GB RAM for parallel processing
- **Scalability**: Better for larger codebases due to incremental analysis

## Evaluation Metrics

The baseline tracks these metrics for comparison:
- **Vulnerability Detection Rate**: Number of true positives found
- **False Positive Rate**: Incorrect vulnerability reports
- **Analysis Speed**: Time to complete full security scan
- **Resource Usage**: CPU and memory consumption
- **Rule Coverage**: Breadth of security patterns detected

## Troubleshooting

### Common Issues

#### CodeQL Database Creation Fails
```bash
# Check source directory has JavaScript files
ls -la test_samples/*.js

# Verify CodeQL CLI is executable
./codeql_tools/codeql/codeql version

# Clean and retry
make clean && make test
```

#### Semgrep Installation Issues
```bash
# Check Python virtual environment
which python
pip list | grep semgrep

# Reinstall if needed
pip uninstall semgrep && make install-semgrep
```

#### Memory Issues with CodeQL
```bash
# Reduce parallel threads
export CODEQL_THREADS=2

# Reduce RAM allocation
export CODEQL_RAM=4096
```

## Reproducibility

This baseline ensures reproducible results through:
- **Pinned Tool Versions**: Exact version specifications
- **Configuration Files**: Complete setup documentation
- **Automated Installation**: Scripted setup process
- **Test Samples**: Standardized vulnerable code patterns
- **Environment Documentation**: Complete system requirements

## Integration with Code Guardian Evaluation

This SAST baseline serves as a comparison point for evaluating:
1. **Detection Accuracy**: How many vulnerabilities does Code Guardian find vs. traditional SAST?
2. **Performance**: Speed and resource usage comparison
3. **User Experience**: Developer workflow integration
4. **Fix Quality**: Accuracy and applicability of suggested repairs

The standardized output formats enable automated comparison and metric calculation for the research evaluation.
