# SAST Tools Makefile for Code Guardian Evaluation

# Configuration
SHELL := /bin/bash
PROJECT_ROOT := $(shell cd ../../.. && pwd)
VIRTUAL_ENV := $(PROJECT_ROOT)/evaluation/.venv
PYTHON := $(VIRTUAL_ENV)/bin/python

# Directories
RESULTS_DIR := results
CODEQL_DIR := codeql_tools/codeql

# Analysis settings
SOURCE_ROOT ?= ../../datasets
THREADS ?= 4
RAM_MB ?= 8192

# Results files
SEMGREP_RESULTS := $(RESULTS_DIR)/semgrep_results.json
CODEQL_RESULTS := $(RESULTS_DIR)/codeql_results.sarif
COMBINED_RESULTS := $(RESULTS_DIR)/combined_analysis.json

# Default target
.DEFAULT_GOAL := help

# Help
help: ## Show available commands
	@echo "SAST Tools for Code Guardian Evaluation"
	@echo "======================================"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Setup
install: ## Install CodeQL
	@echo "Installing CodeQL..."
	@mkdir -p codeql_tools
	@cd codeql_tools && \
	curl -L https://github.com/github/codeql-cli-binaries/releases/latest/download/codeql-osx64.zip -o codeql.zip && \
	unzip -q codeql.zip && rm codeql.zip
	@echo "Installation complete"

setup: ## Create directories
	@mkdir -p $(RESULTS_DIR)

# Analysis
analyze: setup semgrep codeql combine ## Run complete SAST analysis

test: ## Run analysis on benchmark dataset
	@$(MAKE) analyze SOURCE_ROOT=../../datasets/benchmark

semgrep: setup ## Run Semgrep analysis
	@echo "Running Semgrep analysis..."
	@$(VIRTUAL_ENV)/bin/semgrep \
		--config=p/security-audit \
		--config=p/javascript \
		--json \
		--output=$(SEMGREP_RESULTS) \
		--quiet \
		$(SOURCE_ROOT)

codeql: setup ## Run CodeQL analysis
	@echo "Creating CodeQL database..."
	@rm -rf $(RESULTS_DIR)/codeql_db
	@$(CODEQL_DIR)/codeql database create \
		--language=javascript \
		--source-root=$(SOURCE_ROOT) \
		--threads=$(THREADS) \
		$(RESULTS_DIR)/codeql_db
	@echo "Running CodeQL analysis..."
	@$(CODEQL_DIR)/codeql database analyze \
		$(RESULTS_DIR)/codeql_db \
		codeql/javascript-queries:codeql-suites/javascript-security-and-quality.qls \
		--format=sarif-latest \
		--output=$(CODEQL_RESULTS) \
		--threads=$(THREADS) \
		--ram=$(RAM_MB)

combine: ## Combine analysis results
	@echo "Combining results..."
	@$(PYTHON) -c "import json; \
s=json.load(open('$(SEMGREP_RESULTS)')); \
c=json.load(open('$(CODEQL_RESULTS)')); \
r={'semgrep_count':len(s.get('results',[])), 'codeql_count':len(c.get('runs',[{}])[0].get('results',[])), 'total':len(s.get('results',[]))+len(c.get('runs',[{}])[0].get('results',[]))}; \
json.dump(r, open('$(COMBINED_RESULTS)','w'), indent=2); \
print(f'Total findings: {r[\"total\"]} (Semgrep: {r[\"semgrep_count\"]}, CodeQL: {r[\"codeql_count\"]})')"

# Dataset Analysis
analyze-datasets: ## Analyze evaluation datasets
	@$(PYTHON) analyze_datasets.py --dataset=all
	@$(PYTHON) sast_metrics_bridge.py

# Utilities
clean: ## Clean analysis results
	@rm -rf $(RESULTS_DIR)

verify: ## Check if tools are installed
	@$(VIRTUAL_ENV)/bin/semgrep --version
	@$(CODEQL_DIR)/codeql version

.PHONY: help install setup analyze test semgrep codeql combine
.PHONY: analyze-datasets export-metrics clean verify
