#!/usr/bin/env python3
"""
Dynamic Metrics Runner for Code Guardian Evaluation

This module dynamically discovers and processes metrics data from the metrics-data directory,
automatically running evaluations for all available tools and generating comparative reports.

Features:
- Automatic discovery of metrics data directories
- Dynamic loading of detection, latency, repair, robustness, and usability data
- Comparative analysis between different tools (Code Guardian vs SAST baselines)
- Comprehensive report generation with academic-style summaries
- Flexible output formats for research papers
"""

import json
import logging
import argparse
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
from dataclasses import dataclass
import pandas as pd

# Handle optional imports with fallbacks
try:
    from statistical_tests import StatisticalTestSuite
    STATISTICAL_TESTS_AVAILABLE = True
except ImportError:
    StatisticalTestSuite = None
    STATISTICAL_TESTS_AVAILABLE = False

try:
    from metrics_orchestrator import MetricsOrchestrator
    METRICS_ORCHESTRATOR_AVAILABLE = True
except ImportError:
    MetricsOrchestrator = None
    METRICS_ORCHESTRATOR_AVAILABLE = False


logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


@dataclass
class ToolDataset:
    """Represents a complete dataset for a specific tool"""

    tool_name: str
    data_path: Path
    metadata: Dict[str, Any]
    detection_data: List[Dict[str, Any]]
    latency_data: List[Dict[str, Any]]
    repair_data: List[Dict[str, Any]]
    robustness_data: List[Dict[str, Any]]
    usability_data: List[Dict[str, Any]]

    @property
    def is_complete(self) -> bool:
        """Check if all required data files are present"""
        return all(
            [
                len(self.detection_data) > 0,
                len(self.latency_data) > 0,
                # Repair, robustness, and usability data are optional
            ]
        )


class DynamicMetricsRunner:
    """
    Dynamically discovers and processes metrics data from multiple tools

    Features:
    - Auto-discovery of tool data directories
    - Parallel processing of multiple tools
    - Comparative analysis and reporting
    - Academic-style output generation
    """

    def __init__(self, metrics_data_dir: Path, output_dir: Path, alpha: float = 0.05):
        """
        Initialize dynamic metrics runner

        Args:
            metrics_data_dir: Directory containing tool-specific metrics data
            output_dir: Directory to save evaluation results
            alpha: Significance level for statistical tests (default 0.05)
        """
        self.metrics_data_dir = Path(metrics_data_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Initialize the metrics orchestrator if available
        if METRICS_ORCHESTRATOR_AVAILABLE:
            self.orchestrator = MetricsOrchestrator(self.output_dir)
        else:
            self.orchestrator = None
            logger.warning("MetricsOrchestrator not available - some functionality will be limited")

        # Initialize statistical test suite if available
        if STATISTICAL_TESTS_AVAILABLE:
            self.statistical_suite = StatisticalTestSuite(alpha=alpha)
        else:
            self.statistical_suite = None

        logger.info("Initialized DynamicMetricsRunner")
        logger.info("  Metrics data directory: %s", self.metrics_data_dir)
        logger.info("  Output directory: %s", self.output_dir)
        logger.info("  Statistical significance level: α=%.3f", alpha)
        if not STATISTICAL_TESTS_AVAILABLE:
            logger.warning(
                "Statistical tests not available - running without statistical analysis"
            )

    def discover_tool_datasets(self) -> Dict[str, ToolDataset]:
        """
        Automatically discover all tool datasets in the metrics-data directory
        Handles both flat structure (code-guardian/) and nested structure (sast/semgrep/, sast/codeql/)

        Returns:
            Dictionary mapping tool names to their datasets
        """
        logger.info("🔍 Discovering tool datasets...")

        tool_datasets = {}

        if not self.metrics_data_dir.exists():
            logger.warning("Metrics data directory not found: %s", self.metrics_data_dir)
            return tool_datasets

        # Scan for subdirectories (each represents a tool or tool category)
        for tool_dir in self.metrics_data_dir.iterdir():
            if tool_dir.is_dir():
                # Check if this is a direct tool directory (has JSON files)
                if self._has_metrics_files(tool_dir):
                    tool_name = tool_dir.name
                    logger.info("  📊 Found tool directory: %s", tool_name)

                    try:
                        dataset = self._load_tool_dataset(tool_name, tool_dir)
                        if dataset:
                            tool_datasets[tool_name] = dataset
                            logger.info("    ✅ Loaded dataset for %s", tool_name)
                            self._log_dataset_info(dataset)
                        else:
                            logger.warning(
                                "    ⚠️  Could not load dataset for %s", tool_name
                            )
                    except (ImportError, AttributeError, RuntimeError) as e:
                        logger.error(
                            "    ❌ Failed to load dataset for %s: %s", tool_name, e
                        )

                # Check if this is a category directory with nested tool directories
                else:
                    category_name = tool_dir.name
                    logger.info("  📁 Found category directory: %s", category_name)

                    # Scan nested directories
                    for nested_dir in tool_dir.iterdir():
                        if nested_dir.is_dir() and self._has_metrics_files(nested_dir):
                            tool_name = f"{category_name}-{nested_dir.name}"
                            logger.info("    📊 Found nested tool: %s", tool_name)

                            try:
                                dataset = self._load_tool_dataset(tool_name, nested_dir)
                                if dataset:
                                    tool_datasets[tool_name] = dataset
                                    logger.info(
                                        "      ✅ Loaded dataset for %s", tool_name
                                    )
                                    self._log_dataset_info(dataset)
                                else:
                                    logger.warning(
                                        "      ⚠️  Could not load dataset for %s", tool_name
                                    )
                            except (ImportError, AttributeError, RuntimeError) as e:
                                logger.error(
                                    "      ❌ Failed to load dataset for %s: %s", tool_name, e
                                )

        logger.info("📈 Discovered %d tool datasets", len(tool_datasets))
        return tool_datasets

    def _has_metrics_files(self, directory: Path) -> bool:
        """
        Check if a directory contains metrics data files

        Args:
            directory: Directory to check

        Returns:
            True if directory contains metrics JSON files
        """
        required_files = ["detection_data.json", "latency_data.json"]
        return any((directory / filename).exists() for filename in required_files)

    def _log_dataset_info(self, dataset: ToolDataset) -> None:
        """Log information about a loaded dataset"""
        logger.info("       Detection samples: %d", len(dataset.detection_data))
        logger.info("       Latency measurements: %d", len(dataset.latency_data))
        logger.info("       Repair suggestions: %d", len(dataset.repair_data))
        logger.info("       Robustness tests: %d", len(dataset.robustness_data))
        logger.info("       Usability interactions: %d", len(dataset.usability_data))

    def _load_tool_dataset(
        self, tool_name: str, tool_dir: Path
    ) -> Optional[ToolDataset]:
        """
        Load a complete dataset for a specific tool

        Args:
            tool_name: Name of the tool
            tool_dir: Directory containing the tool's data

        Returns:
            ToolDataset object or None if loading fails
        """
        required_files = {
            "detection_data.json": [],
            "latency_data.json": [],
            "repair_data.json": [],
            "robustness_data.json": [],
            "usability_data.json": [],
        }

        optional_metadata_files = [
            "export_metadata.json",
            f"{tool_name}_baseline_metadata.json",
            f"{tool_name}_metadata.json",
        ]

        # Load required data files
        for filename in required_files.keys():
            file_path = tool_dir / filename
            if file_path.exists():
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        required_files[filename] = (
                            data if isinstance(data, list) else []
                        )
                except (IOError, json.JSONDecodeError) as e:
                    logger.warning("Failed to load %s for %s: %s", filename, tool_name, e)
                    required_files[filename] = []
            else:
                logger.warning("Missing %s for %s", filename, tool_name)
                required_files[filename] = []

        # Load metadata
        metadata = {}
        for metadata_file in optional_metadata_files:
            metadata_path = tool_dir / metadata_file
            if metadata_path.exists():
                try:
                    with open(metadata_path, "r", encoding="utf-8") as f:
                        metadata = json.load(f)
                        break
                except (IOError, json.JSONDecodeError) as e:
                    logger.warning("Failed to load metadata %s: %s", metadata_file, e)

        # Check if we have sufficient data
        if (
            len(required_files["detection_data.json"]) == 0
            and len(required_files["latency_data.json"]) == 0
        ):
            logger.warning("No usable data found for %s", tool_name)
            return None

        return ToolDataset(
            tool_name=tool_name,
            data_path=tool_dir,
            metadata=metadata,
            detection_data=required_files["detection_data.json"],
            latency_data=required_files["latency_data.json"],
            repair_data=required_files["repair_data.json"],
            robustness_data=required_files["robustness_data.json"],
            usability_data=required_files["usability_data.json"],
        )

    def run_comprehensive_evaluation(self) -> Dict[str, Any]:
        """
        Run comprehensive evaluation on all discovered tools

        Returns:
            Dictionary with complete evaluation results for all tools
        """
        logger.info("🚀 Starting comprehensive evaluation of all tools...")

        # Discover all available datasets
        tool_datasets = self.discover_tool_datasets()

        if not tool_datasets:
            logger.error(
                "No tool datasets found. Please check the metrics-data directory."
            )
            return {"error": "No tool datasets found"}

        # Run evaluation for each tool
        all_results = {}
        tool_summaries = {}

        for tool_name, dataset in tool_datasets.items():
            logger.info("📊 Evaluating %s...", tool_name)

            try:
                # Run metrics orchestrator for this tool if available
                if self.orchestrator:
                    tool_results = self.orchestrator.run_complete_evaluation(
                        detection_data=dataset.detection_data,
                        latency_data=dataset.latency_data,
                        repair_data=dataset.repair_data,
                        robustness_data=dataset.robustness_data,
                        usability_data=dataset.usability_data,
                    )
                else:
                    # Fallback evaluation without orchestrator
                    tool_results = {
                        "error": "MetricsOrchestrator not available",
                        "summary": {"overall_score": 0, "dimension_scores": {}},
                    }

                # Add tool-specific metadata
                tool_results["tool_info"] = {
                    "name": tool_name,
                    "data_path": str(dataset.data_path),
                    "metadata": dataset.metadata,
                    "data_completeness": {
                        "detection": len(dataset.detection_data),
                        "latency": len(dataset.latency_data),
                        "repair": len(dataset.repair_data),
                        "robustness": len(dataset.robustness_data),
                        "usability": len(dataset.usability_data),
                    },
                }

                all_results[tool_name] = tool_results
                tool_summaries[tool_name] = tool_results.get("summary", {})

                # Save individual tool report
                tool_report_path = (
                    self.output_dir / f"{tool_name}_evaluation_report.json"
                )
                with open(tool_report_path, "w", encoding="utf-8") as f:
                    json.dump(tool_results, f, indent=2, default=str)

                logger.info("✅ Evaluation completed for %s", tool_name)
                if "summary" in tool_results:
                    overall_score = tool_results["summary"].get("overall_score", 0)
                    logger.info("    Overall Score: %.3f", overall_score)

            except (ImportError, AttributeError, RuntimeError) as e:
                logger.error("❌ Evaluation failed for %s: %s", tool_name, e)
                all_results[tool_name] = {"error": str(e)}

        # Generate comparative analysis
        comparative_results = self._generate_comparative_analysis(
            all_results, tool_summaries
        )

        # Run statistical significance tests between tools (if available)
        if STATISTICAL_TESTS_AVAILABLE and self.statistical_suite:
            statistical_results = self._run_statistical_comparisons(
                tool_datasets, all_results
            )
        else:
            statistical_results = {
                "note": "Statistical tests not available",
                "pairwise_comparisons": {},
                "overall_significance": {},
                "academic_findings": [],
            }

        # Save comprehensive report
        comprehensive_report = {
            "evaluation_timestamp": datetime.now().isoformat(),
            "tools_evaluated": list(tool_datasets.keys()),
            "individual_results": all_results,
            "comparative_analysis": comparative_results,
            "statistical_analysis": statistical_results,
            "configuration": {
                "metrics_data_dir": str(self.metrics_data_dir),
                "output_dir": str(self.output_dir),
                "tools_discovered": len(tool_datasets),
                "statistical_alpha": (
                    self.statistical_suite.alpha if self.statistical_suite else 0.05
                ),
            },
        }

        comprehensive_report_path = (
            self.output_dir / "comprehensive_evaluation_report.json"
        )
        with open(comprehensive_report_path, "w", encoding="utf-8") as f:
            json.dump(comprehensive_report, f, indent=2, default=str)

        # Generate academic summary
        academic_summary = self._generate_academic_summary(comprehensive_report)
        academic_summary_path = self.output_dir / "academic_summary.json"
        with open(academic_summary_path, "w", encoding="utf-8") as f:
            json.dump(academic_summary, f, indent=2, default=str)

        # Generate CSV reports for easy analysis
        self._generate_csv_reports(all_results)

        logger.info("🎯 Comprehensive evaluation completed!")
        logger.info("📄 Reports saved to: %s", self.output_dir)
        logger.info("📊 Tools evaluated: %s", ', '.join(tool_datasets.keys()))

        return comprehensive_report

    def _generate_comparative_analysis(
        self, all_results: Dict[str, Any], tool_summaries: Dict[str, Any]  # noqa: ARG002
    ) -> Dict[str, Any]:
        """
        Generate comparative analysis between tools

        Args:
            all_results: Complete results for all tools (currently unused)
            tool_summaries: Summary metrics for each tool

        Returns:
            Dictionary with comparative analysis
        """
        logger.info("📈 Generating comparative analysis...")

        # Extract key metrics for comparison
        comparison_metrics = {}
        for tool_name, summary in tool_summaries.items():
            if "overall_score" in summary:
                comparison_metrics[tool_name] = {
                    "overall_score": summary.get("overall_score", 0),
                    "dimension_scores": summary.get("dimension_scores", {}),
                    "strengths": summary.get("strengths", []),
                    "weaknesses": summary.get("weaknesses", []),
                }

        # Find best performing tool in each dimension
        best_performers = {}
        all_dimensions = set()
        for tool_scores in comparison_metrics.values():
            all_dimensions.update(tool_scores.get("dimension_scores", {}).keys())

        for dimension in all_dimensions:
            best_score = 0
            best_tool = None
            for tool_name, tool_scores in comparison_metrics.items():
                score = tool_scores.get("dimension_scores", {}).get(dimension, 0)
                if score > best_score:
                    best_score = score
                    best_tool = tool_name

            if best_tool:
                best_performers[dimension] = {"tool": best_tool, "score": best_score}

        # Overall ranking
        tool_rankings = []
        for tool_name, tool_scores in comparison_metrics.items():
            tool_rankings.append(
                {
                    "tool": tool_name,
                    "overall_score": tool_scores.get("overall_score", 0),
                    "dimension_scores": tool_scores.get("dimension_scores", {}),
                }
            )

        tool_rankings.sort(key=lambda x: x["overall_score"], reverse=True)

        return {
            "tool_rankings": tool_rankings,
            "best_performers_by_dimension": best_performers,
            "comparison_matrix": comparison_metrics,
            "key_findings": self._extract_key_findings(
                comparison_metrics, best_performers
            ),
        }

    def _extract_key_findings(
        self, comparison_metrics: Dict[str, Any], best_performers: Dict[str, Any]
    ) -> List[str]:
        """Extract key findings from the comparative analysis"""
        findings = []

        # Overall performance ranking
        if comparison_metrics:
            sorted_tools = sorted(
                comparison_metrics.items(),
                key=lambda x: x[1].get("overall_score", 0),
                reverse=True,
            )

            if len(sorted_tools) > 1:
                best_tool = sorted_tools[0][0]
                best_score = sorted_tools[0][1].get("overall_score", 0)
                findings.append(
                    f"{best_tool} achieved the highest overall score ({best_score:.3f})"
                )

        # Dimension analysis
        if "accuracy" in best_performers:
            best_accuracy_tool = best_performers["accuracy"]["tool"]
            best_accuracy_score = best_performers["accuracy"]["score"]
            findings.append(
                f"{best_accuracy_tool} showed best accuracy performance ({best_accuracy_score:.3f})"
            )

        if "latency" in best_performers:
            best_latency_tool = best_performers["latency"]["tool"]
            findings.append(
                f"{best_latency_tool} demonstrated best latency performance"
            )

        # Code Guardian specific insights
        if "code-guardian" in comparison_metrics:
            cg_scores = comparison_metrics["code-guardian"]["dimension_scores"]
            if cg_scores:
                strong_dimensions = [
                    dim for dim, score in cg_scores.items() if score >= 0.8
                ]
                if strong_dimensions:
                    findings.append(
                        f"Code Guardian shows strong performance in: {', '.join(strong_dimensions)}"
                    )

        return findings

    def _run_statistical_comparisons(
        self, tool_datasets: Dict[str, ToolDataset], all_results: Dict[str, Any]  # noqa: ARG002
    ) -> Dict[str, Any]:
        """
        Run comprehensive statistical significance tests between all tool pairs

        Args:
            tool_datasets: Tool datasets for extracting raw data
            all_results: Complete evaluation results (currently unused)

        Returns:
            Dictionary with statistical comparison results
        """
        logger.info("📊 Running statistical significance tests...")

        statistical_results = {
            "pairwise_comparisons": {},
            "overall_significance": {},
            "statistical_summary": {},
            "academic_findings": [],
        }

        tools = list(tool_datasets.keys())

        # Run pairwise comparisons for all tool pairs
        for i, tool1 in enumerate(tools):
            for tool2 in tools[i + 1 :]:
                logger.info("🔬 Comparing %s vs %s", tool1, tool2)

                comparison_key = f"{tool1}_vs_{tool2}"

                try:
                    # Accuracy comparison
                    accuracy_comparison = None
                    if (
                        len(tool_datasets[tool1].detection_data) > 0
                        and len(tool_datasets[tool2].detection_data) > 0
                    ):

                        accuracy_comparison = (
                            self.statistical_suite.compare_accuracy_comprehensive(
                                tool_datasets[tool1].detection_data,
                                tool_datasets[tool2].detection_data,
                                tool1,
                                tool2,
                            )
                        )

                    # Latency comparison
                    latency_comparison = None
                    if (
                        len(tool_datasets[tool1].latency_data) > 0
                        and len(tool_datasets[tool2].latency_data) > 0
                    ):

                        # Extract latency values
                        tool1_latencies = [
                            item.get("latency_ms", 0)
                            for item in tool_datasets[tool1].latency_data
                        ]
                        tool2_latencies = [
                            item.get("latency_ms", 0)
                            for item in tool_datasets[tool2].latency_data
                        ]

                        latency_comparison = (
                            self.statistical_suite.compare_latency_comprehensive(
                                tool1_latencies,
                                tool2_latencies,
                                tool1,
                                tool2,
                                paired=False,
                            )
                        )

                    # Store comparison results
                    statistical_results["pairwise_comparisons"][comparison_key] = {
                        "tools": [tool1, tool2],
                        "accuracy_comparison": accuracy_comparison,
                        "latency_comparison": latency_comparison,
                        "sample_sizes": {
                            tool1: {
                                "detection": len(tool_datasets[tool1].detection_data),
                                "latency": len(tool_datasets[tool1].latency_data),
                            },
                            tool2: {
                                "detection": len(tool_datasets[tool2].detection_data),
                                "latency": len(tool_datasets[tool2].latency_data),
                            },
                        },
                    }

                    # Extract key findings for this comparison
                    self._extract_comparison_findings(
                        comparison_key,
                        accuracy_comparison,
                        latency_comparison,
                        statistical_results,
                    )

                except (ImportError, AttributeError, RuntimeError, ValueError) as e:
                    logger.error(
                        "❌ Statistical comparison failed for %s vs %s: %s",
                        tool1,
                        tool2,
                        str(e),
                    )
                    statistical_results["pairwise_comparisons"][comparison_key] = {
                        "tools": [tool1, tool2],
                        "error": str(e),
                    }

        # Generate overall statistical summary
        statistical_results["overall_significance"] = (
            self._summarize_statistical_significance(
                statistical_results["pairwise_comparisons"]
            )
        )

        # Generate academic summary
        statistical_results["academic_findings"] = (
            self._generate_academic_statistical_findings(
                statistical_results["pairwise_comparisons"], tools
            )
        )

        # Save detailed statistical report
        statistical_report_path = (
            self.output_dir / "statistical_significance_report.json"
        )
        with open(statistical_report_path, "w", encoding="utf-8") as f:
            json.dump(statistical_results, f, indent=2, default=str)

        logger.info("✅ Statistical analysis completed")
        logger.info("📄 Statistical report saved to: %s", statistical_report_path)

        return statistical_results

    def _extract_comparison_findings(
        self,
        comparison_key: str,
        accuracy_comparison: Optional[Dict[str, Any]],
        latency_comparison: Optional[Dict[str, Any]],
        statistical_results: Dict[str, Any],
    ) -> None:
        """Extract key findings from a pairwise comparison"""
        findings = []

        if accuracy_comparison:
            sig_summary = accuracy_comparison.get("significance_summary", {})
            if sig_summary.get("bonferroni_corrected_significant"):
                evidence_strength = sig_summary.get("evidence_strength", "Unknown")
                conclusion = sig_summary.get(
                    "overall_conclusion", "Significant difference"
                )
                findings.append(
                    f"Accuracy: {evidence_strength} evidence - {conclusion}"
                )

        if latency_comparison:
            sig_summary = latency_comparison.get("significance_summary", {})
            if sig_summary.get("bonferroni_corrected_significant"):
                evidence_strength = sig_summary.get("evidence_strength", "Unknown")
                conclusion = sig_summary.get(
                    "overall_conclusion", "Significant difference"
                )
                findings.append(f"Latency: {evidence_strength} evidence - {conclusion}")

        if findings:
            statistical_results["statistical_summary"][comparison_key] = findings

    def _summarize_statistical_significance(
        self, pairwise_comparisons: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Summarize overall statistical significance across all comparisons"""
        total_comparisons = len(pairwise_comparisons)
        significant_accuracy = 0
        significant_latency = 0

        for comparison in pairwise_comparisons.values():
            if "error" in comparison:
                continue

            acc_comp = comparison.get("accuracy_comparison")
            if acc_comp and acc_comp.get("significance_summary", {}).get(
                "bonferroni_corrected_significant"
            ):
                significant_accuracy += 1

            lat_comp = comparison.get("latency_comparison")
            if lat_comp and lat_comp.get("significance_summary", {}).get(
                "bonferroni_corrected_significant"
            ):
                significant_latency += 1

        return {
            "total_comparisons": total_comparisons,
            "significant_accuracy_comparisons": significant_accuracy,
            "significant_latency_comparisons": significant_latency,
            "accuracy_significance_rate": (
                significant_accuracy / total_comparisons if total_comparisons > 0 else 0
            ),
            "latency_significance_rate": (
                significant_latency / total_comparisons if total_comparisons > 0 else 0
            ),
            "overall_significance_detected": (significant_accuracy > 0)
            or (significant_latency > 0),
        }

    def _generate_academic_statistical_findings(
        self, pairwise_comparisons: Dict[str, Any], tools: List[str]  # noqa: ARG002
    ) -> List[str]:
        """
        Generate academic-style findings from statistical comparisons
        
        Args:
            pairwise_comparisons: Dictionary of pairwise comparison results
            tools: List of tool names (currently unused but kept for API compatibility)
        """
        findings = []

        # Check for Code Guardian vs others comparisons
        code_guardian_comparisons = []
        for comparison_key, comparison in pairwise_comparisons.items():
            if "error" in comparison:
                continue

            tools_compared = comparison.get("tools", [])
            if "code-guardian" in tools_compared:
                other_tool = [t for t in tools_compared if t != "code-guardian"][0]

                acc_comp = comparison.get("accuracy_comparison")
                if acc_comp and acc_comp.get("significance_summary", {}).get(
                    "bonferroni_corrected_significant"
                ):
                    effect_sizes = acc_comp.get("effect_sizes", {})
                    improvement = effect_sizes.get("relative_improvement_pct")
                    if improvement and improvement > 0:
                        findings.append(
                            f"Code Guardian demonstrates statistically significant accuracy improvement "
                            f"over {other_tool} ({improvement:.1f}% relative improvement, p < 0.05)"
                        )
                    elif improvement and improvement < 0:
                        findings.append(
                            f"Code Guardian shows statistically significant lower accuracy compared to "
                            f"{other_tool} ({abs(improvement):.1f}% relative decrease, p < 0.05)"
                        )

                lat_comp = comparison.get("latency_comparison")
                if lat_comp and lat_comp.get("significance_summary", {}).get(
                    "bonferroni_corrected_significant"
                ):
                    effect_sizes = lat_comp.get("effect_sizes", {})
                    effect_size = effect_sizes.get("cohens_d", 0)
                    if effect_size > 0:
                        findings.append(
                            f"Code Guardian exhibits statistically significant lower latency compared to "
                            f"{other_tool} (Cohen's d = {effect_size:.3f}, p < 0.05)"
                        )

                code_guardian_comparisons.append(comparison_key)

        # General statistical robustness
        if len(code_guardian_comparisons) > 1:
            findings.append(
                f"Statistical significance testing conducted across {len(code_guardian_comparisons)} "
                f"tool comparisons with Bonferroni correction for multiple testing"
            )

        return findings

    def _generate_academic_summary(
        self, comprehensive_report: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Generate academic-style summary suitable for research papers

        Args:
            comprehensive_report: Complete evaluation results

        Returns:
            Academic summary with research findings
        """
        logger.info("📚 Generating academic summary...")

        tools_evaluated = comprehensive_report.get("tools_evaluated", [])
        comparative_analysis = comprehensive_report.get("comparative_analysis", {})

        academic_summary = {
            "research_context": {
                "evaluation_scope": f"Comprehensive evaluation of {len(tools_evaluated)} security analysis tools",
                "tools_compared": tools_evaluated,
                "evaluation_dimensions": [
                    "accuracy",
                    "latency",
                    "repair_quality",
                    "robustness",
                    "usability",
                ],
                "methodology": "Multi-dimensional quantitative evaluation with statistical analysis",
            },
            "key_findings": comparative_analysis.get("key_findings", []),
            "performance_metrics": {},
            "statistical_significance": {},
            "limitations": [
                "Dataset representativeness",
                "Evaluation environment specificity",
                "Human evaluation subjectivity in repair quality assessment",
                "Limited real-world deployment testing",
            ],
            "recommendations": [],
            "future_work": [
                "Expanded dataset coverage",
                "Longitudinal performance analysis",
                "Real-world deployment validation",
                "User study integration",
            ],
        }

        # Extract performance metrics for each tool
        individual_results = comprehensive_report.get("individual_results", {})
        for tool_name, tool_results in individual_results.items():
            if "error" not in tool_results:
                tool_metrics = {}

                # Accuracy metrics
                if (
                    "accuracy" in tool_results
                    and "error" not in tool_results["accuracy"]
                ):
                    acc = tool_results["accuracy"]
                    tool_metrics["accuracy"] = {
                        "precision": acc.get("precision", 0),
                        "recall": acc.get("recall", 0),
                        "f1_score": acc.get("f1_score", 0),
                    }

                # Latency metrics
                if "latency" in tool_results and "error" not in tool_results["latency"]:
                    lat = tool_results["latency"]
                    tool_metrics["latency"] = {
                        "median_ms": lat.get("median_latency_ms", 0),
                        "p95_ms": lat.get("p95_latency_ms", 0),
                    }

                # Overall score
                if "summary" in tool_results:
                    tool_metrics["overall_score"] = tool_results["summary"].get(
                        "overall_score", 0
                    )

                academic_summary["performance_metrics"][tool_name] = tool_metrics

        # Generate recommendations based on findings
        rankings = comparative_analysis.get("tool_rankings", [])
        if rankings:
            best_tool = rankings[0]["tool"]
            best_score = rankings[0]["overall_score"]

            if best_score >= 0.8:
                academic_summary["recommendations"].append(
                    f"{best_tool} demonstrates production-ready performance for security analysis"
                )
            elif best_score >= 0.6:
                academic_summary["recommendations"].append(
                    f"{best_tool} shows promise but requires targeted improvements"
                )
            else:
                academic_summary["recommendations"].append(
                    "All evaluated tools require significant improvements before production deployment"
                )

        return academic_summary

    def _generate_csv_reports(self, all_results: Dict[str, Any]) -> None:
        """Generate CSV reports for easy data analysis"""
        logger.info("📊 Generating CSV reports...")

        # Summary metrics CSV
        summary_data = []
        for tool_name, tool_results in all_results.items():
            if "error" not in tool_results and "summary" in tool_results:
                row = {"Tool": tool_name}
                row["Overall_Score"] = tool_results["summary"].get("overall_score", 0)

                # Add dimension scores
                dimension_scores = tool_results["summary"].get("dimension_scores", {})
                for dimension, score in dimension_scores.items():
                    row[f"{dimension}_score"] = score

                # Add data counts
                if "tool_info" in tool_results:
                    data_completeness = tool_results["tool_info"].get(
                        "data_completeness", {}
                    )
                    for data_type, count in data_completeness.items():
                        row[f"{data_type}_samples"] = count

                summary_data.append(row)

        if summary_data:
            summary_df = pd.DataFrame(summary_data)
            summary_csv_path = self.output_dir / "tools_summary_comparison.csv"
            summary_df.to_csv(summary_csv_path, index=False)
            logger.info("📄 Saved summary CSV: %s", summary_csv_path)

        # Detailed metrics CSV
        detailed_data = []
        for tool_name, tool_results in all_results.items():
            if "error" not in tool_results:
                base_row = {"Tool": tool_name}

                # Accuracy metrics
                if (
                    "accuracy" in tool_results
                    and "error" not in tool_results["accuracy"]
                ):
                    acc = tool_results["accuracy"]
                    acc_row = base_row.copy()
                    acc_row.update(
                        {
                            "Metric_Type": "Accuracy",
                            "Precision": acc.get("precision", 0),
                            "Recall": acc.get("recall", 0),
                            "F1_Score": acc.get("f1_score", 0),
                            "Accuracy": acc.get("accuracy", 0),
                        }
                    )
                    detailed_data.append(acc_row)

                # Latency metrics
                if "latency" in tool_results and "error" not in tool_results["latency"]:
                    lat = tool_results["latency"]
                    lat_row = base_row.copy()
                    lat_row.update(
                        {
                            "Metric_Type": "Latency",
                            "Mean_ms": lat.get("mean_latency_ms", 0),
                            "Median_ms": lat.get("median_latency_ms", 0),
                            "P95_ms": lat.get("p95_latency_ms", 0),
                            "P99_ms": lat.get("p99_latency_ms", 0),
                        }
                    )
                    detailed_data.append(lat_row)

        if detailed_data:
            detailed_df = pd.DataFrame(detailed_data)
            detailed_csv_path = self.output_dir / "detailed_metrics_comparison.csv"
            detailed_df.to_csv(detailed_csv_path, index=False)
            logger.info("📄 Saved detailed CSV: %s", detailed_csv_path)

    def run_tool_specific_evaluation(self, tool_name: str) -> Optional[Dict[str, Any]]:
        """
        Run evaluation for a specific tool only

        Args:
            tool_name: Name of the tool to evaluate

        Returns:
            Evaluation results for the specified tool
        """
        logger.info("🎯 Running evaluation for specific tool: %s", tool_name)

        tool_datasets = self.discover_tool_datasets()

        if tool_name not in tool_datasets:
            logger.error(
                "Tool '%s' not found in available datasets: %s", tool_name, list(tool_datasets.keys())
            )
            return None

        dataset = tool_datasets[tool_name]

        try:
            if self.orchestrator:
                results = self.orchestrator.run_complete_evaluation(
                    detection_data=dataset.detection_data,
                    latency_data=dataset.latency_data,
                    repair_data=dataset.repair_data,
                    robustness_data=dataset.robustness_data,
                    usability_data=dataset.usability_data,
                )
            else:
                # Fallback evaluation without orchestrator
                results = {
                    "error": "MetricsOrchestrator not available",
                    "summary": {"overall_score": 0, "dimension_scores": {}},
                }

            # Save tool-specific report
            tool_report_path = self.output_dir / f"{tool_name}_specific_evaluation.json"
            with open(tool_report_path, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2, default=str)

            logger.info("✅ Tool-specific evaluation completed for %s", tool_name)
            logger.info("📄 Report saved to: %s", tool_report_path)

            return results

        except (ImportError, AttributeError, RuntimeError) as e:
            logger.error("❌ Tool-specific evaluation failed for %s: %s", tool_name, e)
            return None


def main():
    """Main entry point for dynamic metrics evaluation"""
    parser = argparse.ArgumentParser(
        description="Dynamic Metrics Runner for Code Guardian Evaluation"
    )
    parser.add_argument(
        "--metrics-data-dir",
        type=Path,
        default=Path(__file__).parent.parent / "metrics-data",
        help="Directory containing tool metrics data",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(__file__).parent.parent / "evaluation_results",
        help="Directory to save evaluation results",
    )
    parser.add_argument("--tool", type=str, help="Evaluate specific tool only")
    parser.add_argument(
        "--list-tools", action="store_true", help="List available tools and exit"
    )

    args = parser.parse_args()

    # Initialize runner
    runner = DynamicMetricsRunner(args.metrics_data_dir, args.output_dir)

    if args.list_tools:
        # List available tools
        tool_datasets = runner.discover_tool_datasets()
        print("\n📊 Available Tools:")
        print("=" * 50)
        for tool_name, dataset in tool_datasets.items():
            print(f"  🔧 {tool_name}")
            print(f"     Detection samples: {len(dataset.detection_data)}")
            print(f"     Latency measurements: {len(dataset.latency_data)}")
            print(f"     Complete dataset: {'✅' if dataset.is_complete else '⚠️'}")
        print()
        return

    if args.tool:
        # Run tool-specific evaluation
        results = runner.run_tool_specific_evaluation(args.tool)
        if results:
            print(f"\n✅ Evaluation completed for {args.tool}")
            if "summary" in results:
                print(
                    f"Overall Score: {results['summary'].get('overall_score', 0):.3f}"
                )
        else:
            print(f"\n❌ Evaluation failed for {args.tool}")
    else:
        # Run comprehensive evaluation
        results = runner.run_comprehensive_evaluation()

        if "error" not in results:
            print("\n🎯 Comprehensive Evaluation Completed!")
            print("=" * 50)

            comparative_analysis = results.get("comparative_analysis", {})
            tool_rankings = comparative_analysis.get("tool_rankings", [])

            if tool_rankings:
                print("\n📈 Tool Rankings:")
                for i, tool_ranking in enumerate(tool_rankings, 1):
                    tool_name = tool_ranking["tool"]
                    overall_score = tool_ranking["overall_score"]
                    print(f"  {i}. {tool_name}: {overall_score:.3f}")

            key_findings = comparative_analysis.get("key_findings", [])
            if key_findings:
                print("\n🔍 Key Findings:")
                for finding in key_findings:
                    print(f"  • {finding}")

            print(f"\n📄 Reports saved to: {args.output_dir}")
        else:
            print(f"\n❌ Evaluation failed: {results['error']}")


if __name__ == "__main__":
    main()
