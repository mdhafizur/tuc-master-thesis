#!/usr/bin/env python3
"""
Latency Metrics Calculator for Code Guardian VS Code Extension

This module implements comprehensive latency analysis for evaluating the
Code Guardian extension's performance, including median response time,
percentile analysis, and statistical comparisons with baselines.

Academic Standards:
- Percentile-based analysis (P50, P95, P99)
- Statistical significance testing
- Performance regression detection
- Resource utilization correlation
"""

import statistics
import time
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
import json
import logging
from pathlib import Path
import numpy as np
import pandas as pd
from scipy import stats
from scipy.stats import mannwhitneyu, wilcoxon, ks_2samp, norm
from sklearn.metrics import mean_squared_error, mean_absolute_error

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class LatencyMeasurement:
    """Individual latency measurement from Code Guardian"""

    sample_id: str
    operation_type: str  # 'file_analysis', 'selection_analysis', 'quick_fix'
    latency_ms: float
    file_size_bytes: Optional[int] = None
    lines_of_code: Optional[int] = None
    vulnerability_count: Optional[int] = None
    model_name: Optional[str] = None
    timestamp: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "sample_id": self.sample_id,
            "operation_type": self.operation_type,
            "latency_ms": self.latency_ms,
            "file_size_bytes": self.file_size_bytes,
            "lines_of_code": self.lines_of_code,
            "vulnerability_count": self.vulnerability_count,
            "model_name": self.model_name,
            "timestamp": self.timestamp,
        }


@dataclass
class LatencyMetrics:
    """Comprehensive latency metrics"""

    operation_type: str
    n_measurements: int

    # Central tendency
    median_ms: float
    mean_ms: float

    # Percentiles
    p50_ms: float  # Same as median
    p95_ms: float
    p99_ms: float
    min_ms: float
    max_ms: float

    # Variability
    std_dev_ms: float
    coefficient_of_variation: float

    # Thresholds
    acceptable_threshold_ms: float = 1000  # 1 second
    fast_threshold_ms: float = 500  # 0.5 seconds

    # Performance categorization
    fast_responses_pct: float = 0.0  # % under fast threshold
    acceptable_responses_pct: float = 0.0  # % under acceptable threshold
    slow_responses_pct: float = 0.0  # % over acceptable threshold

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "operation_type": self.operation_type,
            "n_measurements": self.n_measurements,
            "median_ms": self.median_ms,
            "mean_ms": self.mean_ms,
            "p50_ms": self.p50_ms,
            "p95_ms": self.p95_ms,
            "p99_ms": self.p99_ms,
            "min_ms": self.min_ms,
            "max_ms": self.max_ms,
            "std_dev_ms": self.std_dev_ms,
            "coefficient_of_variation": self.coefficient_of_variation,
            "performance_thresholds": {
                "acceptable_threshold_ms": self.acceptable_threshold_ms,
                "fast_threshold_ms": self.fast_threshold_ms,
            },
            "performance_distribution": {
                "fast_responses_pct": self.fast_responses_pct,
                "acceptable_responses_pct": self.acceptable_responses_pct,
                "slow_responses_pct": self.slow_responses_pct,
            },
        }


class LatencyCalculator:
    """
    Main class for calculating latency metrics and performance analysis

    Features:
    - Percentile-based latency analysis
    - Performance threshold evaluation
    - Baseline comparison with statistical tests
    - File size and complexity correlation analysis
    - Model performance comparison
    """

    def __init__(
        self, acceptable_threshold_ms: float = 1000, fast_threshold_ms: float = 500
    ):
        """
        Initialize latency calculator

        Args:
            acceptable_threshold_ms: Maximum acceptable response time (ms)
            fast_threshold_ms: Threshold for "fast" responses (ms)
        """
        self.acceptable_threshold_ms = acceptable_threshold_ms
        self.fast_threshold_ms = fast_threshold_ms
        logger.info(
            "Initialized LatencyCalculator with thresholds: "
            "fast=%dms, acceptable=%dms",
            fast_threshold_ms,
            acceptable_threshold_ms,
        )

    def calculate_metrics(
        self, measurements: List[LatencyMeasurement]
    ) -> LatencyMetrics:
        """
        Calculate comprehensive latency metrics using numpy and scipy

        Args:
            measurements: List of latency measurements

        Returns:
            LatencyMetrics object with all computed metrics
        """
        if not measurements:
            raise ValueError("No measurements provided")

        operation_type = measurements[0].operation_type
        logger.info(
            "Calculating latency metrics for %d %s measurements",
            len(measurements),
            operation_type,
        )

        # Extract latency values and convert to numpy array
        latencies = np.array([m.latency_ms for m in measurements])
        n = len(latencies)

        # Central tendency using numpy
        median_ms = np.median(latencies)
        mean_ms = np.mean(latencies)

        # Percentiles using numpy
        p50_ms = median_ms
        p95_ms = np.percentile(latencies, 95)
        p99_ms = np.percentile(latencies, 99)
        min_ms = np.min(latencies)
        max_ms = np.max(latencies)

        # Variability using numpy
        std_dev_ms = np.std(latencies, ddof=1) if n > 1 else 0.0
        cv = std_dev_ms / mean_ms if mean_ms > 0 else 0.0

        # Performance categorization
        fast_count = np.sum(latencies <= self.fast_threshold_ms)
        acceptable_count = np.sum(latencies <= self.acceptable_threshold_ms)

        fast_pct = (fast_count / n) * 100
        acceptable_pct = (acceptable_count / n) * 100
        slow_pct = 100 - acceptable_pct

        latency_metrics = LatencyMetrics(
            operation_type=operation_type,
            n_measurements=n,
            median_ms=float(median_ms),
            mean_ms=float(mean_ms),
            p50_ms=float(p50_ms),
            p95_ms=float(p95_ms),
            p99_ms=float(p99_ms),
            min_ms=float(min_ms),
            max_ms=float(max_ms),
            std_dev_ms=float(std_dev_ms),
            coefficient_of_variation=float(cv),
            acceptable_threshold_ms=self.acceptable_threshold_ms,
            fast_threshold_ms=self.fast_threshold_ms,
            fast_responses_pct=float(fast_pct),
            acceptable_responses_pct=float(acceptable_pct),
            slow_responses_pct=float(slow_pct),
        )

        logger.info(
            "Calculated latency metrics: median=%.1fms, p95=%.1fms, "
            "%.1f%% fast, %.1f%% acceptable",
            median_ms,
            p95_ms,
            fast_pct,
            acceptable_pct,
        )

        return latency_metrics

    def analyze_by_operation_type(
        self, measurements: List[LatencyMeasurement]
    ) -> Dict[str, LatencyMetrics]:
        """
        Analyze latency by operation type

        Args:
            measurements: List of latency measurements

        Returns:
            Dictionary mapping operation types to their metrics
        """
        logger.info("Analyzing latency by operation type")

        # Group by operation type
        type_groups = {}
        for measurement in measurements:
            op_type = measurement.operation_type
            if op_type not in type_groups:
                type_groups[op_type] = []
            type_groups[op_type].append(measurement)

        # Calculate metrics for each type
        type_metrics = {}
        for op_type, type_measurements in type_groups.items():
            if (
                len(type_measurements) >= 3
            ):  # Minimum measurements for meaningful analysis
                type_metrics[op_type] = self.calculate_metrics(type_measurements)
                logger.info(
                    "%s: %d measurements, median=%.1fms",
                    op_type,
                    len(type_measurements),
                    type_metrics[op_type].median_ms,
                )

        return type_metrics

    def compare_models(
        self, measurements: List[LatencyMeasurement]
    ) -> Dict[str, LatencyMetrics]:
        """
        Compare latency across different models

        Args:
            measurements: List of latency measurements with model names

        Returns:
            Dictionary mapping model names to their metrics
        """
        logger.info("Comparing latency across models")

        # Group by model
        model_groups = {}
        for measurement in measurements:
            model = measurement.model_name or "unknown"
            if model not in model_groups:
                model_groups[model] = []
            model_groups[model].append(measurement)

        # Calculate metrics for each model
        model_metrics = {}
        for model, model_measurements in model_groups.items():
            if len(model_measurements) >= 5:  # Minimum for comparison
                model_metrics[model] = self.calculate_metrics(model_measurements)
                logger.info(
                    "%s: %d measurements, median=%.1fms",
                    model,
                    len(model_measurements),
                    model_metrics[model].median_ms,
                )

        return model_metrics

    def analyze_size_correlation(
        self, measurements: List[LatencyMeasurement]
    ) -> Dict[str, Any]:
        """
        Analyze correlation between file size/complexity and latency using scipy

        Args:
            measurements: List of measurements with size information

        Returns:
            Dictionary with correlation analysis
        """
        logger.info("Analyzing size-latency correlation")

        # Filter measurements with size information
        sized_measurements = [
            m
            for m in measurements
            if m.file_size_bytes is not None or m.lines_of_code is not None
        ]

        if len(sized_measurements) < 10:
            logger.warning(
                "Insufficient measurements with size information for correlation analysis"
            )
            return {"error": "Insufficient data for correlation analysis"}

        # Extract data for correlation using pandas
        df_data = []
        for m in sized_measurements:
            df_data.append(
                {
                    "latency_ms": m.latency_ms,
                    "file_size_bytes": m.file_size_bytes,
                    "lines_of_code": m.lines_of_code,
                }
            )

        df = pd.DataFrame(df_data)

        # Calculate correlations using scipy
        size_correlation = {}

        if df["file_size_bytes"].notna().sum() >= 10:
            # Use scipy's pearsonr for proper correlation with p-value
            corr_coef, p_value = stats.pearsonr(
                df["file_size_bytes"].dropna(),
                df.loc[df["file_size_bytes"].notna(), "latency_ms"],
            )
            size_correlation["file_size"] = {
                "correlation_coefficient": float(corr_coef),
                "p_value": float(p_value),
                "significant": p_value < 0.05,
                "sample_size": int(df["file_size_bytes"].notna().sum()),
            }

        if df["lines_of_code"].notna().sum() >= 10:
            corr_coef, p_value = stats.pearsonr(
                df["lines_of_code"].dropna(),
                df.loc[df["lines_of_code"].notna(), "latency_ms"],
            )
            size_correlation["lines_of_code"] = {
                "correlation_coefficient": float(corr_coef),
                "p_value": float(p_value),
                "significant": p_value < 0.05,
                "sample_size": int(df["lines_of_code"].notna().sum()),
            }

        # Size-based performance buckets
        size_buckets = self._analyze_size_buckets(sized_measurements)

        return {
            "correlation_analysis": size_correlation,
            "size_buckets": size_buckets,
            "n_measurements": len(sized_measurements),
            "pandas_summary": {
                "mean_latency": float(df["latency_ms"].mean()),
                "std_latency": float(df["latency_ms"].std()),
                "correlation_matrix": (
                    df.corr().to_dict() if len(df.columns) > 1 else {}
                ),
            },
        }

    def compare_with_baseline_statistical(
        self,
        code_guardian_measurements: List[LatencyMeasurement],
        baseline_measurements: List[LatencyMeasurement],
    ) -> Dict[str, Any]:
        """
        Compare latency with baseline using statistical significance tests

        Args:
            code_guardian_measurements: Latency measurements from Code Guardian
            baseline_measurements: Latency measurements from baseline tool

        Returns:
            Dictionary with statistical comparison results
        """
        logger.info(
            "Performing statistical latency comparison between Code Guardian and baseline"
        )

        # Extract latency values
        cg_latencies = [m.latency_ms for m in code_guardian_measurements]
        bl_latencies = [m.latency_ms for m in baseline_measurements]

        if len(cg_latencies) < 3 or len(bl_latencies) < 3:
            logger.warning("Insufficient samples for statistical comparison")
            return {"error": "Insufficient samples for statistical tests"}

        # Calculate basic metrics for both
        cg_metrics = self.calculate_metrics(code_guardian_measurements)
        bl_metrics = self.calculate_metrics(baseline_measurements)

        # Statistical tests
        statistical_results = {}

        # Mann-Whitney U test (non-parametric alternative to t-test)
        mannwhitney_result = self._mann_whitney_test(cg_latencies, bl_latencies)
        statistical_results["mann_whitney_u"] = mannwhitney_result

        # Wilcoxon signed-rank test (if paired samples available)
        if len(cg_latencies) == len(bl_latencies):
            wilcoxon_result = self._wilcoxon_test(cg_latencies, bl_latencies)
            statistical_results["wilcoxon_signed_rank"] = wilcoxon_result

        # Kolmogorov-Smirnov test (distribution comparison)
        ks_result = self._kolmogorov_smirnov_test(cg_latencies, bl_latencies)
        statistical_results["kolmogorov_smirnov"] = ks_result

        # Effect size (Cohen's d equivalent for medians)
        effect_size = self._calculate_effect_size(cg_latencies, bl_latencies)

        # Performance improvement calculation
        median_improvement_pct = (
            (bl_metrics.median_ms - cg_metrics.median_ms) / bl_metrics.median_ms
        ) * 100
        p95_improvement_pct = (
            (bl_metrics.p95_ms - cg_metrics.p95_ms) / bl_metrics.p95_ms
        ) * 100

        return {
            "code_guardian_metrics": cg_metrics.to_dict(),
            "baseline_metrics": bl_metrics.to_dict(),
            "statistical_tests": statistical_results,
            "effect_size": effect_size,
            "improvements": {
                "median_improvement_pct": median_improvement_pct,
                "p95_improvement_pct": p95_improvement_pct,
                "absolute_median_improvement_ms": bl_metrics.median_ms
                - cg_metrics.median_ms,
                "absolute_p95_improvement_ms": bl_metrics.p95_ms - cg_metrics.p95_ms,
            },
            "sample_sizes": {
                "code_guardian": len(cg_latencies),
                "baseline": len(bl_latencies),
            },
        }

    def _mann_whitney_test(
        self, group1: List[float], group2: List[float]
    ) -> Dict[str, Any]:
        """
        Perform Mann-Whitney U test using scipy.stats

        Args:
            group1: First group of latency measurements
            group2: Second group of latency measurements

        Returns:
            Dictionary with test results
        """
        try:
            # Use scipy implementation
            statistic, p_value = mannwhitneyu(group1, group2, alternative="two-sided")

            return {
                "test_name": "Mann-Whitney U Test",
                "statistic": float(statistic),
                "p_value": float(p_value),
                "significant": p_value < 0.05,
                "interpretation": (
                    "Groups have significantly different distributions"
                    if p_value < 0.05
                    else "No significant difference between groups"
                ),
                "effect_interpretation": self._interpret_mannwhitney_effect(
                    statistic, len(group1), len(group2)
                ),
            }

        except Exception as e:
            logger.error("Mann-Whitney test failed: %s", str(e))
            return {
                "test_name": "Mann-Whitney U Test",
                "error": str(e),
                "significant": None,
            }

    def _wilcoxon_test(
        self, group1: List[float], group2: List[float]
    ) -> Dict[str, Any]:
        """
        Perform Wilcoxon signed-rank test using scipy.stats

        Args:
            group1: First group of paired measurements
            group2: Second group of paired measurements

        Returns:
            Dictionary with test results
        """
        try:
            if len(group1) != len(group2):
                return {
                    "test_name": "Wilcoxon Signed-Rank Test",
                    "error": "Groups must have equal size for paired test",
                    "significant": None,
                }

            # Calculate differences
            differences = np.array(group1) - np.array(group2)

            # Remove zero differences
            non_zero_diffs = differences[differences != 0]

            if len(non_zero_diffs) < 6:
                return {
                    "test_name": "Wilcoxon Signed-Rank Test",
                    "error": "Insufficient non-zero differences for test",
                    "significant": None,
                }

            statistic, p_value = wilcoxon(non_zero_diffs)

            return {
                "test_name": "Wilcoxon Signed-Rank Test",
                "statistic": float(statistic),
                "p_value": float(p_value),
                "significant": p_value < 0.05,
                "interpretation": (
                    "Paired groups have significantly different medians"
                    if p_value < 0.05
                    else "No significant difference in paired medians"
                ),
                "n_pairs": len(non_zero_diffs),
            }

        except Exception as e:
            logger.error("Wilcoxon test failed: %s", str(e))
            return {
                "test_name": "Wilcoxon Signed-Rank Test",
                "error": str(e),
                "significant": None,
            }

    def _kolmogorov_smirnov_test(
        self, group1: List[float], group2: List[float]
    ) -> Dict[str, Any]:
        """
        Perform Kolmogorov-Smirnov test using scipy.stats

        Args:
            group1: First group of measurements
            group2: Second group of measurements

        Returns:
            Dictionary with test results
        """
        try:
            # Use scipy implementation
            statistic, p_value = ks_2samp(group1, group2)

            return {
                "test_name": "Kolmogorov-Smirnov Test",
                "statistic": float(statistic),
                "p_value": float(p_value),
                "significant": p_value < 0.05,
                "interpretation": (
                    "Distributions are significantly different"
                    if p_value < 0.05
                    else "No significant difference in distributions"
                ),
                "effect_size": (
                    "Large"
                    if statistic > 0.5
                    else "Medium" if statistic > 0.3 else "Small"
                ),
            }

        except Exception as e:
            logger.error("Kolmogorov-Smirnov test failed: %s", str(e))
            return {
                "test_name": "Kolmogorov-Smirnov Test",
                "error": str(e),
                "significant": None,
            }

    def _calculate_effect_size(
        self, group1: List[float], group2: List[float]
    ) -> Dict[str, Any]:
        """
        Calculate effect size using numpy and scipy

        Args:
            group1: First group of measurements
            group2: Second group of measurements

        Returns:
            Dictionary with effect size metrics
        """
        try:
            # Convert to numpy arrays
            g1 = np.array(group1)
            g2 = np.array(group2)

            # Basic statistics using numpy
            mean1, mean2 = np.mean(g1), np.mean(g2)
            median1, median2 = np.median(g1), np.median(g2)

            # Cohen's d using numpy
            if len(g1) > 1 and len(g2) > 1:
                std1 = np.std(g1, ddof=1)
                std2 = np.std(g2, ddof=1)

                # Pooled standard deviation
                n1, n2 = len(g1), len(g2)
                pooled_std = np.sqrt(
                    ((n1 - 1) * std1**2 + (n2 - 1) * std2**2) / (n1 + n2 - 2)
                )

                cohens_d = (mean1 - mean2) / pooled_std if pooled_std > 0 else 0
            else:
                cohens_d = 0

            # Effect size interpretation
            effect_interpretation = (
                "Large"
                if abs(cohens_d) > 0.8
                else (
                    "Medium"
                    if abs(cohens_d) > 0.5
                    else "Small" if abs(cohens_d) > 0.2 else "Negligible"
                )
            )

            # Median-based effect size (more robust for skewed distributions)
            median_diff_pct = (
                ((median2 - median1) / median1 * 100) if median1 > 0 else 0
            )

            return {
                "cohens_d": float(cohens_d),
                "effect_interpretation": effect_interpretation,
                "mean_difference": float(mean2 - mean1),
                "median_difference": float(median2 - median1),
                "median_difference_pct": float(median_diff_pct),
                "practical_significance": abs(median_diff_pct)
                > 10,  # >10% difference is practically significant
                "numpy_statistics": {
                    "group1_mean": float(mean1),
                    "group1_std": float(np.std(g1, ddof=1)),
                    "group2_mean": float(mean2),
                    "group2_std": float(np.std(g2, ddof=1)),
                },
            }
        except Exception as e:
            logger.error("Effect size calculation failed: %s", str(e))
            return {"error": str(e), "cohens_d": None, "practical_significance": None}

    def _interpret_mannwhitney_effect(self, statistic: float, n1: int, n2: int) -> str:
        """
        Interpret the effect size for Mann-Whitney U test

        Args:
            statistic: Test statistic
            n1: Size of first group
            n2: Size of second group

        Returns:
            Effect size interpretation
        """
        # Calculate U statistic if not provided
        u1 = statistic
        u2 = n1 * n2 - u1
        u_min = min(u1, u2)

        # Effect size (similar to Cohen's d categories)
        effect_size = 1 - (2 * u_min) / (n1 * n2)

        if effect_size > 0.7:
            return "Large effect"
        elif effect_size > 0.5:
            return "Medium effect"
        elif effect_size > 0.3:
            return "Small effect"
        else:
            return "Negligible effect"

    def _normal_cdf(self, x: float) -> float:
        """
        Approximate normal cumulative distribution function

        Args:
            x: Value to compute CDF for

        Returns:
            Approximate CDF value
        """
        # Simple approximation using error function approximation
        # This is a rough approximation for when scipy is not available
        if x < -5:
            return 0.0
        elif x > 5:
            return 1.0
        else:
            # Abramowitz and Stegun approximation
            a1, a2, a3, a4, a5 = (
                0.254829592,
                -0.284496736,
                1.421413741,
                -1.453152027,
                1.061405429,
            )
            p = 0.3275911

            sign = 1 if x >= 0 else -1
            x = abs(x) / (2**0.5)

            t = 1.0 / (1.0 + p * x)
            y = 1.0 - (((((a5 * t + a4) * t) + a3) * t + a2) * t + a1) * t * (
                2.71828 ** (-x * x)
            )

            return 0.5 * (1.0 + sign * y)

    def detect_performance_regression(
        self,
        baseline_measurements: List[LatencyMeasurement],
        current_measurements: List[LatencyMeasurement],
        threshold_pct: float = 10.0,
    ) -> Dict[str, Any]:
        """
        Detect performance regression using numpy for calculations

        Args:
            baseline_measurements: Historical performance measurements
            current_measurements: Current performance measurements
            threshold_pct: Regression threshold percentage

        Returns:
            Dictionary with regression analysis
        """
        logger.info(
            "Detecting performance regression with %.1f%% threshold", threshold_pct
        )

        baseline_metrics = self.calculate_metrics(baseline_measurements)
        current_metrics = self.calculate_metrics(current_measurements)

        # Calculate percentage changes
        median_change_pct = (
            (current_metrics.median_ms - baseline_metrics.median_ms)
            / baseline_metrics.median_ms
        ) * 100
        p95_change_pct = (
            (current_metrics.p95_ms - baseline_metrics.p95_ms) / baseline_metrics.p95_ms
        ) * 100

        # Detect regression
        median_regression = median_change_pct > threshold_pct
        p95_regression = p95_change_pct > threshold_pct

        # Performance category changes
        acceptable_change = (
            current_metrics.acceptable_responses_pct
            - baseline_metrics.acceptable_responses_pct
        )

        regression_analysis = {
            "baseline_metrics": baseline_metrics.to_dict(),
            "current_metrics": current_metrics.to_dict(),
            "changes": {
                "median_change_pct": median_change_pct,
                "p95_change_pct": p95_change_pct,
                "acceptable_responses_change_pct": acceptable_change,
            },
            "regression_detected": {
                "median_regression": median_regression,
                "p95_regression": p95_regression,
                "overall_regression": median_regression or p95_regression,
            },
            "threshold_pct": threshold_pct,
        }

        if regression_analysis["regression_detected"]["overall_regression"]:
            logger.warning(
                "Performance regression detected! Median: %.1f%%, P95: %.1f%%",
                median_change_pct,
                p95_change_pct,
            )
        else:
            logger.info("No significant performance regression detected")

        return regression_analysis

    def generate_report(
        self, measurements: List[LatencyMeasurement], output_path: Optional[Path] = None
    ) -> Dict[str, Any]:
        """
        Generate comprehensive latency report using pandas and scipy

        Args:
            measurements: Latency measurements to analyze
            output_path: Optional path to save report

        Returns:
            Dictionary with complete analysis
        """
        logger.info("Generating latency report for %d measurements", len(measurements))

        # Overall metrics
        overall_metrics = self.calculate_metrics(measurements)

        # By operation type
        operation_metrics = self.analyze_by_operation_type(measurements)

        # By model
        model_metrics = self.compare_models(measurements)

        # Size correlation
        size_analysis = self.analyze_size_correlation(measurements)

        # Summary statistics using pandas if we have enough data
        if len(measurements) > 10:
            df_data = [m.to_dict() for m in measurements]
            df = pd.DataFrame(df_data)
            pandas_summary = {
                "descriptive_statistics": df["latency_ms"].describe().to_dict(),
                "operation_type_summary": (
                    df.groupby("operation_type")["latency_ms"].describe().to_dict()
                    if "operation_type" in df.columns
                    else {}
                ),
            }
        else:
            pandas_summary = {"note": "Insufficient data for pandas analysis"}

        report_data = {
            "timestamp": time.time(),
            "summary": {
                "total_measurements": len(measurements),
                "operation_types": list(set(m.operation_type for m in measurements)),
                "models_tested": list(
                    set(m.model_name for m in measurements if m.model_name)
                ),
                "time_range_hours": self._calculate_time_range(measurements),
            },
            "overall_metrics": overall_metrics.to_dict(),
            "by_operation_type": {
                op_type: metrics_data.to_dict()
                for op_type, metrics_data in operation_metrics.items()
            },
            "by_model": {
                model: metrics_data.to_dict()
                for model, metrics_data in model_metrics.items()
            },
            "size_analysis": size_analysis,
            "pandas_summary": pandas_summary,
            "configuration": {
                "acceptable_threshold_ms": self.acceptable_threshold_ms,
                "fast_threshold_ms": self.fast_threshold_ms,
            },
        }

        # Save report if path provided
        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(report_data, f, indent=2)
            logger.info("Saved latency report to %s", output_path)

        return report_data

    def _simple_correlation(
        self, x_values: List[float], y_values: List[float]
    ) -> float:
        """
        Calculate simple correlation coefficient (Pearson)

        Args:
            x_values: Independent variable values
            y_values: Dependent variable values

        Returns:
            Correlation coefficient (-1 to 1)
        """
        if len(x_values) != len(y_values) or len(x_values) < 2:
            return 0.0

        n = len(x_values)
        x_mean = sum(x_values) / n
        y_mean = sum(y_values) / n

        numerator = sum((x - x_mean) * (y - y_mean) for x, y in zip(x_values, y_values))
        x_var = sum((x - x_mean) ** 2 for x in x_values)
        y_var = sum((y - y_mean) ** 2 for y in y_values)

        denominator = (x_var * y_var) ** 0.5

        return numerator / denominator if denominator > 0 else 0.0

    def _analyze_size_buckets(
        self, measurements: List[LatencyMeasurement]
    ) -> Dict[str, Any]:
        """
        Analyze performance across different file size buckets using pandas

        Args:
            measurements: List of measurements with size information

        Returns:
            Dictionary with size bucket analysis
        """
        # Define size buckets (lines of code)
        size_buckets = {
            "small": (0, 100),
            "medium": (100, 500),
            "large": (500, 1000),
            "very_large": (1000, float("inf")),
        }

        # Create DataFrame for easier analysis
        df_data = []
        for measurement in measurements:
            if measurement.lines_of_code is not None:
                df_data.append(
                    {
                        "latency_ms": measurement.latency_ms,
                        "lines_of_code": measurement.lines_of_code,
                    }
                )

        if not df_data:
            return {"error": "No measurements with lines_of_code available"}

        df = pd.DataFrame(df_data)

        # Categorize by size buckets
        def categorize_size(lines):
            for bucket, (min_lines, max_lines) in size_buckets.items():
                if min_lines <= lines < max_lines:
                    return bucket
            return "very_large"

        df["size_bucket"] = df["lines_of_code"].apply(categorize_size)

        # Calculate metrics for each bucket using pandas
        bucket_metrics = {}
        for bucket in size_buckets.keys():
            bucket_data = df[df["size_bucket"] == bucket]
            if len(bucket_data) >= 3:
                bucket_metrics[bucket] = {
                    "n_measurements": len(bucket_data),
                    "median_latency_ms": float(bucket_data["latency_ms"].median()),
                    "mean_latency_ms": float(bucket_data["latency_ms"].mean()),
                    "std_latency_ms": float(bucket_data["latency_ms"].std()),
                    "size_range": size_buckets[bucket],
                }

        return bucket_metrics

    def generate_report(
        self, measurements: List[LatencyMeasurement], output_path: Optional[Path] = None
    ) -> Dict[str, Any]:
        """
        Generate comprehensive latency report

        Args:
            measurements: Latency measurements to analyze
            output_path: Optional path to save report

        Returns:
            Dictionary with complete analysis
        """
        logger.info("Generating latency report for %d measurements", len(measurements))

        # Overall metrics
        overall_metrics = self.calculate_metrics(measurements)

        # By operation type
        operation_metrics = self.analyze_by_operation_type(measurements)

        # By model
        model_metrics = self.compare_models(measurements)

        # Size correlation
        size_analysis = self.analyze_size_correlation(measurements)

        # Summary statistics
        report_data = {
            "timestamp": time.time(),
            "summary": {
                "total_measurements": len(measurements),
                "operation_types": list(set(m.operation_type for m in measurements)),
                "models_tested": list(
                    set(m.model_name for m in measurements if m.model_name)
                ),
                "time_range_hours": self._calculate_time_range(measurements),
            },
            "overall_metrics": overall_metrics.to_dict(),
            "by_operation_type": {
                op_type: metrics_data.to_dict()
                for op_type, metrics_data in operation_metrics.items()
            },
            "by_model": {
                model: metrics_data.to_dict()
                for model, metrics_data in model_metrics.items()
            },
            "size_analysis": size_analysis,
            "configuration": {
                "acceptable_threshold_ms": self.acceptable_threshold_ms,
                "fast_threshold_ms": self.fast_threshold_ms,
            },
        }

        # Save report if path provided
        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(report_data, f, indent=2)
            logger.info("Saved latency report to %s", output_path)

        return report_data

    def _calculate_time_range(
        self, measurements: List[LatencyMeasurement]
    ) -> Optional[float]:
        """Calculate time range of measurements in hours"""
        timestamps = [m.timestamp for m in measurements if m.timestamp is not None]
        if len(timestamps) < 2:
            return None

        time_range_seconds = max(timestamps) - min(timestamps)
        return time_range_seconds / 3600  # Convert to hours


def load_latency_measurements(file_path: Path) -> List[LatencyMeasurement]:
    """
    Load latency measurements from JSON file

    Args:
        file_path: Path to JSON file with latency measurements

    Returns:
        List of LatencyMeasurement objects
    """
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    measurements = []
    for item in data:
        measurement = LatencyMeasurement(
            sample_id=item["sample_id"],
            operation_type=item["operation_type"],
            latency_ms=item["latency_ms"],
            file_size_bytes=item.get("file_size_bytes"),
            lines_of_code=item.get("lines_of_code"),
            vulnerability_count=item.get("vulnerability_count"),
            model_name=item.get("model_name"),
            timestamp=item.get("timestamp"),
        )
        measurements.append(measurement)

    return measurements


class LatencyBenchmark:
    """Utility class for running latency benchmarks"""

    def __init__(self):
        self.measurements = []

    def start_measurement(
        self, sample_id: str, operation_type: str
    ) -> "LatencyMeasurement":
        """Start a latency measurement"""
        return {
            "sample_id": sample_id,
            "operation_type": operation_type,
            "start_time": time.time(),
        }

    def end_measurement(
        self, measurement_context: Dict[str, Any], **kwargs
    ) -> LatencyMeasurement:
        """End a latency measurement and create LatencyMeasurement object"""
        end_time = time.time()
        latency_ms = (end_time - measurement_context["start_time"]) * 1000

        measurement = LatencyMeasurement(
            sample_id=measurement_context["sample_id"],
            operation_type=measurement_context["operation_type"],
            latency_ms=latency_ms,
            timestamp=end_time,
            **kwargs,
        )

        self.measurements.append(measurement)
        return measurement

    def get_measurements(self) -> List[LatencyMeasurement]:
        """Get all collected measurements"""
        return self.measurements.copy()


if __name__ == "__main__":
    # Example usage
    calculator = LatencyCalculator(acceptable_threshold_ms=1000, fast_threshold_ms=500)

    # Example measurements
    example_measurements = [
        LatencyMeasurement(
            "sample_1", "file_analysis", 450, 2048, 85, 2, "codelama-7b"
        ),
        LatencyMeasurement(
            "sample_2", "file_analysis", 850, 4096, 200, 5, "codelama-7b"
        ),
        LatencyMeasurement(
            "sample_3", "selection_analysis", 200, 512, 25, 1, "phi-3-mini"
        ),
        LatencyMeasurement("sample_4", "quick_fix", 1200, 1024, 45, 1, "starcoder-15b"),
    ]

    # Calculate metrics
    overall_metrics = calculator.calculate_metrics(example_measurements)
    print("Overall Latency Metrics:")
    print(f"Median: {overall_metrics.median_ms:.1f}ms")
    print(f"P95: {overall_metrics.p95_ms:.1f}ms")
    print(f"Fast responses: {overall_metrics.fast_responses_pct:.1f}%")
    print(f"Acceptable responses: {overall_metrics.acceptable_responses_pct:.1f}%")

    # Generate report
    report = calculator.generate_report(example_measurements)
    print(
        f"Generated report with {report['summary']['total_measurements']} measurements"
    )
