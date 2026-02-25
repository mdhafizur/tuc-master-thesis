#!/usr/bin/env python3
"""
Robustness Metrics Calculator for Code Guardian VS Code Extension

This module evaluates the robustness of Code Guardian across different conditions:
- Performance under edge cases
- Behavior with malformed inputs
- Consistency across different environments
- Stability under stress conditions

Academic Standards:
- Stress testing protocols
- Edge case coverage analysis
- Environmental consistency measurement
- Statistical stability assessment
"""

import re
import json
import logging
import statistics
import numpy as np
import pandas as pd
from scipy import stats
from scipy.stats import mannwhitneyu, wilcoxon, kruskal, chi2_contingency
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from pathlib import Path
from enum import Enum

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class StressTestType(Enum):
    """Types of stress tests"""

    LARGE_FILES = "large_files"
    DEEPLY_NESTED = "deeply_nested"
    MANY_VULNERABILITIES = "many_vulnerabilities"
    COMPLEX_SYNTAX = "complex_syntax"
    UNICODE_EDGE_CASES = "unicode_edge_cases"
    MEMORY_PRESSURE = "memory_pressure"
    CONCURRENT_REQUESTS = "concurrent_requests"
    TIMEOUT_CONDITIONS = "timeout_conditions"


class EnvironmentType(Enum):
    """Environment configurations for testing"""

    LOCAL_VSCODE = "local_vscode"
    CLOUD_VSCODE = "cloud_vscode"
    CODESPACES = "codespaces"
    REMOTE_SSH = "remote_ssh"
    CONTAINERS = "containers"
    LOW_MEMORY = "low_memory"
    HIGH_LATENCY = "high_latency"


@dataclass
class EdgeCaseTest:
    """Individual edge case test scenario"""

    test_id: str
    test_type: StressTestType
    description: str
    input_code: str
    expected_behavior: str

    # Test parameters
    file_size_kb: Optional[int] = None
    nesting_depth: Optional[int] = None
    vulnerability_count: Optional[int] = None
    complexity_score: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "test_id": self.test_id,
            "test_type": self.test_type.value,
            "description": self.description,
            "input_code": self.input_code,
            "expected_behavior": self.expected_behavior,
            "file_size_kb": self.file_size_kb,
            "nesting_depth": self.nesting_depth,
            "vulnerability_count": self.vulnerability_count,
            "complexity_score": self.complexity_score,
        }


@dataclass
class RobustnessTestResult:
    """Result of a robustness test"""

    test_id: str
    environment: EnvironmentType

    # Execution results
    completed_successfully: bool
    execution_time_ms: float

    # Detection results
    detected_vulnerabilities: int
    false_positives: int
    false_negatives: int

    # Error handling
    graceful_degradation: bool = True
    error_occurred: bool = False
    memory_usage_mb: Optional[float] = None
    error_type: Optional[str] = None
    error_message: Optional[str] = None

    # Performance metrics
    response_latency_p95: Optional[float] = None
    cpu_usage_percent: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "test_id": self.test_id,
            "environment": self.environment.value,
            "completed_successfully": self.completed_successfully,
            "execution_time_ms": self.execution_time_ms,
            "memory_usage_mb": self.memory_usage_mb,
            "detected_vulnerabilities": self.detected_vulnerabilities,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "error_occurred": self.error_occurred,
            "error_type": self.error_type,
            "error_message": self.error_message,
            "graceful_degradation": self.graceful_degradation,
            "response_latency_p95": self.response_latency_p95,
            "cpu_usage_percent": self.cpu_usage_percent,
        }


@dataclass
class RobustnessMetrics:
    """Comprehensive robustness metrics"""

    n_tests: int
    n_environments: int

    # Overall stability
    success_rate: float
    error_rate: float
    graceful_degradation_rate: float

    # Performance under stress
    avg_execution_time_ms: float
    p95_execution_time_ms: float
    performance_degradation_factor: float

    # Consistency metrics
    cross_environment_consistency: float
    detection_variance: float

    # Error analysis
    by_error_type: Dict[str, int]
    by_test_type: Dict[str, float]
    by_environment: Dict[str, float]

    # Stress test specific
    large_file_handling: float  # Success rate for large files
    nesting_limit_stability: float  # Stability at deep nesting
    concurrent_handling: float  # Performance under concurrency

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "n_tests": self.n_tests,
            "n_environments": self.n_environments,
            "overall_stability": {
                "success_rate": self.success_rate,
                "error_rate": self.error_rate,
                "graceful_degradation_rate": self.graceful_degradation_rate,
            },
            "performance_under_stress": {
                "avg_execution_time_ms": self.avg_execution_time_ms,
                "p95_execution_time_ms": self.p95_execution_time_ms,
                "performance_degradation_factor": self.performance_degradation_factor,
            },
            "consistency_metrics": {
                "cross_environment_consistency": self.cross_environment_consistency,
                "detection_variance": self.detection_variance,
            },
            "error_analysis": {
                "by_error_type": self.by_error_type,
                "by_test_type": self.by_test_type,
                "by_environment": self.by_environment,
            },
            "stress_test_results": {
                "large_file_handling": self.large_file_handling,
                "nesting_limit_stability": self.nesting_limit_stability,
                "concurrent_handling": self.concurrent_handling,
            },
        }


class RobustnessCalculator:
    """
    Main class for calculating robustness metrics

    Features:
    - Edge case stress testing
    - Environmental consistency evaluation
    - Performance degradation analysis
    - Error handling assessment
    - Statistical stability measurement
    """

    def __init__(
        self,
        baseline_execution_time_ms: float = 1000.0,
        consistency_threshold: float = 0.8,
        max_degradation_factor: float = 5.0,
    ):
        """
        Initialize robustness calculator

        Args:
            baseline_execution_time_ms: Expected normal execution time
            consistency_threshold: Minimum consistency score for robustness
            max_degradation_factor: Maximum acceptable performance degradation
        """
        self.baseline_execution_time = baseline_execution_time_ms
        self.consistency_threshold = consistency_threshold
        self.max_degradation_factor = max_degradation_factor
        logger.info(
            "Initialized RobustnessCalculator with baseline: %.2fms",
            baseline_execution_time_ms,
        )

    def calculate_metrics(
        self,
        edge_case_tests: List[EdgeCaseTest],
        test_results: List[RobustnessTestResult],
    ) -> RobustnessMetrics:
        """
        Calculate comprehensive robustness metrics using pandas and numpy

        Args:
            edge_case_tests: List of edge case test definitions
            test_results: List of test execution results

        Returns:
            RobustnessMetrics object with all computed metrics
        """
        logger.info(
            "Calculating robustness metrics for %d tests with %d results",
            len(edge_case_tests),
            len(test_results),
        )

        if not test_results:
            raise ValueError("Test results are required")

        # Create DataFrame for analysis
        results_df = pd.DataFrame([r.to_dict() for r in test_results])
        tests_df = pd.DataFrame([t.to_dict() for t in edge_case_tests])

        # Merge test definitions with results
        merged_df = pd.merge(results_df, tests_df, on="test_id", how="left")

        # Basic statistics
        n_tests = len(results_df)
        n_environments = len(results_df["environment"].unique())

        # Overall stability metrics using pandas
        success_rate = float(results_df["completed_successfully"].mean())
        error_rate = float(results_df["error_occurred"].mean())
        graceful_degradation_rate = float(results_df["graceful_degradation"].mean())

        # Performance metrics using numpy
        execution_times = results_df["execution_time_ms"].dropna().values
        avg_execution_time = (
            float(np.mean(execution_times)) if len(execution_times) > 0 else 0.0
        )
        p95_execution_time = (
            float(np.percentile(execution_times, 95))
            if len(execution_times) > 0
            else 0.0
        )

        performance_degradation = (
            avg_execution_time / self.baseline_execution_time
            if self.baseline_execution_time > 0
            else 1.0
        )

        # Consistency analysis using pandas groupby and numpy
        cross_env_consistency = self._calculate_cross_environment_consistency_pandas(
            results_df
        )
        detection_variance = self._calculate_detection_variance_pandas(results_df)

        # Error analysis using pandas
        error_analysis = self._analyze_errors_pandas(results_df)

        # Test type analysis using merged DataFrame
        test_type_analysis = self._analyze_by_test_type_pandas(merged_df)

        # Environment analysis using pandas groupby
        environment_analysis = self._analyze_by_environment_pandas(results_df)

        # Stress test specific metrics
        stress_metrics = self._calculate_stress_metrics_pandas(merged_df)

        robustness_metrics = RobustnessMetrics(
            n_tests=n_tests,
            n_environments=n_environments,
            success_rate=success_rate,
            error_rate=error_rate,
            graceful_degradation_rate=graceful_degradation_rate,
            avg_execution_time_ms=avg_execution_time,
            p95_execution_time_ms=p95_execution_time,
            performance_degradation_factor=performance_degradation,
            cross_environment_consistency=cross_env_consistency,
            detection_variance=detection_variance,
            by_error_type=error_analysis["by_error_type"],
            by_test_type=test_type_analysis,
            by_environment=environment_analysis,
            large_file_handling=stress_metrics["large_file_handling"],
            nesting_limit_stability=stress_metrics["nesting_limit_stability"],
            concurrent_handling=stress_metrics["concurrent_handling"],
        )

        logger.info(
            "Calculated robustness metrics: success=%.1f%%, consistency=%.2f, degradation=%.1fx",
            success_rate * 100,
            cross_env_consistency,
            performance_degradation,
        )

        return robustness_metrics

    def generate_edge_case_tests(
        self, base_vulnerability_samples: List[Dict[str, Any]]
    ) -> List[EdgeCaseTest]:
        """
        Generate edge case tests from base vulnerability samples

        Args:
            base_vulnerability_samples: Base samples to create edge cases from

        Returns:
            List of EdgeCaseTest objects
        """
        logger.info(
            "Generating edge case tests from %d base samples",
            len(base_vulnerability_samples),
        )

        edge_cases = []

        for i, sample in enumerate(
            base_vulnerability_samples[:10]
        ):  # Limit for demonstration
            code = sample.get("code", "")
            vuln_type = sample.get("vulnerability_type", "unknown")

            # Large file test
            large_code = self._create_large_file_version(code)
            edge_cases.append(
                EdgeCaseTest(
                    f"large_file_{i}",
                    StressTestType.LARGE_FILES,
                    f"Large file version of {vuln_type} vulnerability",
                    large_code,
                    "Should detect vulnerability despite large file size",
                    file_size_kb=len(large_code) // 1024,
                )
            )

            # Deeply nested test
            nested_code = self._create_deeply_nested_version(code)
            edge_cases.append(
                EdgeCaseTest(
                    f"nested_{i}",
                    StressTestType.DEEPLY_NESTED,
                    f"Deeply nested version of {vuln_type} vulnerability",
                    nested_code,
                    "Should detect vulnerability in deeply nested structure",
                    nesting_depth=self._count_nesting_depth(nested_code),
                )
            )

            # Multiple vulnerabilities test
            multi_vuln_code = self._create_multiple_vulnerabilities_version(code)
            edge_cases.append(
                EdgeCaseTest(
                    f"multi_vuln_{i}",
                    StressTestType.MANY_VULNERABILITIES,
                    f"Multiple {vuln_type} vulnerabilities in one file",
                    multi_vuln_code,
                    "Should detect all vulnerability instances",
                    vulnerability_count=self._count_expected_vulnerabilities(
                        multi_vuln_code, vuln_type
                    ),
                )
            )

            # Unicode edge case
            unicode_code = self._create_unicode_edge_case(code)
            edge_cases.append(
                EdgeCaseTest(
                    f"unicode_{i}",
                    StressTestType.UNICODE_EDGE_CASES,
                    f"Unicode characters with {vuln_type} vulnerability",
                    unicode_code,
                    "Should handle Unicode correctly and detect vulnerability",
                    complexity_score=self._calculate_code_complexity(unicode_code),
                )
            )

        logger.info("Generated %d edge case tests", len(edge_cases))
        return edge_cases

    def assess_environmental_consistency(
        self, test_results: List[RobustnessTestResult]
    ) -> Dict[str, Any]:
        """
        Assess consistency across different environments

        Args:
            test_results: Test results from multiple environments

        Returns:
            Dictionary with consistency analysis
        """
        logger.info(
            "Assessing environmental consistency across %d test results",
            len(test_results),
        )

        # Group by test_id and environment
        env_results = {}
        for result in test_results:
            test_id = result.test_id
            env = result.environment.value

            if test_id not in env_results:
                env_results[test_id] = {}
            env_results[test_id][env] = result

        # Calculate consistency metrics
        consistency_scores = []
        performance_variance = []
        detection_consistency = []

        for test_id, env_data in env_results.items():
            if len(env_data) < 2:  # Need at least 2 environments for consistency
                continue

            # Success consistency
            success_rates = [
                1 if r.completed_successfully else 0 for r in env_data.values()
            ]
            success_consistency = 1.0 - (max(success_rates) - min(success_rates))
            consistency_scores.append(success_consistency)

            # Performance consistency
            exec_times = [
                r.execution_time_ms
                for r in env_data.values()
                if r.execution_time_ms is not None
            ]
            if len(exec_times) >= 2:
                mean_time = statistics.mean(exec_times)
                variance = statistics.variance(exec_times) if len(exec_times) > 1 else 0
                cv = (variance**0.5) / mean_time if mean_time > 0 else 0
                performance_variance.append(cv)

            # Detection consistency
            detections = [r.detected_vulnerabilities for r in env_data.values()]
            if len(detections) >= 2:
                detection_std = (
                    statistics.stdev(detections) if len(detections) > 1 else 0
                )
                detection_mean = statistics.mean(detections)
                detection_cv = (
                    detection_std / detection_mean if detection_mean > 0 else 0
                )
                detection_consistency.append(1.0 - min(detection_cv, 1.0))

        # Calculate overall metrics
        overall_consistency = (
            statistics.mean(consistency_scores) if consistency_scores else 0.0
        )
        avg_performance_variance = (
            statistics.mean(performance_variance) if performance_variance else 0.0
        )
        avg_detection_consistency = (
            statistics.mean(detection_consistency) if detection_consistency else 0.0
        )

        return {
            "overall_consistency": overall_consistency,
            "performance_variance": avg_performance_variance,
            "detection_consistency": avg_detection_consistency,
            "n_tests_analyzed": len(consistency_scores),
            "environments_tested": list(
                set(result.environment.value for result in test_results)
            ),
        }

    def _calculate_cross_environment_consistency_pandas(
        self, df: pd.DataFrame
    ) -> float:
        """Calculate consistency score across environments using pandas"""
        if len(df) == 0:
            return 0.0

        # Group by test_id and calculate success rate per environment
        env_success = (
            df.groupby(["test_id", "environment"])["completed_successfully"]
            .mean()
            .reset_index()
        )

        # Calculate variance in success rates across environments for each test
        test_variances = env_success.groupby("test_id")["completed_successfully"].var()

        # Overall consistency is 1 - mean variance (lower variance = higher consistency)
        mean_variance = test_variances.mean() if not test_variances.empty else 0.0
        consistency = max(0.0, 1.0 - mean_variance)

        return float(consistency)

    def _calculate_detection_variance_pandas(self, df: pd.DataFrame) -> float:
        """Calculate detection variance using pandas"""
        if len(df) == 0:
            return 0.0

        # Calculate coefficient of variation for detected vulnerabilities
        detected_vulns = df["detected_vulnerabilities"].dropna()
        if len(detected_vulns) < 2:
            return 0.0

        mean_detected = detected_vulns.mean()
        std_detected = detected_vulns.std()

        return float(std_detected / mean_detected) if mean_detected > 0 else 0.0

    def _analyze_errors_pandas(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Analyze errors by type using pandas"""
        if len(df) == 0:
            return {"by_error_type": {}}

        # Group by error type and calculate statistics
        error_analysis = {}
        if "error_type" in df.columns:
            error_stats = (
                df.groupby("error_type")
                .agg(
                    {
                        "error_occurred": "sum",
                        "execution_time_ms": ["mean", "std"],
                        "completed_successfully": "mean",
                    }
                )
                .round(3)
            )

            error_analysis = error_stats.to_dict("index")

        return {"by_error_type": error_analysis}

    def _analyze_by_test_type_pandas(
        self, df: pd.DataFrame
    ) -> Dict[str, Dict[str, float]]:
        """Analyze performance by test type using pandas"""
        if len(df) == 0 or "test_type" not in df.columns:
            return {}

        test_type_stats = (
            df.groupby("test_type")
            .agg(
                {
                    "completed_successfully": "mean",
                    "execution_time_ms": "mean",
                    "detected_vulnerabilities": "mean",
                    "error_occurred": "mean",
                }
            )
            .round(3)
        )

        return test_type_stats.to_dict("index")

    def _analyze_by_environment_pandas(
        self, df: pd.DataFrame
    ) -> Dict[str, Dict[str, float]]:
        """Analyze performance by environment using pandas"""
        if len(df) == 0:
            return {}

        env_stats = (
            df.groupby("environment")
            .agg(
                {
                    "completed_successfully": "mean",
                    "execution_time_ms": ["mean", "std"],
                    "detected_vulnerabilities": "mean",
                    "graceful_degradation": "mean",
                }
            )
            .round(3)
        )

        return env_stats.to_dict("index")

    def _calculate_stress_metrics_pandas(
        self, df: pd.DataFrame
    ) -> Dict[str, Dict[str, float]]:
        """Calculate stress test specific metrics using pandas"""
        stress_metrics = {
            "large_file_handling": {},
            "nesting_limit_stability": {},
            "concurrent_handling": {},
        }

        if len(df) == 0:
            return stress_metrics

        # Large file handling analysis
        if "file_size_kb" in df.columns:
            large_files = df[df["file_size_kb"].notna() & (df["file_size_kb"] > 100)]
            if not large_files.empty:
                stress_metrics["large_file_handling"] = {
                    "success_rate": float(large_files["completed_successfully"].mean()),
                    "avg_execution_time": float(
                        large_files["execution_time_ms"].mean()
                    ),
                    "performance_impact": float(
                        large_files["execution_time_ms"].mean()
                        / df["execution_time_ms"].mean()
                        if df["execution_time_ms"].mean() > 0
                        else 1.0
                    ),
                }

        # Nesting limit stability
        if "nesting_depth" in df.columns:
            deep_nested = df[df["nesting_depth"].notna() & (df["nesting_depth"] > 10)]
            if not deep_nested.empty:
                stress_metrics["nesting_limit_stability"] = {
                    "success_rate": float(deep_nested["completed_successfully"].mean()),
                    "max_depth_handled": float(deep_nested["nesting_depth"].max()),
                    "avg_execution_time": float(
                        deep_nested["execution_time_ms"].mean()
                    ),
                }

        # Concurrent handling (if applicable)
        concurrent_tests = df[
            df["test_type"].str.contains("concurrent", case=False, na=False)
        ]
        if not concurrent_tests.empty:
            stress_metrics["concurrent_handling"] = {
                "success_rate": float(
                    concurrent_tests["completed_successfully"].mean()
                ),
                "avg_execution_time": float(
                    concurrent_tests["execution_time_ms"].mean()
                ),
            }

        return stress_metrics

    def _calculate_cross_environment_consistency(
        self, test_results: List[RobustnessTestResult]
    ) -> float:
        """Calculate consistency score across environments"""
        env_consistency = self.assess_environmental_consistency(test_results)
        return env_consistency["overall_consistency"]

    def _calculate_detection_variance(
        self, test_results: List[RobustnessTestResult]
    ) -> float:
        """Calculate variance in detection results"""
        detections = [r.detected_vulnerabilities for r in test_results]
        if len(detections) <= 1:
            return 0.0

        variance = statistics.variance(detections)
        mean_detections = statistics.mean(detections)

        # Normalized variance (coefficient of variation)
        return variance / (mean_detections**2) if mean_detections > 0 else 0.0

    def _analyze_errors(
        self, test_results: List[RobustnessTestResult]
    ) -> Dict[str, Any]:
        """Analyze error patterns in test results"""
        error_results = [r for r in test_results if r.error_occurred]

        error_types = {}
        for result in error_results:
            error_type = result.error_type or "unknown"
            error_types[error_type] = error_types.get(error_type, 0) + 1

        return {
            "by_error_type": error_types,
            "total_errors": len(error_results),
            "unique_error_types": len(error_types),
        }

    def _analyze_by_test_type(
        self, edge_tests: List[EdgeCaseTest], test_results: List[RobustnessTestResult]
    ) -> Dict[str, float]:
        """Analyze success rates by test type"""
        test_type_map = {test.test_id: test.test_type for test in edge_tests}

        type_results = {}
        for result in test_results:
            if result.test_id in test_type_map:
                test_type = test_type_map[result.test_id].value
                if test_type not in type_results:
                    type_results[test_type] = []
                type_results[test_type].append(result.completed_successfully)

        type_success_rates = {}
        for test_type, successes in type_results.items():
            type_success_rates[test_type] = (
                sum(successes) / len(successes) if successes else 0.0
            )

        return type_success_rates

    def _analyze_by_environment(
        self, test_results: List[RobustnessTestResult]
    ) -> Dict[str, float]:
        """Analyze success rates by environment"""
        env_results = {}
        for result in test_results:
            env = result.environment.value
            if env not in env_results:
                env_results[env] = []
            env_results[env].append(result.completed_successfully)

        env_success_rates = {}
        for env, successes in env_results.items():
            env_success_rates[env] = (
                sum(successes) / len(successes) if successes else 0.0
            )

        return env_success_rates

    def _calculate_stress_metrics(
        self, edge_tests: List[EdgeCaseTest], test_results: List[RobustnessTestResult]
    ) -> Dict[str, float]:
        """Calculate stress-specific metrics"""
        test_type_map = {test.test_id: test.test_type for test in edge_tests}

        # Large file handling
        large_file_results = [
            r.completed_successfully
            for r in test_results
            if r.test_id in test_type_map
            and test_type_map[r.test_id] == StressTestType.LARGE_FILES
        ]
        large_file_handling = (
            sum(large_file_results) / len(large_file_results)
            if large_file_results
            else 0.0
        )

        # Nesting stability
        nesting_results = [
            r.completed_successfully
            for r in test_results
            if r.test_id in test_type_map
            and test_type_map[r.test_id] == StressTestType.DEEPLY_NESTED
        ]
        nesting_stability = (
            sum(nesting_results) / len(nesting_results) if nesting_results else 0.0
        )

        # Concurrent handling
        concurrent_results = [
            r.completed_successfully
            for r in test_results
            if r.test_id in test_type_map
            and test_type_map[r.test_id] == StressTestType.CONCURRENT_REQUESTS
        ]
        concurrent_handling = (
            sum(concurrent_results) / len(concurrent_results)
            if concurrent_results
            else 0.0
        )

        return {
            "large_file_handling": large_file_handling,
            "nesting_limit_stability": nesting_stability,
            "concurrent_handling": concurrent_handling,
        }

    def _calculate_percentile(self, values: List[float], percentile: int) -> float:
        """Calculate percentile of values"""
        if not values:
            return 0.0

        sorted_values = sorted(values)
        k = (len(sorted_values) - 1) * percentile / 100
        f = int(k)
        c = k - f

        if f + 1 < len(sorted_values):
            return sorted_values[f] * (1 - c) + sorted_values[f + 1] * c
        else:
            return sorted_values[f]

    def _create_large_file_version(self, code: str) -> str:
        """Create a large file version by adding padding content"""
        padding_lines = []
        for i in range(500):  # Add 500 lines of realistic padding
            padding_lines.extend(
                [
                    f"// Generated utility function {i}",
                    f"function utilityFunction{i}() {{",
                    f"    const data = 'sample data {i}';",
                    "    return data.length > 0;",
                    "}",
                    "",
                ]
            )

        padding = "\n".join(padding_lines)
        return f"{padding}\n\n// ORIGINAL CODE START\n{code}\n// ORIGINAL CODE END\n\n{padding}"

    def _create_deeply_nested_version(self, code: str) -> str:
        """Create deeply nested version of code"""
        nested_prefix = ""
        nested_suffix = ""

        for i in range(15):  # Create 15 levels of nesting
            nested_prefix += f"if (condition{i}) {{\n" + "    " * (i + 1)
            nested_suffix = "\n" + "    " * i + "}" + nested_suffix

        # Indent the original code
        indented_code = "\n".join("    " * 15 + line for line in code.split("\n"))

        return f"{nested_prefix}\n{indented_code}\n{nested_suffix}"

    def _create_multiple_vulnerabilities_version(self, code: str) -> str:
        """Create version with multiple instances of the vulnerability"""
        variations = []

        # Create 5 variations of the original vulnerable code
        for i in range(5):
            variation = code.replace("user", f"user{i}")
            variation = variation.replace("input", f"input{i}")
            variation = variation.replace("query", f"query{i}")
            variations.append(f"// Variation {i + 1}\n{variation}")

        return "\n\n".join(variations)

    def _create_unicode_edge_case(self, code: str) -> str:
        """Create version with Unicode edge cases"""
        # Add Unicode variable names and strings
        unicode_code = code.replace("user", "用户")
        unicode_code = unicode_code.replace("input", "输入")
        unicode_code = unicode_code.replace("'sample'", "'🔒🛡️ sàmplé 测试'")

        return f"// Unicode test case\n{unicode_code}"

    def _count_nesting_depth(self, code: str) -> int:
        """Count maximum nesting depth in code"""
        max_depth = 0
        current_depth = 0

        for char in code:
            if char == "{":
                current_depth += 1
                max_depth = max(max_depth, current_depth)
            elif char == "}":
                current_depth = max(0, current_depth - 1)

        return max_depth

    def _count_expected_vulnerabilities(self, code: str, vuln_type: str) -> int:
        """Count expected number of vulnerabilities in code"""
        # Simple heuristic based on vulnerability patterns
        patterns = {
            "sql-injection": [r"query.*\+", r"execute.*\+", r"SELECT.*\+"],
            "xss": [r"innerHTML\s*=", r"document\.write", r"eval\s*\("],
            "command-injection": [r"exec\s*\(", r"system\s*\(", r"spawn\s*\("],
        }

        vuln_patterns = patterns.get(vuln_type, [])
        count = 0

        for pattern in vuln_patterns:
            count += len(re.findall(pattern, code, re.IGNORECASE))

        return max(count, 1)  # At least 1 if any patterns found

    def _calculate_code_complexity(self, code: str) -> float:
        """Calculate code complexity score"""
        # Simple complexity based on various factors
        lines = len(code.split("\n"))
        functions = len(re.findall(r"\bfunction\b", code, re.IGNORECASE))
        conditionals = len(
            re.findall(r"\b(if|for|while|switch)\b", code, re.IGNORECASE)
        )
        nesting_depth = self._count_nesting_depth(code)

        complexity = (
            lines * 0.1 + functions * 2 + conditionals * 1.5 + nesting_depth * 3
        )
        return complexity

    def generate_report(
        self,
        edge_case_tests: List[EdgeCaseTest],
        test_results: List[RobustnessTestResult],
        output_path: Optional[Path] = None,
    ) -> Dict[str, Any]:
        """
        Generate comprehensive robustness report

        Args:
            edge_case_tests: Edge case test definitions
            test_results: Test execution results
            output_path: Optional path to save report

        Returns:
            Dictionary with complete analysis
        """
        logger.info("Generating robustness report for %d tests", len(test_results))

        # Calculate main metrics
        robustness_metrics = self.calculate_metrics(edge_case_tests, test_results)

        # Additional analysis
        environmental_analysis = self.assess_environmental_consistency(test_results)

        report_data = {
            "timestamp": json.dumps(None),  # Would use datetime in real implementation
            "summary": {
                "total_tests": len(test_results),
                "total_edge_cases": len(edge_case_tests),
                "environments_tested": list(
                    set(r.environment.value for r in test_results)
                ),
                "test_types": list(set(t.test_type.value for t in edge_case_tests)),
            },
            "robustness_metrics": robustness_metrics.to_dict(),
            "environmental_analysis": environmental_analysis,
            "configuration": {
                "baseline_execution_time_ms": self.baseline_execution_time,
                "consistency_threshold": self.consistency_threshold,
                "max_degradation_factor": self.max_degradation_factor,
            },
        }

        # Save report if path provided
        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(report_data, f, indent=2)
            logger.info("Saved robustness report to %s", output_path)

        return report_data


if __name__ == "__main__":
    # Example usage
    calculator = RobustnessCalculator(
        baseline_execution_time_ms=1000.0, consistency_threshold=0.8
    )

    # Example edge case tests
    example_tests = [
        EdgeCaseTest(
            "large_file_1",
            StressTestType.LARGE_FILES,
            "Large SQL injection test",
            "SELECT * FROM users WHERE id = ' + userId" * 100,
            "Should detect vulnerability despite large size",
            file_size_kb=50,
        )
    ]

    # Example test results
    example_results = [
        RobustnessTestResult(
            "large_file_1", EnvironmentType.LOCAL_VSCODE, True, 2500.0, 45.0, 1, 0, 0
        )
    ]

    # Calculate metrics
    example_robustness_metrics = calculator.calculate_metrics(
        example_tests, example_results
    )
    print(f"Success Rate: {example_robustness_metrics.success_rate:.1%}")
    print(
        f"Performance Degradation: {example_robustness_metrics.performance_degradation_factor:.1f}x"
    )
    print(
        f"Cross-Environment Consistency: {example_robustness_metrics.cross_environment_consistency:.2f}"
    )

    # Generate report
    report = calculator.generate_report(example_tests, example_results)
    print(f"Generated robustness report for {report['summary']['total_tests']} tests")
