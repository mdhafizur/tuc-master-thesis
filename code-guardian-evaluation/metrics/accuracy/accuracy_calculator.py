#!/usr/bin/env python3
"""
Accuracy Metrics Calculator for Code Guardian VS Code Extension

This module implements comprehensive accuracy metrics for evaluating the
Code Guardian extension's vulnerability detection performance, including
precision, recall, F1-score, and statistical significance testing.

Academic Standards:
- McNemar's test for statistical significance
- Bootstrap confidence intervals
- Expected Calibration Error (ECE)
- Confusion matrix analysis
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from scipy import stats
from scipy.stats import chi2_contingency, fisher_exact
from statsmodels.stats.contingency_tables import mcnemar
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
    roc_auc_score,
    precision_recall_curve,
    roc_curve,
    auc,
)
from sklearn.utils import resample
import json
import logging
from pathlib import Path
import matplotlib.pyplot as plt
import seaborn as sns

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class DetectionResult:
    """Individual detection result from Code Guardian or baseline"""

    sample_id: str
    true_label: bool  # True if vulnerable
    predicted_label: bool  # True if detected as vulnerable
    confidence: Optional[float] = None  # Confidence score (0-1)
    detection_time_ms: Optional[float] = None
    vulnerability_type: Optional[str] = None
    tool_name: str = "code_guardian"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "sample_id": self.sample_id,
            "true_label": self.true_label,
            "predicted_label": self.predicted_label,
            "confidence": self.confidence,
            "detection_time_ms": self.detection_time_ms,
            "vulnerability_type": self.vulnerability_type,
            "tool_name": self.tool_name,
        }


@dataclass
class AccuracyMetrics:
    """Comprehensive accuracy metrics with confidence intervals"""

    precision: float
    recall: float
    f1_score: float
    accuracy: float
    specificity: float
    false_positive_rate: float
    false_negative_rate: float

    # Confidence intervals (95% by default)
    precision_ci: Tuple[float, float]
    recall_ci: Tuple[float, float]
    f1_ci: Tuple[float, float]

    # Confusion matrix components
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int

    # Statistical significance
    mcnemar_p_value: Optional[float] = None
    expected_calibration_error: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "precision": self.precision,
            "recall": self.recall,
            "f1_score": self.f1_score,
            "accuracy": self.accuracy,
            "specificity": self.specificity,
            "false_positive_rate": self.false_positive_rate,
            "false_negative_rate": self.false_negative_rate,
            "precision_ci": self.precision_ci,
            "recall_ci": self.recall_ci,
            "f1_ci": self.f1_ci,
            "confusion_matrix": {
                "true_positives": self.true_positives,
                "false_positives": self.false_positives,
                "true_negatives": self.true_negatives,
                "false_negatives": self.false_negatives,
            },
            "mcnemar_p_value": self.mcnemar_p_value,
            "expected_calibration_error": self.expected_calibration_error,
        }


class AccuracyCalculator:
    """
    Main class for calculating accuracy metrics with statistical analysis

    Features:
    - Precision, recall, F1-score calculation
    - Bootstrap confidence intervals
    - McNemar's test for baseline comparison
    - Expected Calibration Error for confidence analysis
    - Vulnerability type breakdown
    """

    def __init__(self, n_bootstrap: int = 1000, confidence_level: float = 0.95):
        """
        Initialize accuracy calculator

        Args:
            n_bootstrap: Number of bootstrap samples for confidence intervals
            confidence_level: Confidence level for intervals (default 95%)
        """
        self.n_bootstrap = n_bootstrap
        self.confidence_level = confidence_level
        self.alpha = 1 - confidence_level
        logger.info(
            f"Initialized AccuracyCalculator with {n_bootstrap} bootstrap samples"
        )

    def calculate_metrics(self, results: List[DetectionResult]) -> AccuracyMetrics:
        """
        Calculate comprehensive accuracy metrics using scikit-learn

        Args:
            results: List of detection results

        Returns:
            AccuracyMetrics object with all computed metrics
        """
        logger.info(f"Calculating accuracy metrics for {len(results)} results")

        # Extract predictions and ground truth
        y_true = np.array([r.true_label for r in results])
        y_pred = np.array([r.predicted_label for r in results])

        # Use scikit-learn for core metrics
        precision = precision_score(y_true, y_pred, zero_division=0)
        recall = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)
        accuracy = accuracy_score(y_true, y_pred)

        # Confusion matrix using sklearn
        cm = confusion_matrix(y_true, y_pred)
        # Handle edge cases where confusion matrix might not be 2x2
        if cm.shape == (2, 2):
            tn, fp, fn, tp = cm.ravel()
        elif len(np.unique(y_true)) == 1 and len(np.unique(y_pred)) == 1:
            # Only one class present
            if y_true[0] == y_pred[0]:
                tp, fp, tn, fn = len(y_true), 0, 0, 0
            else:
                tp, fp, tn, fn = 0, len(y_true), 0, 0
        else:
            # Handle other edge cases
            tp = int(np.sum((y_true == 1) & (y_pred == 1)))
            fp = int(np.sum((y_true == 0) & (y_pred == 1)))
            tn = int(np.sum((y_true == 0) & (y_pred == 0)))
            fn = int(np.sum((y_true == 1) & (y_pred == 0)))

        # Additional metrics
        specificity = tn / (tn + fp) if (tn + fp) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

        # Bootstrap confidence intervals using sklearn's resample
        precision_ci = self._bootstrap_ci_sklearn(y_true, y_pred, precision_score)
        recall_ci = self._bootstrap_ci_sklearn(y_true, y_pred, recall_score)
        f1_ci = self._bootstrap_ci_sklearn(y_true, y_pred, f1_score)

        # Expected Calibration Error (if confidence scores available)
        ece = (
            self._calculate_ece(results)
            if any(r.confidence is not None for r in results)
            else None
        )

        metrics = AccuracyMetrics(
            precision=precision,
            recall=recall,
            f1_score=f1,
            accuracy=accuracy,
            specificity=specificity,
            false_positive_rate=fpr,
            false_negative_rate=fnr,
            precision_ci=precision_ci,
            recall_ci=recall_ci,
            f1_ci=f1_ci,
            true_positives=tp,
            false_positives=fp,
            true_negatives=tn,
            false_negatives=fn,
            expected_calibration_error=ece,
        )

        logger.info(
            f"Calculated metrics: P={precision:.3f}, R={recall:.3f}, F1={f1:.3f}"
        )
        return metrics

    def comprehensive_statistical_comparison(
        self,
        code_guardian_results: List[DetectionResult],
        baseline_results: List[DetectionResult],
    ) -> Dict[str, Any]:
        """
        Comprehensive statistical comparison with multiple tests

        Args:
            code_guardian_results: Results from Code Guardian
            baseline_results: Results from baseline tool

        Returns:
            Dictionary with comprehensive statistical analysis
        """
        logger.info("Performing comprehensive statistical comparison")

        # Basic comparison
        basic_comparison = self.compare_with_baseline(
            code_guardian_results, baseline_results
        )

        # Ensure same samples for additional tests
        cg_dict = {r.sample_id: r for r in code_guardian_results}
        bl_dict = {r.sample_id: r for r in baseline_results}
        common_ids = set(cg_dict.keys()) & set(bl_dict.keys())

        if len(common_ids) < 10:
            logger.warning("Insufficient common samples for robust statistical testing")
            return {
                "basic_comparison": basic_comparison,
                "warning": "Insufficient samples for comprehensive testing",
            }

        # Extract aligned data
        y_true = []
        cg_pred = []
        bl_pred = []
        cg_conf = []
        bl_conf = []

        for sample_id in sorted(common_ids):
            cg_result = cg_dict[sample_id]
            bl_result = bl_dict[sample_id]

            y_true.append(cg_result.true_label)
            cg_pred.append(cg_result.predicted_label)
            bl_pred.append(bl_result.predicted_label)

            if cg_result.confidence is not None:
                cg_conf.append(cg_result.confidence)
            if bl_result.confidence is not None:
                bl_conf.append(bl_result.confidence)

        # Convert to arrays
        y_true = np.array(y_true)
        cg_pred = np.array(cg_pred)
        bl_pred = np.array(bl_pred)

        # Additional statistical tests
        additional_tests = {}

        # Chi-square test for independence (if enough samples)
        chi_square_result = self._chi_square_test(y_true, cg_pred, bl_pred)
        additional_tests["chi_square"] = chi_square_result

        # Fisher's exact test (for small samples or sparse contingency tables)
        fisher_result = self._fisher_exact_test(y_true, cg_pred, bl_pred)
        additional_tests["fisher_exact"] = fisher_result

        # Confidence interval comparison
        ci_comparison = self._confidence_interval_comparison(cg_pred, bl_pred, y_true)
        additional_tests["confidence_interval_comparison"] = ci_comparison

        # Proportions test (z-test for proportions)
        proportions_test = self._proportions_z_test(cg_pred, bl_pred, y_true)
        additional_tests["proportions_z_test"] = proportions_test

        # Effect size calculations
        effect_sizes = self._calculate_accuracy_effect_sizes(y_true, cg_pred, bl_pred)

        # Meta-analysis of significance
        significance_summary = self._summarize_significance(
            basic_comparison, additional_tests
        )

        return {
            "basic_comparison": basic_comparison,
            "additional_tests": additional_tests,
            "effect_sizes": effect_sizes,
            "significance_summary": significance_summary,
            "sample_size": len(common_ids),
            "test_power_analysis": self._calculate_test_power(len(common_ids)),
        }

    def _chi_square_test(
        self, y_true: np.ndarray, pred1: np.ndarray, pred2: np.ndarray
    ) -> Dict[str, Any]:
        """
        Perform chi-square test for independence using scipy.stats

        Args:
            y_true: Ground truth labels
            pred1: Predictions from first tool
            pred2: Predictions from second tool

        Returns:
            Dictionary with chi-square test results
        """
        try:
            # Create 2x2 contingency table for tool predictions
            tool1_correct = pred1 == y_true
            tool2_correct = pred2 == y_true

            both_correct = np.sum(tool1_correct & tool2_correct)
            tool1_only = np.sum(tool1_correct & ~tool2_correct)
            tool2_only = np.sum(~tool1_correct & tool2_correct)
            both_wrong = np.sum(~tool1_correct & ~tool2_correct)

            contingency_table = np.array(
                [[both_correct, tool1_only], [tool2_only, both_wrong]]
            )

            chi2, p_value, dof, expected = chi2_contingency(contingency_table)

            return {
                "test_name": "Chi-square Test of Independence",
                "chi2_statistic": float(chi2),
                "p_value": float(p_value),
                "degrees_of_freedom": int(dof),
                "significant": p_value < 0.05,
                "contingency_table": contingency_table.tolist(),
                "expected_frequencies": expected.tolist(),
                "interpretation": (
                    "Tool performances are significantly dependent"
                    if p_value < 0.05
                    else "No significant dependence between tool performances"
                ),
            }

        except Exception as e:
            logger.error("Chi-square test failed: %s", str(e))
            return {
                "test_name": "Chi-square Test",
                "error": str(e),
                "significant": None,
            }

    def _fisher_exact_test(
        self, y_true: np.ndarray, pred1: np.ndarray, pred2: np.ndarray
    ) -> Dict[str, Any]:
        """
        Perform Fisher's exact test using scipy.stats

        Args:
            y_true: Ground truth labels
            pred1: Predictions from first tool
            pred2: Predictions from second tool

        Returns:
            Dictionary with Fisher's exact test results
        """
        try:
            # Create contingency table
            tool1_correct = pred1 == y_true
            tool2_correct = pred2 == y_true

            both_correct = np.sum(tool1_correct & tool2_correct)
            tool1_only = np.sum(tool1_correct & ~tool2_correct)
            tool2_only = np.sum(~tool1_correct & tool2_correct)
            both_wrong = np.sum(~tool1_correct & ~tool2_correct)

            contingency_table = np.array(
                [[both_correct, tool1_only], [tool2_only, both_wrong]]
            )

            odds_ratio, p_value = fisher_exact(contingency_table)

            return {
                "test_name": "Fisher's Exact Test",
                "odds_ratio": float(odds_ratio),
                "p_value": float(p_value),
                "significant": p_value < 0.05,
                "contingency_table": contingency_table.tolist(),
                "interpretation": (
                    "Significant association between tool performances"
                    if p_value < 0.05
                    else "No significant association between tool performances"
                ),
            }

        except Exception as e:
            logger.error("Fisher's exact test failed: %s", str(e))
            return {
                "test_name": "Fisher's Exact Test",
                "error": str(e),
                "significant": None,
            }

    def _confidence_interval_comparison(
        self, pred1: np.ndarray, pred2: np.ndarray, y_true: np.ndarray
    ) -> Dict[str, Any]:
        """
        Compare confidence intervals of accuracy metrics using scipy.stats

        Args:
            pred1: Predictions from first tool
            pred2: Predictions from second tool
            y_true: Ground truth labels

        Returns:
            Dictionary with CI comparison results
        """
        from scipy.stats import norm

        # Calculate accuracies
        acc1 = np.mean(pred1 == y_true)
        acc2 = np.mean(pred2 == y_true)

        n1, n2 = len(pred1), len(pred2)

        # Calculate 95% confidence intervals using normal approximation
        z = norm.ppf(0.975)  # 95% confidence

        # CI for tool 1 (Wilson score interval)
        p1 = acc1
        ci1_lower = (
            p1 + z**2 / (2 * n1) - z * np.sqrt(p1 * (1 - p1) / n1 + z**2 / (4 * n1**2))
        ) / (1 + z**2 / n1)
        ci1_upper = (
            p1 + z**2 / (2 * n1) + z * np.sqrt(p1 * (1 - p1) / n1 + z**2 / (4 * n1**2))
        ) / (1 + z**2 / n1)

        # CI for tool 2
        p2 = acc2
        ci2_lower = (
            p2 + z**2 / (2 * n2) - z * np.sqrt(p2 * (1 - p2) / n2 + z**2 / (4 * n2**2))
        ) / (1 + z**2 / n2)
        ci2_upper = (
            p2 + z**2 / (2 * n2) + z * np.sqrt(p2 * (1 - p2) / n2 + z**2 / (4 * n2**2))
        ) / (1 + z**2 / n2)

        # Check for overlap
        no_overlap = (ci1_lower > ci2_upper) or (ci2_lower > ci1_upper)

        return {
            "tool1_accuracy": float(acc1),
            "tool1_ci": [float(ci1_lower), float(ci1_upper)],
            "tool2_accuracy": float(acc2),
            "tool2_ci": [float(ci2_lower), float(ci2_upper)],
            "confidence_intervals_overlap": not no_overlap,
            "significant_difference": no_overlap,
            "accuracy_difference": float(acc1 - acc2),
            "interpretation": (
                "Significantly different accuracies (non-overlapping CIs)"
                if no_overlap
                else "No significant difference (overlapping CIs)"
            ),
        }

    def _proportions_z_test(
        self, pred1: np.ndarray, pred2: np.ndarray, y_true: np.ndarray
    ) -> Dict[str, Any]:
        """
        Perform z-test for comparing two proportions using scipy.stats

        Args:
            pred1: Predictions from first tool
            pred2: Predictions from second tool
            y_true: Ground truth labels

        Returns:
            Dictionary with z-test results
        """
        try:
            # Calculate sample statistics
            n1, n2 = len(pred1), len(pred2)
            x1 = np.sum(pred1 == y_true)  # successes for tool 1
            x2 = np.sum(pred2 == y_true)  # successes for tool 2

            p1 = x1 / n1  # proportion for tool 1
            p2 = x2 / n2  # proportion for tool 2

            # Use scipy.stats for proper z-test
            from scipy.stats import norm

            # Pooled proportion
            p_pooled = (x1 + x2) / (n1 + n2)

            # Standard error
            se = np.sqrt(p_pooled * (1 - p_pooled) * (1 / n1 + 1 / n2))

            # Z-statistic
            z_stat = (p1 - p2) / se if se > 0 else 0

            # Two-tailed p-value using scipy
            p_value = 2 * (1 - norm.cdf(abs(z_stat)))

            return {
                "test_name": "Two-Proportion Z-Test",
                "z_statistic": float(z_stat),
                "p_value": float(p_value),
                "significant": p_value < 0.05,
                "tool1_proportion": float(p1),
                "tool2_proportion": float(p2),
                "proportion_difference": float(p1 - p2),
                "pooled_proportion": float(p_pooled),
                "standard_error": float(se),
                "interpretation": (
                    "Significantly different accuracy rates"
                    if p_value < 0.05
                    else "No significant difference in accuracy rates"
                ),
            }
        except Exception as e:
            logger.error("Proportions z-test failed: %s", str(e))
            return {
                "test_name": "Two-Proportion Z-Test",
                "error": str(e),
                "significant": None,
            }

    def _calculate_accuracy_effect_sizes(
        self, y_true: np.ndarray, pred1: np.ndarray, pred2: np.ndarray
    ) -> Dict[str, Any]:
        """
        Calculate various effect sizes for accuracy comparison

        Args:
            y_true: Ground truth labels
            pred1: Predictions from first tool
            pred2: Predictions from second tool

        Returns:
            Dictionary with effect size metrics
        """
        # Basic accuracies
        acc1 = np.mean(pred1 == y_true)
        acc2 = np.mean(pred2 == y_true)

        # Cohen's h for proportions
        p1, p2 = acc1, acc2
        cohens_h = 2 * (np.arcsin(np.sqrt(p1)) - np.arcsin(np.sqrt(p2)))

        # Odds ratio
        tp1, fp1, tn1, fn1 = self._confusion_matrix_components(y_true, pred1)
        tp2, fp2, tn2, fn2 = self._confusion_matrix_components(y_true, pred2)

        # Calculate odds ratio (accuracy odds)
        odds1 = (tp1 + tn1) / (fp1 + fn1) if (fp1 + fn1) > 0 else float("inf")
        odds2 = (tp2 + tn2) / (fp2 + fn2) if (fp2 + fn2) > 0 else float("inf")
        odds_ratio = (
            odds1 / odds2 if odds2 > 0 and odds2 != float("inf") else float("inf")
        )

        # Risk ratio (relative risk)
        risk_ratio = acc1 / acc2 if acc2 > 0 else float("inf")

        # Absolute difference in accuracy
        absolute_difference = acc1 - acc2

        # Relative improvement
        relative_improvement = absolute_difference / acc2 if acc2 > 0 else float("inf")

        # Effect size interpretation
        effect_interpretation = (
            "Large"
            if abs(cohens_h) > 0.8
            else (
                "Medium"
                if abs(cohens_h) > 0.5
                else "Small" if abs(cohens_h) > 0.2 else "Negligible"
            )
        )

        return {
            "cohens_h": float(cohens_h),
            "effect_interpretation": effect_interpretation,
            "odds_ratio": float(odds_ratio) if odds_ratio != float("inf") else None,
            "risk_ratio": float(risk_ratio) if risk_ratio != float("inf") else None,
            "absolute_difference": float(absolute_difference),
            "relative_improvement": (
                float(relative_improvement)
                if relative_improvement != float("inf")
                else None
            ),
            "practical_significance": abs(absolute_difference) > 0.05,  # >5% difference
        }

    def _summarize_significance(
        self, basic_comparison: Dict[str, Any], additional_tests: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Summarize significance across all tests

        Args:
            basic_comparison: Results from basic McNemar's test
            additional_tests: Results from additional statistical tests

        Returns:
            Summary of significance findings
        """
        significant_tests = []
        total_tests = 0

        # Check McNemar's test
        if "mcnemar_test" in basic_comparison and basic_comparison["mcnemar_test"].get(
            "significant"
        ):
            significant_tests.append("McNemar")
        if "mcnemar_test" in basic_comparison:
            total_tests += 1

        # Check additional tests
        for test_name, test_result in additional_tests.items():
            if isinstance(test_result, dict) and test_result.get("significant"):
                significant_tests.append(test_name)
            if isinstance(test_result, dict) and "significant" in test_result:
                total_tests += 1

        # Multiple testing correction (Bonferroni)
        bonferroni_alpha = 0.05 / total_tests if total_tests > 0 else 0.05

        return {
            "significant_tests": significant_tests,
            "total_tests_performed": total_tests,
            "proportion_significant": (
                len(significant_tests) / total_tests if total_tests > 0 else 0
            ),
            "overall_significance": len(significant_tests) > 0,
            "bonferroni_corrected_alpha": bonferroni_alpha,
            "robust_significance": len(significant_tests)
            >= total_tests // 2,  # Majority of tests significant
            "interpretation": self._interpret_overall_significance(
                significant_tests, total_tests
            ),
        }

    def _calculate_test_power(self, sample_size: int) -> Dict[str, Any]:
        """
        Calculate statistical test power analysis

        Args:
            sample_size: Number of samples in the test

        Returns:
            Dictionary with power analysis results
        """
        # Basic power analysis heuristics
        if sample_size < 10:
            power_category = "Very Low"
            power_estimate = 0.1
        elif sample_size < 30:
            power_category = "Low"
            power_estimate = 0.5
        elif sample_size < 100:
            power_category = "Moderate"
            power_estimate = 0.8
        else:
            power_category = "High"
            power_estimate = 0.95

        return {
            "sample_size": sample_size,
            "power_category": power_category,
            "estimated_power": power_estimate,
            "minimum_recommended_size": 30,
            "adequate_power": sample_size >= 30,
        }

    def generate_classification_report(
        self, results: List[DetectionResult]
    ) -> Dict[str, Any]:
        """
        Generate sklearn classification report

        Args:
            results: Detection results to analyze

        Returns:
            Dictionary with classification report
        """
        y_true = np.array([r.true_label for r in results])
        y_pred = np.array([r.predicted_label for r in results])

        # Get vulnerability types for detailed analysis
        vulnerability_types = [
            r.vulnerability_type for r in results if r.vulnerability_type
        ]

        # Generate classification report
        report = classification_report(y_true, y_pred, output_dict=True)

        return {
            "sklearn_classification_report": report,
            "confusion_matrix": confusion_matrix(y_true, y_pred).tolist(),
            "unique_classes": np.unique(y_true).tolist(),
            "sample_distribution": {
                "positive_samples": int(np.sum(y_true)),
                "negative_samples": int(np.sum(~y_true)),
                "total_samples": len(y_true),
            },
        }

    def compare_with_baseline(
        self,
        code_guardian_results: List[DetectionResult],
        baseline_results: List[DetectionResult],
    ) -> Dict[str, Any]:
        """
        Compare Code Guardian with baseline using McNemar's test

        Args:
            code_guardian_results: Results from Code Guardian
            baseline_results: Results from baseline tool

        Returns:
            Dictionary with comparison metrics and statistical significance
        """
        logger.info("Performing baseline comparison with McNemar's test")

        # Ensure same samples
        cg_dict = {r.sample_id: r for r in code_guardian_results}
        bl_dict = {r.sample_id: r for r in baseline_results}

        common_ids = set(cg_dict.keys()) & set(bl_dict.keys())
        if len(common_ids) != len(code_guardian_results):
            logger.warning(f"Only {len(common_ids)} common samples for comparison")

        # Extract predictions for common samples
        y_true = []
        cg_pred = []
        bl_pred = []

        for sample_id in sorted(common_ids):
            y_true.append(cg_dict[sample_id].true_label)
            cg_pred.append(cg_dict[sample_id].predicted_label)
            bl_pred.append(bl_dict[sample_id].predicted_label)

        y_true = np.array(y_true)
        cg_pred = np.array(cg_pred)
        bl_pred = np.array(bl_pred)

        # Calculate metrics for both tools
        cg_metrics = self.calculate_metrics(
            [cg_dict[sid] for sid in sorted(common_ids)]
        )
        bl_metrics = self.calculate_metrics(
            [bl_dict[sid] for sid in sorted(common_ids)]
        )

        # McNemar's test
        mcnemar_result = self._mcnemar_test(y_true, cg_pred, bl_pred)

        return {
            "code_guardian_metrics": cg_metrics.to_dict(),
            "baseline_metrics": bl_metrics.to_dict(),
            "mcnemar_test": mcnemar_result,
            "improvement": {
                "precision_diff": cg_metrics.precision - bl_metrics.precision,
                "recall_diff": cg_metrics.recall - bl_metrics.recall,
                "f1_diff": cg_metrics.f1_score - bl_metrics.f1_score,
            },
            "n_samples": len(common_ids),
        }

    def analyze_by_vulnerability_type(
        self, results: List[DetectionResult]
    ) -> Dict[str, AccuracyMetrics]:
        """
        Analyze accuracy by vulnerability type

        Args:
            results: List of detection results with vulnerability types

        Returns:
            Dictionary mapping vulnerability types to their metrics
        """
        logger.info("Analyzing accuracy by vulnerability type")

        # Group by vulnerability type
        type_groups = {}
        for result in results:
            vuln_type = result.vulnerability_type or "unknown"
            if vuln_type not in type_groups:
                type_groups[vuln_type] = []
            type_groups[vuln_type].append(result)

        # Calculate metrics for each type
        type_metrics = {}
        for vuln_type, type_results in type_groups.items():
            if len(type_results) >= 5:  # Minimum samples for meaningful metrics
                type_metrics[vuln_type] = self.calculate_metrics(type_results)
                logger.info(
                    f"{vuln_type}: {len(type_results)} samples, "
                    f"F1={type_metrics[vuln_type].f1_score:.3f}"
                )

        return type_metrics

    def _interpret_overall_significance(
        self, significant_tests: List[str], total_tests: int
    ) -> str:
        """Interpret overall significance across multiple tests"""
        if len(significant_tests) == 0:
            return "No statistical evidence of difference between tools"
        elif len(significant_tests) == total_tests:
            return "Strong statistical evidence of difference (all tests significant)"
        elif len(significant_tests) >= total_tests // 2:
            return "Moderate statistical evidence of difference (majority of tests significant)"
        else:
            return "Weak statistical evidence of difference (few tests significant)"

    def _confusion_matrix_components(
        self, y_true: np.ndarray, y_pred: np.ndarray
    ) -> Tuple[int, int, int, int]:
        """Calculate confusion matrix components using sklearn"""
        cm = confusion_matrix(y_true, y_pred)
        if cm.shape == (2, 2):
            tn, fp, fn, tp = cm.ravel()
        else:
            # Handle edge cases
            tp = int(np.sum((y_true == 1) & (y_pred == 1)))
            fp = int(np.sum((y_true == 0) & (y_pred == 1)))
            tn = int(np.sum((y_true == 0) & (y_pred == 0)))
            fn = int(np.sum((y_true == 1) & (y_pred == 0)))
        return tp, fp, tn, fn

    def _bootstrap_ci_sklearn(
        self, y_true: np.ndarray, y_pred: np.ndarray, metric_func
    ) -> Tuple[float, float]:
        """
        Calculate bootstrap confidence interval using scikit-learn's resample

        Args:
            y_true: Ground truth labels
            y_pred: Predicted labels
            metric_func: Sklearn metric function to calculate

        Returns:
            Tuple of (lower_bound, upper_bound)
        """
        n = len(y_true)
        bootstrap_scores = []

        for _ in range(self.n_bootstrap):
            # Bootstrap sample using sklearn's resample
            y_true_boot, y_pred_boot = resample(
                y_true, y_pred, n_samples=n, random_state=None
            )

            # Calculate metric with zero_division handling
            score = metric_func(y_true_boot, y_pred_boot, zero_division=0)
            bootstrap_scores.append(score)

        # Calculate confidence interval
        lower_percentile = (self.alpha / 2) * 100
        upper_percentile = (1 - self.alpha / 2) * 100

        ci_lower = np.percentile(bootstrap_scores, lower_percentile)
        ci_upper = np.percentile(bootstrap_scores, upper_percentile)

        return (ci_lower, ci_upper)

    def _bootstrap_ci(
        self, y_true: np.ndarray, y_pred: np.ndarray, metric_func
    ) -> Tuple[float, float]:
        """
        Calculate bootstrap confidence interval for a metric

        Args:
            y_true: Ground truth labels
            y_pred: Predicted labels
            metric_func: Function to calculate the metric

        Returns:
            Tuple of (lower_bound, upper_bound)
        """
        n = len(y_true)
        bootstrap_scores = []

        for _ in range(self.n_bootstrap):
            # Bootstrap sample
            indices = np.random.choice(n, size=n, replace=True)
            y_true_boot = y_true[indices]
            y_pred_boot = y_pred[indices]

            # Calculate metric
            score = metric_func(y_true_boot, y_pred_boot)
            bootstrap_scores.append(score)

        # Calculate confidence interval
        lower_percentile = (self.alpha / 2) * 100
        upper_percentile = (1 - self.alpha / 2) * 100

        ci_lower = np.percentile(bootstrap_scores, lower_percentile)
        ci_upper = np.percentile(bootstrap_scores, upper_percentile)

        return (ci_lower, ci_upper)

    def _mcnemar_test(
        self, y_true: np.ndarray, pred1: np.ndarray, pred2: np.ndarray
    ) -> Dict[str, Any]:
        """
        Perform McNemar's test using scipy.stats

        Args:
            y_true: Ground truth labels
            pred1: Predictions from first classifier (Code Guardian)
            pred2: Predictions from second classifier (baseline)

        Returns:
            Dictionary with test results
        """
        # Create contingency table for McNemar's test
        correct1 = pred1 == y_true
        correct2 = pred2 == y_true

        # McNemar table focuses on disagreement cases
        both_correct = np.sum(correct1 & correct2)
        tool1_only = np.sum(correct1 & ~correct2)
        tool2_only = np.sum(~correct1 & correct2)
        both_wrong = np.sum(~correct1 & ~correct2)

        try:
            # Perform McNemar's test using scipy
            contingency_table = np.array([[tool1_only, tool2_only]])

            if tool1_only + tool2_only < 25:
                logger.warning(
                    "Small sample for McNemar's test, results may be unreliable"
                )

            result = mcnemar(contingency_table, exact=tool1_only + tool2_only < 25)

            return {
                "statistic": float(result.statistic),
                "p_value": float(result.pvalue),
                "significant": result.pvalue < 0.05,
                "contingency_table": {
                    "both_correct": int(both_correct),
                    "tool1_only_correct": int(tool1_only),
                    "tool2_only_correct": int(tool2_only),
                    "both_wrong": int(both_wrong),
                },
            }
        except Exception as e:
            logger.error("McNemar's test failed: %s", str(e))
            return {
                "statistic": None,
                "p_value": None,
                "significant": None,
                "error": str(e),
            }

    def _calculate_ece(self, results: List[DetectionResult], n_bins: int = 10) -> float:
        """
        Calculate Expected Calibration Error for confidence scores

        Args:
            results: Detection results with confidence scores
            n_bins: Number of confidence bins

        Returns:
            Expected Calibration Error value
        """
        # Filter results with confidence scores
        scored_results = [r for r in results if r.confidence is not None]
        if len(scored_results) < 10:
            return None

        confidences = np.array([r.confidence for r in scored_results])
        predictions = np.array([r.predicted_label for r in scored_results])
        accuracies = np.array(
            [r.true_label == r.predicted_label for r in scored_results]
        )

        # Create bins
        bin_boundaries = np.linspace(0, 1, n_bins + 1)
        bin_lowers = bin_boundaries[:-1]
        bin_uppers = bin_boundaries[1:]

        ece = 0
        for bin_lower, bin_upper in zip(bin_lowers, bin_uppers):
            # Find predictions in this bin
            in_bin = (confidences > bin_lower) & (confidences <= bin_upper)
            prop_in_bin = in_bin.mean()

            if prop_in_bin > 0:
                accuracy_in_bin = accuracies[in_bin].mean()
                avg_confidence_in_bin = confidences[in_bin].mean()
                ece += np.abs(avg_confidence_in_bin - accuracy_in_bin) * prop_in_bin

        return ece

    def generate_report(
        self, results: List[DetectionResult], output_path: Optional[Path] = None
    ) -> Dict[str, Any]:
        """
        Generate comprehensive accuracy report using sklearn and scipy

        Args:
            results: Detection results to analyze
            output_path: Optional path to save report

        Returns:
            Dictionary with complete analysis
        """
        logger.info(f"Generating accuracy report for {len(results)} results")

        # Overall metrics
        overall_metrics = self.calculate_metrics(results)

        # Sklearn classification report
        classification_report_data = self.generate_classification_report(results)

        # By vulnerability type
        type_metrics = self.analyze_by_vulnerability_type(results)

        # Summary statistics
        n_vulnerable = sum(1 for r in results if r.true_label)
        n_detected = sum(1 for r in results if r.predicted_label)

        report = {
            "timestamp": pd.Timestamp.now().isoformat(),
            "summary": {
                "total_samples": len(results),
                "vulnerable_samples": n_vulnerable,
                "detected_samples": n_detected,
                "tools_analyzed": list(set(r.tool_name for r in results)),
            },
            "overall_metrics": overall_metrics.to_dict(),
            "sklearn_classification_report": classification_report_data,
            "by_vulnerability_type": {
                vtype: metrics.to_dict() for vtype, metrics in type_metrics.items()
            },
            "configuration": {
                "n_bootstrap": self.n_bootstrap,
                "confidence_level": self.confidence_level,
            },
        }

        # Save report if path provided
        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w") as f:
                json.dump(report, f, indent=2)
            logger.info(f"Saved accuracy report to {output_path}")

        return report

    def plot_confusion_matrix(
        self, metrics: AccuracyMetrics, output_path: Optional[Path] = None
    ) -> None:
        """Plot confusion matrix visualization"""
        cm = np.array(
            [
                [metrics.true_negatives, metrics.false_positives],
                [metrics.false_negatives, metrics.true_positives],
            ]
        )

        plt.figure(figsize=(8, 6))
        sns.heatmap(
            cm,
            annot=True,
            fmt="d",
            cmap="Blues",
            xticklabels=["Predicted Safe", "Predicted Vulnerable"],
            yticklabels=["Actually Safe", "Actually Vulnerable"],
        )
        plt.title("Code Guardian Confusion Matrix")
        plt.ylabel("True Label")
        plt.xlabel("Predicted Label")

        if output_path:
            plt.savefig(output_path, dpi=300, bbox_inches="tight")
            logger.info(f"Saved confusion matrix plot to {output_path}")

        plt.show()


def load_detection_results(file_path: Path) -> List[DetectionResult]:
    """
    Load detection results from JSON file

    Args:
        file_path: Path to JSON file with detection results

    Returns:
        List of DetectionResult objects
    """
    with open(file_path, "r") as f:
        data = json.load(f)

    results = []
    for item in data:
        result = DetectionResult(
            sample_id=item["sample_id"],
            true_label=item["true_label"],
            predicted_label=item["predicted_label"],
            confidence=item.get("confidence"),
            detection_time_ms=item.get("detection_time_ms"),
            vulnerability_type=item.get("vulnerability_type"),
            tool_name=item.get("tool_name", "code_guardian"),
        )
        results.append(result)

    return results


if __name__ == "__main__":
    # Example usage
    calculator = AccuracyCalculator(n_bootstrap=1000)

    # Example results (in practice, load from evaluation runs)
    example_results = [
        DetectionResult("sample_1", True, True, 0.9, 150, "sql-injection"),
        DetectionResult("sample_2", False, False, 0.1, 120, "safe"),
        DetectionResult("sample_3", True, False, 0.3, 180, "xss"),
        DetectionResult("sample_4", False, True, 0.7, 200, "safe"),
    ]

    # Calculate metrics
    metrics = calculator.calculate_metrics(example_results)
    print(
        f"Precision: {metrics.precision:.3f} [{metrics.precision_ci[0]:.3f}, {metrics.precision_ci[1]:.3f}]"
    )
    print(
        f"Recall: {metrics.recall:.3f} [{metrics.recall_ci[0]:.3f}, {metrics.recall_ci[1]:.3f}]"
    )
    print(
        f"F1-Score: {metrics.f1_score:.3f} [{metrics.f1_ci[0]:.3f}, {metrics.f1_ci[1]:.3f}]"
    )

    # Generate report
    report = calculator.generate_report(example_results)
    print(f"Generated report with {report['summary']['total_samples']} samples")
