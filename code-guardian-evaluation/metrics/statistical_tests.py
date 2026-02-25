#!/usr/bin/env python3
"""
Enhanced Statistical Tests Module for Code Guardian Evaluation

This module provides comprehensive statistical significance testing for
comparing Code Guardian with baseline tools, including both accuracy and
latency comparisons with multiple statistical tests.

Academic Standards:
- McNemar's test for accuracy comparison
- Mann-Whitney U test for latency comparison
- Wilcoxon signed-rank test for paired comparisons
- Chi-square test of independence
- Fisher's exact test for small samples
- Cohen's d and effect size calculations
- Multiple testing corrections
"""

import logging
from typing import Dict, List, Tuple, Optional, Any
import json
from pathlib import Path
import statistics
from datetime import datetime

try:
    import numpy as np
    from scipy.stats import (
        mannwhitneyu,
        wilcoxon,
        ks_2samp,
        mcnemar,
        chi2_contingency,
        fisher_exact,
    )

    SCIPY_AVAILABLE = True
except ImportError:
    SCIPY_AVAILABLE = False
    # Fallback implementations will be used

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class StatisticalTestSuite:
    """
    Comprehensive statistical testing suite for Code Guardian evaluation

    Features:
    - Multiple statistical tests with fallback implementations
    - Effect size calculations
    - Multiple testing corrections
    - Academic-quality reporting
    """

    def __init__(self, alpha: float = 0.05, confidence_level: float = 0.95):
        """
        Initialize statistical test suite

        Args:
            alpha: Significance level (default 0.05)
            confidence_level: Confidence level for intervals (default 0.95)
        """
        self.alpha = alpha
        self.confidence_level = confidence_level
        logger.info("Initialized StatisticalTestSuite with α=%.3f", alpha)

    def compare_accuracy_comprehensive(
        self,
        tool1_results: List[Dict[str, Any]],
        tool2_results: List[Dict[str, Any]],
        tool1_name: str = "Code Guardian",
        tool2_name: str = "Baseline",
    ) -> Dict[str, Any]:
        """
        Comprehensive accuracy comparison with multiple statistical tests

        Args:
            tool1_results: Detection results from first tool
            tool2_results: Detection results from second tool
            tool1_name: Name of first tool
            tool2_name: Name of second tool

        Returns:
            Dictionary with comprehensive statistical analysis
        """
        logger.info(
            "Performing comprehensive accuracy comparison: %s vs %s",
            tool1_name,
            tool2_name,
        )

        # Align samples by sample_id
        aligned_data = self._align_samples(tool1_results, tool2_results)

        if len(aligned_data["sample_ids"]) < 10:
            logger.warning(
                "Insufficient aligned samples (%d) for robust statistical testing",
                len(aligned_data["sample_ids"]),
            )

        # Extract aligned predictions and ground truth
        y_true = np.array(aligned_data["true_labels"])
        pred1 = np.array(aligned_data["tool1_predictions"])
        pred2 = np.array(aligned_data["tool2_predictions"])

        # Calculate basic metrics
        basic_metrics = self._calculate_basic_metrics(
            y_true, pred1, pred2, tool1_name, tool2_name
        )

        # Statistical tests
        statistical_tests = {}

        # 1. McNemar's test (primary test for accuracy comparison)
        mcnemar_result = self._mcnemar_test_comprehensive(y_true, pred1, pred2)
        statistical_tests["mcnemar"] = mcnemar_result

        # 2. Chi-square test of independence
        chi_square_result = self._chi_square_independence_test(y_true, pred1, pred2)
        statistical_tests["chi_square"] = chi_square_result

        # 3. Fisher's exact test (for small samples)
        fisher_result = self._fisher_exact_test_comprehensive(y_true, pred1, pred2)
        statistical_tests["fisher_exact"] = fisher_result

        # 4. Two-proportion z-test
        proportions_test = self._two_proportion_z_test(y_true, pred1, pred2)
        statistical_tests["proportions_z_test"] = proportions_test

        # 5. Confidence interval comparison
        ci_comparison = self._confidence_interval_comparison(y_true, pred1, pred2)
        statistical_tests["confidence_intervals"] = ci_comparison

        # Effect sizes
        effect_sizes = self._calculate_accuracy_effect_sizes(y_true, pred1, pred2)

        # Multiple testing correction
        corrected_results = self._apply_multiple_testing_correction(statistical_tests)

        # Overall significance assessment
        significance_summary = self._assess_overall_significance(
            corrected_results, effect_sizes
        )

        return {
            "tools_compared": [tool1_name, tool2_name],
            "sample_size": len(aligned_data["sample_ids"]),
            "basic_metrics": basic_metrics,
            "statistical_tests": statistical_tests,
            "corrected_tests": corrected_results,
            "effect_sizes": effect_sizes,
            "significance_summary": significance_summary,
            "test_configuration": {
                "alpha": self.alpha,
                "confidence_level": self.confidence_level,
                "scipy_available": SCIPY_AVAILABLE,
            },
        }

    def compare_latency_comprehensive(
        self,
        tool1_latencies: List[float],
        tool2_latencies: List[float],
        tool1_name: str = "Code Guardian",
        tool2_name: str = "Baseline",
        paired: bool = False,
    ) -> Dict[str, Any]:
        """
        Comprehensive latency comparison with multiple statistical tests

        Args:
            tool1_latencies: Latency measurements from first tool
            tool2_latencies: Latency measurements from second tool
            tool1_name: Name of first tool
            tool2_name: Name of second tool
            paired: Whether measurements are paired

        Returns:
            Dictionary with comprehensive statistical analysis
        """
        logger.info(
            "Performing comprehensive latency comparison: %s vs %s (paired=%s)",
            tool1_name,
            tool2_name,
            paired,
        )

        # Basic descriptive statistics
        basic_stats = self._calculate_latency_descriptives(
            tool1_latencies, tool2_latencies, tool1_name, tool2_name
        )

        # Statistical tests
        statistical_tests = {}

        # 1. Mann-Whitney U test (primary test for independent groups)
        if not paired:
            mannwhitney_result = self._mann_whitney_u_test(
                tool1_latencies, tool2_latencies
            )
            statistical_tests["mann_whitney_u"] = mannwhitney_result

        # 2. Wilcoxon signed-rank test (for paired samples)
        if paired and len(tool1_latencies) == len(tool2_latencies):
            wilcoxon_result = self._wilcoxon_signed_rank_test(
                tool1_latencies, tool2_latencies
            )
            statistical_tests["wilcoxon_signed_rank"] = wilcoxon_result

        # 3. Kolmogorov-Smirnov test (distribution comparison)
        ks_result = self._kolmogorov_smirnov_test(tool1_latencies, tool2_latencies)
        statistical_tests["kolmogorov_smirnov"] = ks_result

        # 4. Welch's t-test (if distributions are approximately normal)
        t_test_result = self._welch_t_test(tool1_latencies, tool2_latencies)
        statistical_tests["welch_t_test"] = t_test_result

        # Effect sizes
        effect_sizes = self._calculate_latency_effect_sizes(
            tool1_latencies, tool2_latencies
        )

        # Multiple testing correction
        corrected_results = self._apply_multiple_testing_correction(statistical_tests)

        # Overall significance assessment
        significance_summary = self._assess_overall_significance(
            corrected_results, effect_sizes
        )

        return {
            "tools_compared": [tool1_name, tool2_name],
            "sample_sizes": [len(tool1_latencies), len(tool2_latencies)],
            "basic_statistics": basic_stats,
            "statistical_tests": statistical_tests,
            "corrected_tests": corrected_results,
            "effect_sizes": effect_sizes,
            "significance_summary": significance_summary,
            "test_configuration": {
                "alpha": self.alpha,
                "confidence_level": self.confidence_level,
                "paired": paired,
                "scipy_available": SCIPY_AVAILABLE,
            },
        }

    def _align_samples(
        self, tool1_results: List[Dict[str, Any]], tool2_results: List[Dict[str, Any]]
    ) -> Dict[str, List]:
        """Align samples between two tools by sample_id"""
        tool1_dict = {r["sample_id"]: r for r in tool1_results}
        tool2_dict = {r["sample_id"]: r for r in tool2_results}

        common_ids = set(tool1_dict.keys()) & set(tool2_dict.keys())

        aligned_data = {
            "sample_ids": list(common_ids),
            "true_labels": [],
            "tool1_predictions": [],
            "tool2_predictions": [],
        }

        for sample_id in sorted(common_ids):
            r1, r2 = tool1_dict[sample_id], tool2_dict[sample_id]

            # Extract true labels and predictions properly
            # Prefer explicit fields over 'correct' field
            if "true_label" in r1:
                true_label = r1["true_label"]
            elif "ground_truth" in r1:
                true_label = r1["ground_truth"]
            else:
                # Fallback: assume vulnerability if not specified
                true_label = 1

            # For predictions, prefer explicit predicted_label
            if "predicted_label" in r1:
                pred1 = r1["predicted_label"]
            elif "prediction" in r1:
                pred1 = r1["prediction"]
            elif "correct" in r1:
                # Convert boolean correct to binary prediction assuming true_label=1
                pred1 = 1 if r1["correct"] else 0
            else:
                pred1 = 1  # Default assumption

            if "predicted_label" in r2:
                pred2 = r2["predicted_label"]
            elif "prediction" in r2:
                pred2 = r2["prediction"]
            elif "correct" in r2:
                pred2 = 1 if r2["correct"] else 0
            else:
                pred2 = 1

            aligned_data["true_labels"].append(true_label)
            aligned_data["tool1_predictions"].append(pred1)
            aligned_data["tool2_predictions"].append(pred2)

        return aligned_data

    def _calculate_basic_metrics(
        self,
        y_true: np.ndarray,
        pred1: np.ndarray,
        pred2: np.ndarray,
        tool1_name: str,
        tool2_name: str,
    ) -> Dict[str, Any]:
        """Calculate basic accuracy metrics for both tools"""

        def metrics_for_tool(pred):
            tp = np.sum((y_true == 1) & (pred == 1))
            fp = np.sum((y_true == 0) & (pred == 1))
            tn = np.sum((y_true == 0) & (pred == 0))
            fn = np.sum((y_true == 1) & (pred == 0))

            precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = (
                2 * precision * recall / (precision + recall)
                if (precision + recall) > 0
                else 0.0
            )
            accuracy = (tp + tn) / len(pred)

            return {
                "precision": precision,
                "recall": recall,
                "f1_score": f1,
                "accuracy": accuracy,
                "true_positives": int(tp),
                "false_positives": int(fp),
                "true_negatives": int(tn),
                "false_negatives": int(fn),
            }

        return {
            tool1_name: metrics_for_tool(pred1),
            tool2_name: metrics_for_tool(pred2),
        }

    def _mcnemar_test_comprehensive(
        self, y_true: np.ndarray, pred1: np.ndarray, pred2: np.ndarray
    ) -> Dict[str, Any]:
        """Enhanced McNemar's test with detailed analysis"""
        try:
            # Create McNemar contingency table
            correct1 = pred1 == y_true
            correct2 = pred2 == y_true

            both_correct = np.sum(correct1 & correct2)
            tool1_only = np.sum(correct1 & ~correct2)
            tool2_only = np.sum(~correct1 & correct2)
            both_wrong = np.sum(~correct1 & ~correct2)

            # McNemar focuses on disagreement cases
            b, c = tool1_only, tool2_only

            if SCIPY_AVAILABLE and mcnemar is not None:
                # Use scipy implementation
                table = np.array([[both_correct, tool1_only], [tool2_only, both_wrong]])
                result = mcnemar(table, exact=(b + c) < 25)

                return {
                    "test_name": "McNemar's Test",
                    "statistic": float(result.statistic),
                    "p_value": float(result.pvalue),
                    "significant": result.pvalue < self.alpha,
                    "exact": (b + c) < 25,
                    "disagreement_cases": {
                        "tool1_only_correct": int(b),
                        "tool2_only_correct": int(c),
                    },
                    "agreement_cases": {
                        "both_correct": int(both_correct),
                        "both_wrong": int(both_wrong),
                    },
                    "interpretation": self._interpret_mcnemar_result(
                        result.pvalue, b, c
                    ),
                }
            else:
                # Manual implementation
                if b + c == 0:
                    return {
                        "test_name": "McNemar's Test",
                        "p_value": 1.0,
                        "significant": False,
                        "interpretation": "Perfect agreement between tools",
                    }

                # Chi-square statistic with continuity correction
                chi2_stat = (abs(b - c) - 1) ** 2 / (b + c)
                p_value = 1 - self._chi2_cdf(chi2_stat, 1)

                return {
                    "test_name": "McNemar's Test (Manual)",
                    "statistic": float(chi2_stat),
                    "p_value": float(p_value),
                    "significant": p_value < self.alpha,
                    "disagreement_cases": {
                        "tool1_only_correct": int(b),
                        "tool2_only_correct": int(c),
                    },
                    "interpretation": self._interpret_mcnemar_result(p_value, b, c),
                    "note": "Manual calculation (scipy not available)",
                }
        except Exception as e:
            logger.error("McNemar's test failed: %s", str(e))
            return {"test_name": "McNemar's Test", "error": str(e), "significant": None}

    def _mann_whitney_u_test(
        self, group1: List[float], group2: List[float]
    ) -> Dict[str, Any]:
        """Mann-Whitney U test for comparing two independent groups"""
        try:
            if SCIPY_AVAILABLE and mannwhitneyu is not None:
                statistic, p_value = mannwhitneyu(
                    group1, group2, alternative="two-sided"
                )

                # Calculate effect size (rank-biserial correlation)
                n1, n2 = len(group1), len(group2)
                u1 = statistic
                effect_size = 1 - (2 * u1) / (n1 * n2)

                return {
                    "test_name": "Mann-Whitney U Test",
                    "u_statistic": float(statistic),
                    "p_value": float(p_value),
                    "significant": p_value < self.alpha,
                    "effect_size": float(effect_size),
                    "interpretation": self._interpret_mann_whitney_result(
                        p_value, effect_size
                    ),
                }
            else:
                # Fallback implementation
                combined = [(val, 0) for val in group1] + [(val, 1) for val in group2]
                combined.sort()

                rank_sum_1 = sum(
                    i + 1 for i, (val, group) in enumerate(combined) if group == 0
                )
                n1, n2 = len(group1), len(group2)
                u1 = rank_sum_1 - n1 * (n1 + 1) / 2

                # Normal approximation
                mean_u = n1 * n2 / 2
                var_u = n1 * n2 * (n1 + n2 + 1) / 12
                z_score = (u1 - mean_u) / (var_u**0.5) if var_u > 0 else 0
                p_value = 2 * (1 - self._normal_cdf(abs(z_score)))

                effect_size = 1 - (2 * u1) / (n1 * n2)

                return {
                    "test_name": "Mann-Whitney U Test (Approximation)",
                    "u_statistic": float(u1),
                    "p_value": float(p_value),
                    "significant": p_value < self.alpha,
                    "effect_size": float(effect_size),
                    "interpretation": self._interpret_mann_whitney_result(
                        p_value, effect_size
                    ),
                    "note": "Approximation used (scipy not available)",
                }
        except Exception as e:
            logger.error("Mann-Whitney U test failed: %s", str(e))
            return {
                "test_name": "Mann-Whitney U Test",
                "error": str(e),
                "significant": None,
            }

    def _calculate_accuracy_effect_sizes(
        self, y_true: np.ndarray, pred1: np.ndarray, pred2: np.ndarray
    ) -> Dict[str, Any]:
        """Calculate effect sizes for accuracy comparison"""
        acc1 = np.mean(pred1 == y_true)
        acc2 = np.mean(pred2 == y_true)

        # Cohen's h for proportions
        cohens_h = 2 * (np.arcsin(np.sqrt(acc1)) - np.arcsin(np.sqrt(acc2)))

        # Odds ratio
        tp1, fp1, tn1, fn1 = self._confusion_matrix_components(y_true, pred1)
        tp2, fp2, tn2, fn2 = self._confusion_matrix_components(y_true, pred2)

        odds1 = (tp1 + tn1) / (fp1 + fn1) if (fp1 + fn1) > 0 else float("inf")
        odds2 = (tp2 + tn2) / (fp2 + fn2) if (fp2 + fn2) > 0 else float("inf")
        odds_ratio = odds1 / odds2 if odds2 > 0 and not np.isinf(odds2) else None

        # Risk ratio
        risk_ratio = acc1 / acc2 if acc2 > 0 else None

        return {
            "cohens_h": float(cohens_h),
            "effect_size_interpretation": self._interpret_cohens_h(cohens_h),
            "odds_ratio": (
                float(odds_ratio) if odds_ratio and not np.isinf(odds_ratio) else None
            ),
            "risk_ratio": (
                float(risk_ratio) if risk_ratio and not np.isinf(risk_ratio) else None
            ),
            "absolute_difference": float(acc1 - acc2),
            "relative_improvement_pct": (
                float((acc1 - acc2) / acc2 * 100) if acc2 > 0 else None
            ),
            "practical_significance": abs(acc1 - acc2) > 0.05,  # >5% difference
        }

    def _apply_multiple_testing_correction(
        self, tests: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Apply Bonferroni correction for multiple testing"""
        valid_tests = [
            (name, test)
            for name, test in tests.items()
            if isinstance(test, dict)
            and "p_value" in test
            and test["p_value"] is not None
        ]

        if len(valid_tests) == 0:
            return {}

        corrected_alpha = self.alpha / len(valid_tests)

        corrected_tests = {}
        for name, test in valid_tests:
            corrected_test = test.copy()
            corrected_test["bonferroni_corrected_significant"] = (
                test["p_value"] < corrected_alpha
            )
            corrected_test["corrected_alpha"] = corrected_alpha
            corrected_tests[name] = corrected_test

        return corrected_tests

    def _assess_overall_significance(
        self, corrected_tests: Dict[str, Any], effect_sizes: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Assess overall significance across multiple tests"""
        significant_tests = [
            name
            for name, test in corrected_tests.items()
            if test.get("bonferroni_corrected_significant", False)
        ]

        total_tests = len(corrected_tests)
        practical_significance = effect_sizes.get("practical_significance", False)

        return {
            "significant_tests": significant_tests,
            "total_tests": total_tests,
            "proportion_significant": (
                len(significant_tests) / total_tests if total_tests > 0 else 0
            ),
            "bonferroni_corrected_significant": len(significant_tests) > 0,
            "practical_significance": practical_significance,
            "overall_conclusion": self._generate_overall_conclusion(
                significant_tests, total_tests, practical_significance
            ),
            "evidence_strength": self._assess_evidence_strength(
                significant_tests, total_tests, effect_sizes
            ),
        }

    # Helper methods for interpretation
    def _interpret_mcnemar_result(self, p_value: float, b: int, c: int) -> str:
        if p_value < self.alpha:
            if b > c:
                return "Tool 1 significantly outperforms Tool 2"
            else:
                return "Tool 2 significantly outperforms Tool 1"
        else:
            return "No significant difference between tools"

    def _interpret_mann_whitney_result(self, p_value: float, effect_size: float) -> str:
        if p_value < self.alpha:
            magnitude = (
                "large"
                if abs(effect_size) > 0.5
                else "medium" if abs(effect_size) > 0.3 else "small"
            )
            direction = (
                "Tool 1 has lower latency"
                if effect_size > 0
                else "Tool 2 has lower latency"
            )
            return f"Significant difference with {magnitude} effect size. {direction}"
        else:
            return "No significant difference in latency distributions"

    def _interpret_cohens_h(self, cohens_h: float) -> str:
        abs_h = abs(cohens_h)
        if abs_h < 0.2:
            return "Negligible"
        elif abs_h < 0.5:
            return "Small"
        elif abs_h < 0.8:
            return "Medium"
        else:
            return "Large"

    def _generate_overall_conclusion(
        self,
        significant_tests: List[str],
        total_tests: int,
        practical_significance: bool,
    ) -> str:
        if len(significant_tests) == 0:
            return "No statistical evidence of difference between tools"
        elif practical_significance and len(significant_tests) >= total_tests // 2:
            return "Strong evidence of practical and statistical significance"
        elif len(significant_tests) == total_tests:
            return "Strong statistical evidence (all tests significant)"
        elif len(significant_tests) >= total_tests // 2:
            return "Moderate statistical evidence (majority of tests significant)"
        else:
            return "Weak statistical evidence (few tests significant)"

    def _assess_evidence_strength(
        self,
        significant_tests: List[str],
        total_tests: int,
        effect_sizes: Dict[str, Any],
    ) -> str:
        proportion_sig = len(significant_tests) / total_tests if total_tests > 0 else 0
        practical_sig = effect_sizes.get("practical_significance", False)

        if proportion_sig >= 0.8 and practical_sig:
            return "Very Strong"
        elif proportion_sig >= 0.6 and practical_sig:
            return "Strong"
        elif proportion_sig >= 0.5:
            return "Moderate"
        elif proportion_sig > 0:
            return "Weak"
        else:
            return "None"

    # Utility methods
    def _confusion_matrix_components(
        self, y_true: np.ndarray, y_pred: np.ndarray
    ) -> Tuple[int, int, int, int]:
        """Calculate confusion matrix components"""
        tp = int(np.sum((y_true == 1) & (y_pred == 1)))
        fp = int(np.sum((y_true == 0) & (y_pred == 1)))
        tn = int(np.sum((y_true == 0) & (y_pred == 0)))
        fn = int(np.sum((y_true == 1) & (y_pred == 0)))
        return tp, fp, tn, fn

    def _normal_cdf(self, x: float) -> float:
        """
        Improved standard normal CDF using Abramowitz and Stegun approximation
        """
        if x < -5:
            return 0.0
        elif x > 5:
            return 1.0

        # Abramowitz and Stegun approximation (Formula 7.1.26)
        sign = 1 if x >= 0 else -1
        x = abs(x)

        # Constants
        a1, a2, a3, a4, a5 = (
            0.254829592,
            -0.284496736,
            1.421413741,
            -1.453152027,
            1.061405429,
        )
        p = 0.3275911

        t = 1.0 / (1.0 + p * x)
        y = 1.0 - (((((a5 * t + a4) * t) + a3) * t + a2) * t + a1) * t * np.exp(-x * x)

        return 0.5 * (1.0 + sign * y)

    def _chi2_cdf(self, x: float, df: int) -> float:
        """Approximate chi-square CDF"""
        if x <= 0:
            return 0.0
        elif df == 1:
            return self._normal_cdf((x**0.5))
        else:
            # Normal approximation for higher df
            mean = df
            var = 2 * df
            normalized = (x - mean) / (var**0.5)
            return self._normal_cdf(normalized)

    # Additional methods would include implementations for the other statistical tests
    # (chi_square_independence_test, fisher_exact_test_comprehensive, etc.)
    # These follow similar patterns to the methods above

    def _chi_square_independence_test(
        self, y_true: np.ndarray, pred1: np.ndarray, pred2: np.ndarray
    ) -> Dict[str, Any]:
        """Chi-square test of independence for categorical variables"""
        try:
            # Create contingency table for tool predictions vs true labels
            correct1 = pred1 == y_true
            correct2 = pred2 == y_true

            # 2x2 contingency table: [correct1_yes, correct1_no] x [correct2_yes, correct2_no]
            both_correct = np.sum(correct1 & correct2)
            tool1_only = np.sum(correct1 & ~correct2)
            tool2_only = np.sum(~correct1 & correct2)
            both_wrong = np.sum(~correct1 & ~correct2)

            contingency_table = np.array(
                [[both_correct, tool1_only], [tool2_only, both_wrong]]
            )

            if SCIPY_AVAILABLE and chi2_contingency is not None:
                chi2_stat, p_value, dof, expected = chi2_contingency(contingency_table)

                return {
                    "test_name": "Chi-square Test of Independence",
                    "chi2_statistic": float(chi2_stat),
                    "p_value": float(p_value),
                    "degrees_of_freedom": int(dof),
                    "significant": p_value < self.alpha,
                    "contingency_table": contingency_table.tolist(),
                    "interpretation": (
                        "Tools perform differently"
                        if p_value < self.alpha
                        else "No evidence of different performance"
                    ),
                }
            else:
                # Manual chi-square calculation
                total = np.sum(contingency_table)
                expected = (
                    np.outer(
                        np.sum(contingency_table, axis=1),
                        np.sum(contingency_table, axis=0),
                    )
                    / total
                )
                chi2_stat = np.sum((contingency_table - expected) ** 2 / expected)
                # Approximate p-value using chi-square distribution with 1 DOF
                p_value = 1 - self._chi2_cdf(chi2_stat, 1)

                return {
                    "test_name": "Chi-square Test of Independence (Manual)",
                    "chi2_statistic": float(chi2_stat),
                    "p_value": float(p_value),
                    "degrees_of_freedom": 1,
                    "significant": p_value < self.alpha,
                    "contingency_table": contingency_table.tolist(),
                    "note": "Manual calculation (scipy not available)",
                }
        except Exception as e:
            return {"test_name": "Chi-square Test of Independence", "error": str(e)}

    def _fisher_exact_test_comprehensive(
        self, y_true: np.ndarray, pred1: np.ndarray, pred2: np.ndarray
    ) -> Dict[str, Any]:
        """Fisher's exact test for small sample sizes"""
        try:
            correct1 = pred1 == y_true
            correct2 = pred2 == y_true

            both_correct = np.sum(correct1 & correct2)
            tool1_only = np.sum(correct1 & ~correct2)
            tool2_only = np.sum(~correct1 & correct2)
            both_wrong = np.sum(~correct1 & ~correct2)

            contingency_table = np.array(
                [[both_correct, tool1_only], [tool2_only, both_wrong]]
            )

            if SCIPY_AVAILABLE and fisher_exact is not None:
                odds_ratio, p_value = fisher_exact(contingency_table)

                return {
                    "test_name": "Fisher's Exact Test",
                    "odds_ratio": float(odds_ratio),
                    "p_value": float(p_value),
                    "significant": p_value < self.alpha,
                    "contingency_table": contingency_table.tolist(),
                    "interpretation": (
                        "Significant association"
                        if p_value < self.alpha
                        else "No significant association"
                    ),
                }
            else:
                return {
                    "test_name": "Fisher's Exact Test",
                    "note": "Requires scipy for exact calculation",
                    "contingency_table": contingency_table.tolist(),
                }
        except Exception as e:
            return {"test_name": "Fisher's Exact Test", "error": str(e)}

    def _two_proportion_z_test(
        self, y_true: np.ndarray, pred1: np.ndarray, pred2: np.ndarray
    ) -> Dict[str, Any]:
        """Two-proportion z-test for comparing accuracy rates"""
        try:
            acc1 = np.mean(pred1 == y_true)
            acc2 = np.mean(pred2 == y_true)
            n1, n2 = len(pred1), len(pred2)

            # Pooled proportion
            pooled_p = (np.sum(pred1 == y_true) + np.sum(pred2 == y_true)) / (n1 + n2)

            # Standard error
            se = np.sqrt(pooled_p * (1 - pooled_p) * (1 / n1 + 1 / n2))

            # Z-statistic
            z_stat = (acc1 - acc2) / se if se > 0 else 0

            # Two-tailed p-value
            p_value = 2 * (1 - self._normal_cdf(abs(z_stat)))

            return {
                "test_name": "Two-Proportion Z-Test",
                "z_statistic": float(z_stat),
                "p_value": float(p_value),
                "significant": p_value < self.alpha,
                "proportion_1": float(acc1),
                "proportion_2": float(acc2),
                "difference": float(acc1 - acc2),
                "interpretation": f'Tool 1 {"significantly " if p_value < self.alpha else ""}{"higher" if acc1 > acc2 else "lower"} accuracy',
            }
        except Exception as e:
            return {"test_name": "Two-Proportion Z-Test", "error": str(e)}

    def _confidence_interval_comparison(
        self, y_true: np.ndarray, pred1: np.ndarray, pred2: np.ndarray
    ) -> Dict[str, Any]:
        """Compare confidence intervals for accuracy"""
        try:
            acc1 = np.mean(pred1 == y_true)
            acc2 = np.mean(pred2 == y_true)
            n1, n2 = len(pred1), len(pred2)

            # Wilson score interval (more robust than normal approximation)
            z = 1.96  # 95% confidence

            def wilson_ci(p, n):
                denominator = 1 + z**2 / n
                center = (p + z**2 / (2 * n)) / denominator
                margin = (
                    z * np.sqrt((p * (1 - p) / n + z**2 / (4 * n**2))) / denominator
                )
                return center - margin, center + margin

            ci1 = wilson_ci(acc1, n1)
            ci2 = wilson_ci(acc2, n2)

            # Check for overlap
            overlap = not (ci1[1] < ci2[0] or ci2[1] < ci1[0])

            return {
                "test_name": "Confidence Interval Comparison",
                "tool1_accuracy": float(acc1),
                "tool1_ci_lower": float(ci1[0]),
                "tool1_ci_upper": float(ci1[1]),
                "tool2_accuracy": float(acc2),
                "tool2_ci_lower": float(ci2[0]),
                "tool2_ci_upper": float(ci2[1]),
                "intervals_overlap": overlap,
                "significant_difference": not overlap,
                "interpretation": (
                    "No significant difference"
                    if overlap
                    else "Significant difference detected"
                ),
            }
        except Exception as e:
            return {"test_name": "Confidence Interval Comparison", "error": str(e)}

    def _welch_t_test(self, group1: List[float], group2: List[float]) -> Dict[str, Any]:
        """Welch's t-test for unequal variances"""
        try:
            if len(group1) < 2 or len(group2) < 2:
                return {
                    "test_name": "Welch's t-test",
                    "error": "Insufficient sample size",
                }

            mean1, mean2 = statistics.mean(group1), statistics.mean(group2)
            var1 = statistics.variance(group1)
            var2 = statistics.variance(group2)
            n1, n2 = len(group1), len(group2)

            # Welch's t-statistic
            se = np.sqrt(var1 / n1 + var2 / n2)
            t_stat = (mean1 - mean2) / se if se > 0 else 0

            # Degrees of freedom (Welch-Satterthwaite equation)
            dof = (var1 / n1 + var2 / n2) ** 2 / (
                (var1 / n1) ** 2 / (n1 - 1) + (var2 / n2) ** 2 / (n2 - 1)
            )

            # Approximate p-value using normal distribution (for large samples)
            p_value = 2 * (1 - self._normal_cdf(abs(t_stat)))

            return {
                "test_name": "Welch's t-test",
                "t_statistic": float(t_stat),
                "p_value": float(p_value),
                "degrees_of_freedom": float(dof),
                "significant": p_value < self.alpha,
                "mean_difference": float(mean1 - mean2),
                "interpretation": (
                    "Significant difference in means"
                    if p_value < self.alpha
                    else "No significant difference"
                ),
            }
        except Exception as e:
            return {"test_name": "Welch's t-test", "error": str(e)}

    def _kolmogorov_smirnov_test(
        self, group1: List[float], group2: List[float]
    ) -> Dict[str, Any]:
        """Kolmogorov-Smirnov test for distribution comparison"""
        try:
            if SCIPY_AVAILABLE and ks_2samp is not None:
                statistic, p_value = ks_2samp(group1, group2)

                return {
                    "test_name": "Kolmogorov-Smirnov Test",
                    "ks_statistic": float(statistic),
                    "p_value": float(p_value),
                    "significant": p_value < self.alpha,
                    "interpretation": (
                        "Different distributions"
                        if p_value < self.alpha
                        else "Same distribution"
                    ),
                }
            else:
                return {
                    "test_name": "Kolmogorov-Smirnov Test",
                    "note": "Requires scipy for implementation",
                }
        except Exception as e:
            return {"test_name": "Kolmogorov-Smirnov Test", "error": str(e)}

    def _wilcoxon_signed_rank_test(
        self, group1: List[float], group2: List[float]
    ) -> Dict[str, Any]:
        """Wilcoxon signed-rank test for paired samples"""
        try:
            if len(group1) != len(group2):
                return {
                    "test_name": "Wilcoxon Signed-Rank Test",
                    "error": "Groups must have equal length for paired test",
                }

            if SCIPY_AVAILABLE and wilcoxon is not None:
                statistic, p_value = wilcoxon(group1, group2)

                return {
                    "test_name": "Wilcoxon Signed-Rank Test",
                    "w_statistic": float(statistic),
                    "p_value": float(p_value),
                    "significant": p_value < self.alpha,
                    "interpretation": (
                        "Significant difference"
                        if p_value < self.alpha
                        else "No significant difference"
                    ),
                }
            else:
                return {
                    "test_name": "Wilcoxon Signed-Rank Test",
                    "note": "Requires scipy for implementation",
                }
        except Exception as e:
            return {"test_name": "Wilcoxon Signed-Rank Test", "error": str(e)}

    def _calculate_latency_descriptives(
        self,
        latencies1: List[float],
        latencies2: List[float],
        tool1_name: str,
        tool2_name: str,
    ) -> Dict[str, Any]:
        """Calculate descriptive statistics for latency data"""

        def stats_for_group(latencies, name):
            if not latencies:
                return {f"{name}_count": 0}

            return {
                f"{name}_count": len(latencies),
                f"{name}_mean": statistics.mean(latencies),
                f"{name}_median": statistics.median(latencies),
                f"{name}_std": statistics.stdev(latencies) if len(latencies) > 1 else 0,
                f"{name}_min": min(latencies),
                f"{name}_max": max(latencies),
                f"{name}_p25": self._percentile(latencies, 25),
                f"{name}_p75": self._percentile(latencies, 75),
                f"{name}_p95": self._percentile(latencies, 95),
            }

        stats1 = stats_for_group(latencies1, tool1_name.replace("-", "_"))
        stats2 = stats_for_group(latencies2, tool2_name.replace("-", "_"))

        return {**stats1, **stats2}

    def _calculate_latency_effect_sizes(
        self, latencies1: List[float], latencies2: List[float]
    ) -> Dict[str, Any]:
        """Calculate effect sizes for latency comparison"""
        if not latencies1 or not latencies2:
            return {"error": "Empty latency data"}

        mean1, mean2 = statistics.mean(latencies1), statistics.mean(latencies2)

        # Cohen's d
        if len(latencies1) > 1 and len(latencies2) > 1:
            std1, std2 = statistics.stdev(latencies1), statistics.stdev(latencies2)
            pooled_std = np.sqrt(
                ((len(latencies1) - 1) * std1**2 + (len(latencies2) - 1) * std2**2)
                / (len(latencies1) + len(latencies2) - 2)
            )
            cohens_d = (mean1 - mean2) / pooled_std if pooled_std > 0 else 0
        else:
            cohens_d = 0

        return {
            "cohens_d": float(cohens_d),
            "effect_size_interpretation": self._interpret_cohens_d(cohens_d),
            "mean_difference": float(mean1 - mean2),
            "relative_difference_pct": (
                float((mean1 - mean2) / mean2 * 100) if mean2 > 0 else None
            ),
            "practical_significance": abs(mean1 - mean2) > 100,  # >100ms difference
        }

    def _interpret_cohens_d(self, cohens_d: float) -> str:
        """Interpret Cohen's d effect size"""
        abs_d = abs(cohens_d)
        if abs_d < 0.2:
            return "Negligible"
        elif abs_d < 0.5:
            return "Small"
        elif abs_d < 0.8:
            return "Medium"
        else:
            return "Large"

    def _percentile(self, data: List[float], percentile: int) -> float:
        """Calculate percentile of data"""
        if not data:
            return 0.0

        sorted_data = sorted(data)
        k = (len(sorted_data) - 1) * percentile / 100
        f = int(k)
        c = k - f

        if f + 1 < len(sorted_data):
            return sorted_data[f] * (1 - c) + sorted_data[f + 1] * c
        else:
            return sorted_data[f]

    def _chi2_cdf(self, x: float, df: int) -> float:
        """
        Improved chi-square CDF approximation using Wilson-Hilferty transformation
        """
        if x <= 0:
            return 0.0
        if x == float("inf"):
            return 1.0

        # Wilson-Hilferty transformation for better approximation
        h = 2.0 / (9.0 * df)
        normalized = (pow(x / df, 1.0 / 3.0) - (1.0 - h)) / (h**0.5)
        return self._normal_cdf(normalized)

    def _normal_cdf(self, x: float) -> float:
        """Approximate standard normal CDF using error function approximation"""
        # Abramowitz and Stegun approximation
        if x == 0:
            return 0.5

        sign = 1 if x > 0 else -1
        x = abs(x)

        # Constants for approximation
        a1, a2, a3, a4, a5 = (
            0.254829592,
            -0.284496736,
            1.421413741,
            -1.453152027,
            1.061405429,
        )
        p = 0.3275911

        t = 1.0 / (1.0 + p * x)
        y = 1.0 - (((((a5 * t + a4) * t) + a3) * t + a2) * t + a1) * t * np.exp(-x * x)

        return 0.5 + sign * y * 0.5

    def generate_statistical_report(
        self,
        accuracy_comparison: Dict[str, Any],
        latency_comparison: Optional[Dict[str, Any]] = None,
        output_path: Optional[Path] = None,
    ) -> Dict[str, Any]:
        """
        Generate comprehensive statistical report

        Args:
            accuracy_comparison: Results from accuracy comparison
            latency_comparison: Optional results from latency comparison
            output_path: Optional path to save report

        Returns:
            Complete statistical analysis report
        """
        report = {
            "timestamp": datetime.now().isoformat(),
            "statistical_summary": {
                "accuracy_analysis": accuracy_comparison,
                "latency_analysis": latency_comparison,
            },
            "methodology": {
                "tests_performed": [],
                "corrections_applied": ["Bonferroni"],
                "significance_level": self.alpha,
                "confidence_level": self.confidence_level,
            },
            "conclusions": self._generate_overall_conclusions(
                accuracy_comparison, latency_comparison
            ),
        }

        # Save report if path provided
        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
            logger.info("Saved statistical report to %s", output_path)

        return report

    def _generate_overall_conclusions(
        self,
        accuracy_results: Dict[str, Any],
        latency_results: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Generate overall conclusions from all analyses"""
        conclusions = {
            "accuracy": accuracy_results.get("significance_summary", {}).get(
                "overall_conclusion", "No analysis"
            ),
            "primary_findings": [],
            "academic_significance": "",
            "practical_implications": [],
        }

        # Extract key findings
        if accuracy_results.get("significance_summary", {}).get(
            "bonferroni_corrected_significant"
        ):
            conclusions["primary_findings"].append(
                "Statistically significant accuracy difference detected"
            )

        if latency_results and latency_results.get("significance_summary", {}).get(
            "bonferroni_corrected_significant"
        ):
            conclusions["primary_findings"].append(
                "Statistically significant latency difference detected"
            )

        # Assess academic significance
        evidence_strength = accuracy_results.get("significance_summary", {}).get(
            "evidence_strength", "None"
        )
        conclusions["academic_significance"] = (
            f"{evidence_strength} evidence for tool performance differences"
        )

        return conclusions


# Factory function for easy usage
def create_statistical_test_suite(alpha: float = 0.05) -> StatisticalTestSuite:
    """Create a statistical test suite with specified significance level"""
    return StatisticalTestSuite(alpha=alpha)


if __name__ == "__main__":
    # Example usage
    test_suite = StatisticalTestSuite()

    # Example data
    code_guardian_results = [
        {"sample_id": "test_1", "correct": True, "confidence": 0.9},
        {"sample_id": "test_2", "correct": True, "confidence": 0.8},
    ]
    baseline_results = [
        {"sample_id": "test_1", "correct": False, "confidence": 0.3},
        {"sample_id": "test_2", "correct": True, "confidence": 0.6},
    ]

    # Run comparison
    accuracy_comparison = test_suite.compare_accuracy_comprehensive(
        code_guardian_results, baseline_results, "Code Guardian", "SAST Baseline"
    )

    print("Statistical Comparison Results:")
    print(
        f"Overall Conclusion: {accuracy_comparison['significance_summary']['overall_conclusion']}"
    )
    print(
        f"Evidence Strength: {accuracy_comparison['significance_summary']['evidence_strength']}"
    )
