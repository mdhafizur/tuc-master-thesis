#!/usr/bin/env python3
"""
Repair Quality Metrics Calculator for Code Guardian VS Code Extension

This module evaluates the quality of security fixes suggested by Code Guardian,
including correctness, completeness, and maintainability of the repairs.

Academic Standards:
- Automated repair quality assessment
- Expert evaluation correlation
- Fix applicability scoring
- Security effectiveness measurement
"""

import re
import ast
import json
import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from pathlib import Path
from enum import Enum
import numpy as np
import pandas as pd
from scipy import stats
from scipy.stats import pearsonr, spearmanr
from sklearn.metrics import mean_squared_error, mean_absolute_error

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class RepairType(Enum):
    """Types of security repairs"""

    INPUT_VALIDATION = "input_validation"
    OUTPUT_SANITIZATION = "output_sanitization"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    CRYPTOGRAPHY = "cryptography"
    ERROR_HANDLING = "error_handling"
    CONFIGURATION = "configuration"
    DEPENDENCY_UPDATE = "dependency_update"
    CODE_STRUCTURE = "code_structure"
    OTHER = "other"


@dataclass
class RepairSuggestion:
    """Individual repair suggestion from Code Guardian"""

    sample_id: str
    vulnerability_type: str
    original_code: str
    suggested_fix: str
    repair_type: RepairType
    confidence_score: Optional[float] = None
    explanation: Optional[str] = None
    tool_name: str = "code_guardian"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "sample_id": self.sample_id,
            "vulnerability_type": self.vulnerability_type,
            "original_code": self.original_code,
            "suggested_fix": self.suggested_fix,
            "repair_type": self.repair_type.value,
            "confidence_score": self.confidence_score,
            "explanation": self.explanation,
            "tool_name": self.tool_name,
        }


@dataclass
class RepairEvaluation:
    """Human evaluation of a repair suggestion"""

    sample_id: str
    correctness_score: int  # 1-5 scale
    completeness_score: int  # 1-5 scale
    maintainability_score: int  # 1-5 scale
    security_effectiveness: int  # 1-5 scale

    # Binary flags
    syntactically_valid: bool
    semantically_correct: bool
    fixes_vulnerability: bool
    introduces_new_issues: bool

    # Additional metrics
    code_quality_impact: int  # -2 to +2 scale
    explanation_clarity: int  # 1-5 scale

    evaluator_id: Optional[str] = None
    evaluation_time_minutes: Optional[float] = None
    comments: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "sample_id": self.sample_id,
            "correctness_score": self.correctness_score,
            "completeness_score": self.completeness_score,
            "maintainability_score": self.maintainability_score,
            "security_effectiveness": self.security_effectiveness,
            "syntactically_valid": self.syntactically_valid,
            "semantically_correct": self.semantically_correct,
            "fixes_vulnerability": self.fixes_vulnerability,
            "introduces_new_issues": self.introduces_new_issues,
            "code_quality_impact": self.code_quality_impact,
            "explanation_clarity": self.explanation_clarity,
            "evaluator_id": self.evaluator_id,
            "evaluation_time_minutes": self.evaluation_time_minutes,
            "comments": self.comments,
        }


@dataclass
class RepairQualityMetrics:
    """Comprehensive repair quality metrics"""

    n_repairs: int

    # Automated metrics
    syntax_validity_rate: float
    semantic_correctness_rate: float
    vulnerability_fix_rate: float
    no_new_issues_rate: float

    # Human evaluation averages
    avg_correctness_score: float
    avg_completeness_score: float
    avg_maintainability_score: float
    avg_security_effectiveness: float
    avg_explanation_clarity: float

    # Composite scores
    overall_quality_score: float  # Weighted average
    expert_approval_rate: float  # % with correctness >= 4
    production_ready_rate: float  # % meeting all quality thresholds

    # By repair type breakdown
    by_repair_type: Dict[str, Dict[str, float]]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "n_repairs": self.n_repairs,
            "automated_metrics": {
                "syntax_validity_rate": self.syntax_validity_rate,
                "semantic_correctness_rate": self.semantic_correctness_rate,
                "vulnerability_fix_rate": self.vulnerability_fix_rate,
                "no_new_issues_rate": self.no_new_issues_rate,
            },
            "human_evaluation_averages": {
                "avg_correctness_score": self.avg_correctness_score,
                "avg_completeness_score": self.avg_completeness_score,
                "avg_maintainability_score": self.avg_maintainability_score,
                "avg_security_effectiveness": self.avg_security_effectiveness,
                "avg_explanation_clarity": self.avg_explanation_clarity,
            },
            "composite_scores": {
                "overall_quality_score": self.overall_quality_score,
                "expert_approval_rate": self.expert_approval_rate,
                "production_ready_rate": self.production_ready_rate,
            },
            "by_repair_type": self.by_repair_type,
        }


class RepairQualityCalculator:
    """
    Main class for calculating repair quality metrics

    Features:
    - Automated syntax and semantic validation
    - Security effectiveness assessment
    - Human evaluation correlation
    - Repair type analysis
    - Production readiness scoring
    """

    def __init__(
        self, expert_threshold: int = 4, production_thresholds: Dict[str, float] = None
    ):
        """
        Initialize repair quality calculator

        Args:
            expert_threshold: Minimum correctness score for expert approval
            production_thresholds: Thresholds for production readiness
        """
        self.expert_threshold = expert_threshold
        self.production_thresholds = production_thresholds or {
            "correctness": 4.0,
            "completeness": 3.5,
            "security_effectiveness": 4.0,
            "syntax_valid": True,
            "no_new_issues": True,
        }
        logger.info(
            "Initialized RepairQualityCalculator with expert threshold: %d",
            expert_threshold,
        )

    def calculate_metrics(
        self, suggestions: List[RepairSuggestion], evaluations: List[RepairEvaluation]
    ) -> RepairQualityMetrics:
        """
        Calculate comprehensive repair quality metrics using pandas and numpy

        Args:
            suggestions: List of repair suggestions
            evaluations: List of human evaluations

        Returns:
            RepairQualityMetrics object with all computed metrics
        """
        logger.info(
            "Calculating repair quality metrics for %d suggestions with %d evaluations",
            len(suggestions),
            len(evaluations),
        )

        if not suggestions or not evaluations:
            raise ValueError("Both suggestions and evaluations are required")

        # Create DataFrames for easier analysis
        suggestions_df = pd.DataFrame([s.to_dict() for s in suggestions])
        evaluations_df = pd.DataFrame([e.to_dict() for e in evaluations])

        # Merge on sample_id
        merged_df = pd.merge(
            suggestions_df, evaluations_df, on="sample_id", how="inner"
        )

        if len(merged_df) == 0:
            raise ValueError("No matching suggestions and evaluations found")

        logger.info("Found %d matching suggestion-evaluation pairs", len(merged_df))
        n_repairs = len(merged_df)

        # Calculate automated metrics using numpy
        syntax_validity_rate = float(merged_df["syntactically_valid"].mean())
        semantic_correctness_rate = float(merged_df["semantically_correct"].mean())
        vulnerability_fix_rate = float(merged_df["fixes_vulnerability"].mean())
        no_new_issues_rate = float((~merged_df["introduces_new_issues"]).mean())

        # Calculate human evaluation averages using pandas
        avg_correctness = float(merged_df["correctness_score"].mean())
        avg_completeness = float(merged_df["completeness_score"].mean())
        avg_maintainability = float(merged_df["maintainability_score"].mean())
        avg_security_effectiveness = float(merged_df["security_effectiveness"].mean())
        avg_explanation_clarity = float(merged_df["explanation_clarity"].mean())

        # Calculate composite scores
        overall_quality_score = self._calculate_overall_quality_pandas(merged_df)
        expert_approval_rate = float(
            (merged_df["correctness_score"] >= self.expert_threshold).mean()
        )
        production_ready_rate = float(
            merged_df.apply(self._is_production_ready_pandas, axis=1).mean()
        )

        # Analyze by repair type using pandas groupby
        by_repair_type = self._analyze_by_repair_type_pandas(merged_df)

        quality_metrics = RepairQualityMetrics(
            n_repairs=n_repairs,
            syntax_validity_rate=syntax_validity_rate,
            semantic_correctness_rate=semantic_correctness_rate,
            vulnerability_fix_rate=vulnerability_fix_rate,
            no_new_issues_rate=no_new_issues_rate,
            avg_correctness_score=avg_correctness,
            avg_completeness_score=avg_completeness,
            avg_maintainability_score=avg_maintainability,
            avg_security_effectiveness=avg_security_effectiveness,
            avg_explanation_clarity=avg_explanation_clarity,
            overall_quality_score=overall_quality_score,
            expert_approval_rate=expert_approval_rate,
            production_ready_rate=production_ready_rate,
            by_repair_type=by_repair_type,
        )

        logger.info(
            "Calculated quality metrics: overall=%.2f, expert_approval=%.2f%%",
            overall_quality_score,
            expert_approval_rate * 100,
        )

        return quality_metrics

    def _calculate_overall_quality_pandas(self, df: pd.DataFrame) -> float:
        """
        Calculate weighted overall quality score using pandas

        Weights:
        - Correctness: 30%
        - Security Effectiveness: 25%
        - Completeness: 20%
        - Maintainability: 15%
        - Explanation Clarity: 10%
        """
        if len(df) == 0:
            return 0.0

        weights = {
            "correctness_score": 0.30,
            "security_effectiveness": 0.25,
            "completeness_score": 0.20,
            "maintainability_score": 0.15,
            "explanation_clarity": 0.10,
        }

        # Calculate weighted sum using pandas
        weighted_score = 0.0
        for column, weight in weights.items():
            if column in df.columns:
                weighted_score += (df[column] / 5.0 * weight).mean()

        return float(weighted_score)

    def _is_production_ready_pandas(self, row) -> bool:
        """Check if a repair meets production readiness criteria using pandas row"""
        thresholds = self.production_thresholds

        return (
            row["correctness_score"] >= thresholds.get("correctness", 4.0)
            and row["completeness_score"] >= thresholds.get("completeness", 3.5)
            and row["security_effectiveness"]
            >= thresholds.get("security_effectiveness", 4.0)
            and row["syntactically_valid"] == thresholds.get("syntax_valid", True)
            and not row["introduces_new_issues"]
            == thresholds.get("no_new_issues", True)
        )

    def _analyze_by_repair_type_pandas(
        self, df: pd.DataFrame
    ) -> Dict[str, Dict[str, float]]:
        """Analyze repair quality by repair type using pandas groupby"""
        if "repair_type" not in df.columns or len(df) == 0:
            return {}

        # Group by repair type and calculate statistics
        grouped = df.groupby("repair_type")

        result = {}
        for repair_type, group in grouped:
            if len(group) >= 3:  # Minimum samples for meaningful analysis
                result[repair_type] = {
                    "n_repairs": len(group),
                    "avg_correctness": float(group["correctness_score"].mean()),
                    "avg_completeness": float(group["completeness_score"].mean()),
                    "avg_security_effectiveness": float(
                        group["security_effectiveness"].mean()
                    ),
                    "syntax_validity_rate": float(group["syntactically_valid"].mean()),
                    "vulnerability_fix_rate": float(
                        group["fixes_vulnerability"].mean()
                    ),
                    "expert_approval_rate": float(
                        (group["correctness_score"] >= self.expert_threshold).mean()
                    ),
                    "production_ready_rate": float(
                        group.apply(self._is_production_ready_pandas, axis=1).mean()
                    ),
                }

        return result

    def validate_syntax(self, code: str, language: str = "javascript") -> bool:
        """
        Validate syntax of code

        Args:
            code: Code to validate
            language: Programming language

        Returns:
            True if syntax is valid
        """
        if language.lower() == "python":
            try:
                ast.parse(code)
                return True
            except SyntaxError:
                return False

        # For JavaScript/TypeScript, do basic validation
        # In practice, you'd use a proper JS parser
        return self._basic_js_syntax_check(code)

    def assess_security_improvement(
        self, original_code: str, fixed_code: str, vulnerability_type: str
    ) -> Dict[str, Any]:
        """
        Assess security improvement from original to fixed code

        Args:
            original_code: Original vulnerable code
            fixed_code: Fixed code
            vulnerability_type: Type of vulnerability

        Returns:
            Dictionary with security assessment
        """
        logger.info(
            "Assessing security improvement for %s vulnerability", vulnerability_type
        )

        # Vulnerability-specific patterns
        vuln_patterns = self._get_vulnerability_patterns(vulnerability_type)

        # Check original code for patterns
        original_issues = []
        for pattern_name, pattern_regex in vuln_patterns.items():
            if re.search(pattern_regex, original_code, re.IGNORECASE):
                original_issues.append(pattern_name)

        # Check fixed code for patterns
        fixed_issues = []
        for pattern_name, pattern_regex in vuln_patterns.items():
            if re.search(pattern_regex, fixed_code, re.IGNORECASE):
                fixed_issues.append(pattern_name)

        # Security improvement assessment
        issues_fixed = set(original_issues) - set(fixed_issues)
        issues_remaining = set(original_issues) & set(fixed_issues)
        new_issues = set(fixed_issues) - set(original_issues)

        improvement_score = (
            len(issues_fixed) / len(original_issues) if original_issues else 0.0
        )

        return {
            "original_issues": original_issues,
            "fixed_issues": fixed_issues,
            "issues_fixed": list(issues_fixed),
            "issues_remaining": list(issues_remaining),
            "new_issues": list(new_issues),
            "improvement_score": improvement_score,
            "vulnerability_completely_fixed": len(issues_remaining) == 0
            and len(original_issues) > 0,
        }

    def compare_with_expert_fixes(
        self,
        code_guardian_suggestions: List[RepairSuggestion],
        expert_fixes: List[RepairSuggestion],
    ) -> Dict[str, Any]:
        """
        Compare Code Guardian suggestions with expert-written fixes

        Args:
            code_guardian_suggestions: AI-generated suggestions
            expert_fixes: Expert-written fixes

        Returns:
            Dictionary with comparison analysis
        """
        logger.info(
            "Comparing %d AI suggestions with %d expert fixes",
            len(code_guardian_suggestions),
            len(expert_fixes),
        )

        # Match by sample_id
        cg_dict = {s.sample_id: s for s in code_guardian_suggestions}
        expert_dict = {s.sample_id: s for s in expert_fixes}

        common_ids = set(cg_dict.keys()) & set(expert_dict.keys())
        logger.info("Found %d common samples for comparison", len(common_ids))

        # Similarity analysis
        similarities = []
        for sample_id in common_ids:
            cg_fix = cg_dict[sample_id]
            expert_fix = expert_dict[sample_id]

            similarity = self._calculate_fix_similarity(
                cg_fix.suggested_fix, expert_fix.suggested_fix
            )
            similarities.append(
                {
                    "sample_id": sample_id,
                    "similarity_score": similarity,
                    "vulnerability_type": cg_fix.vulnerability_type,
                }
            )

        avg_similarity = (
            sum(s["similarity_score"] for s in similarities) / len(similarities)
            if similarities
            else 0.0
        )

        # Approach analysis
        approach_comparison = self._compare_repair_approaches(
            [cg_dict[sid] for sid in common_ids],
            [expert_dict[sid] for sid in common_ids],
        )

        return {
            "n_compared": len(common_ids),
            "avg_similarity_score": avg_similarity,
            "individual_similarities": similarities,
            "approach_comparison": approach_comparison,
        }

    def _calculate_overall_quality(self, evaluations: List[RepairEvaluation]) -> float:
        """
        Calculate weighted overall quality score

        Weights:
        - Correctness: 30%
        - Security Effectiveness: 25%
        - Completeness: 20%
        - Maintainability: 15%
        - Explanation Clarity: 10%
        """
        if not evaluations:
            return 0.0

        weights = {
            "correctness": 0.30,
            "security_effectiveness": 0.25,
            "completeness": 0.20,
            "maintainability": 0.15,
            "explanation_clarity": 0.10,
        }

        total_score = 0.0
        for evaluation in evaluations:
            weighted_score = (
                evaluation.correctness_score * weights["correctness"]
                + evaluation.security_effectiveness * weights["security_effectiveness"]
                + evaluation.completeness_score * weights["completeness"]
                + evaluation.maintainability_score * weights["maintainability"]
                + evaluation.explanation_clarity * weights["explanation_clarity"]
            )
            total_score += weighted_score

        return total_score / len(evaluations)

    def _is_production_ready(self, evaluation: RepairEvaluation) -> bool:
        """Check if a repair meets production readiness thresholds"""
        return (
            evaluation.correctness_score >= self.production_thresholds["correctness"]
            and evaluation.completeness_score
            >= self.production_thresholds["completeness"]
            and evaluation.security_effectiveness
            >= self.production_thresholds["security_effectiveness"]
            and evaluation.syntactically_valid
            == self.production_thresholds["syntax_valid"]
            and not evaluation.introduces_new_issues
            == self.production_thresholds["no_new_issues"]
        )

    def _analyze_by_repair_type(
        self, matched_pairs: List[Tuple[RepairSuggestion, RepairEvaluation]]
    ) -> Dict[str, Dict[str, float]]:
        """Analyze quality metrics by repair type"""
        type_groups = {}

        for suggestion, evaluation in matched_pairs:
            repair_type = suggestion.repair_type.value
            if repair_type not in type_groups:
                type_groups[repair_type] = []
            type_groups[repair_type].append(evaluation)

        type_metrics = {}
        for repair_type, evaluations_list in type_groups.items():
            if len(evaluations_list) >= 3:  # Minimum for meaningful analysis
                type_metrics[repair_type] = {
                    "n_repairs": len(evaluations_list),
                    "avg_correctness": sum(
                        e.correctness_score for e in evaluations_list
                    )
                    / len(evaluations_list),
                    "avg_security_effectiveness": sum(
                        e.security_effectiveness for e in evaluations_list
                    )
                    / len(evaluations_list),
                    "vulnerability_fix_rate": sum(
                        1 for e in evaluations_list if e.fixes_vulnerability
                    )
                    / len(evaluations_list),
                }

        return type_metrics

    def _basic_js_syntax_check(self, code: str) -> bool:
        """Basic JavaScript syntax validation"""
        # Simple heuristics - in practice use a real JS parser
        brackets = {"(": ")", "[": "]", "{": "}"}
        stack = []

        in_string = False
        in_comment = False
        escape_next = False

        for i, char in enumerate(code):
            if escape_next:
                escape_next = False
                continue

            if char == "\\" and in_string:
                escape_next = True
                continue

            if char in ['"', "'", "`"] and not in_comment:
                in_string = not in_string
                continue

            if in_string:
                continue

            if char == "/" and i + 1 < len(code):
                if code[i + 1] == "/":
                    in_comment = True
                    continue
                elif code[i + 1] == "*":
                    in_comment = "block"
                    continue

            if (
                in_comment == "block"
                and char == "*"
                and i + 1 < len(code)
                and code[i + 1] == "/"
            ):
                in_comment = False
                continue

            if in_comment == True and char == "\n":
                in_comment = False
                continue

            if in_comment:
                continue

            if char in brackets:
                stack.append(brackets[char])
            elif char in brackets.values():
                if not stack or stack.pop() != char:
                    return False

        return len(stack) == 0 and not in_string

    def _get_vulnerability_patterns(self, vulnerability_type: str) -> Dict[str, str]:
        """Get regex patterns for vulnerability detection"""
        patterns = {
            "sql-injection": {
                "string_concatenation": r'["\'].*\+.*["\']',
                "template_literal": r"`.*\$\{.*\}.*`",
                "direct_query": r"(query|execute|run)\s*\([^)]*\+",
                "no_parameterization": r"SELECT.*WHERE.*[+]",
            },
            "xss": {
                "innerHTML": r"\.innerHTML\s*=",
                "document_write": r"document\.write\s*\(",
                "eval": r"\beval\s*\(",
                "unescaped_output": r"<.*\$\{.*\}.*>",
            },
            "command-injection": {
                "exec": r"\bexec\s*\(",
                "spawn": r"\bspawn\s*\(",
                "system": r"\bsystem\s*\(",
                "shell_execution": r"shell\s*=\s*True",
            },
        }

        return patterns.get(vulnerability_type, {})

    def _calculate_fix_similarity(self, fix1: str, fix2: str) -> float:
        """Calculate similarity between two fixes using simple text similarity"""
        # Simple Jaccard similarity on tokens
        tokens1 = set(re.findall(r"\w+", fix1.lower()))
        tokens2 = set(re.findall(r"\w+", fix2.lower()))

        if not tokens1 and not tokens2:
            return 1.0

        intersection = len(tokens1 & tokens2)
        union = len(tokens1 | tokens2)

        return intersection / union if union > 0 else 0.0

    def _compare_repair_approaches(
        self,
        cg_suggestions: List[RepairSuggestion],
        expert_suggestions: List[RepairSuggestion],
    ) -> Dict[str, Any]:
        """Compare repair approaches between AI and expert fixes"""
        # Analyze repair types
        cg_types = [s.repair_type.value for s in cg_suggestions]
        expert_types = [s.repair_type.value for s in expert_suggestions]

        # Type distribution
        cg_type_dist = {t: cg_types.count(t) / len(cg_types) for t in set(cg_types)}
        expert_type_dist = {
            t: expert_types.count(t) / len(expert_types) for t in set(expert_types)
        }

        return {
            "cg_type_distribution": cg_type_dist,
            "expert_type_distribution": expert_type_dist,
            "approach_alignment": len(set(cg_types) & set(expert_types))
            / len(set(cg_types) | set(expert_types)),
        }

    def analyze_confidence_correlation(
        self, suggestions: List[RepairSuggestion], evaluations: List[RepairEvaluation]
    ) -> Dict[str, Any]:
        """
        Analyze correlation between confidence scores and evaluation metrics using scipy

        Args:
            suggestions: List of repair suggestions with confidence scores
            evaluations: List of human evaluations

        Returns:
            Dictionary with correlation analysis
        """
        # Create DataFrame for analysis
        suggestions_df = pd.DataFrame([s.to_dict() for s in suggestions])
        evaluations_df = pd.DataFrame([e.to_dict() for e in evaluations])

        # Merge on sample_id
        merged_df = pd.merge(
            suggestions_df, evaluations_df, on="sample_id", how="inner"
        )

        if len(merged_df) < 10 or "confidence_score" not in merged_df.columns:
            return {"error": "Insufficient data for correlation analysis"}

        # Remove rows with missing confidence scores
        valid_df = merged_df.dropna(subset=["confidence_score"])

        if len(valid_df) < 10:
            return {"error": "Insufficient valid confidence scores"}

        # Calculate correlations using scipy
        correlations = {}
        evaluation_metrics = [
            "correctness_score",
            "completeness_score",
            "maintainability_score",
            "security_effectiveness",
            "explanation_clarity",
        ]

        for metric in evaluation_metrics:
            if metric in valid_df.columns:
                # Pearson correlation
                pearson_r, pearson_p = pearsonr(
                    valid_df["confidence_score"], valid_df[metric]
                )

                # Spearman correlation (rank-based, more robust)
                spearman_r, spearman_p = spearmanr(
                    valid_df["confidence_score"], valid_df[metric]
                )

                correlations[metric] = {
                    "pearson_correlation": float(pearson_r),
                    "pearson_p_value": float(pearson_p),
                    "spearman_correlation": float(spearman_r),
                    "spearman_p_value": float(spearman_p),
                    "pearson_significant": pearson_p < 0.05,
                    "spearman_significant": spearman_p < 0.05,
                    "sample_size": len(valid_df),
                }

        # Overall correlation summary
        significant_pearson = sum(
            1 for c in correlations.values() if c["pearson_significant"]
        )
        significant_spearman = sum(
            1 for c in correlations.values() if c["spearman_significant"]
        )

        return {
            "correlations": correlations,
            "summary": {
                "total_metrics_analyzed": len(correlations),
                "significant_pearson_correlations": significant_pearson,
                "significant_spearman_correlations": significant_spearman,
                "confidence_score_range": {
                    "min": float(valid_df["confidence_score"].min()),
                    "max": float(valid_df["confidence_score"].max()),
                    "mean": float(valid_df["confidence_score"].mean()),
                    "std": float(valid_df["confidence_score"].std()),
                },
            },
            "interpretation": self._interpret_confidence_correlations(correlations),
        }

    def _interpret_confidence_correlations(self, correlations: Dict[str, Any]) -> str:
        """Interpret the confidence correlation results"""
        strong_correlations = []
        weak_correlations = []

        for metric, corr_data in correlations.items():
            pearson_r = abs(corr_data["pearson_correlation"])
            if corr_data["pearson_significant"]:
                if pearson_r > 0.7:
                    strong_correlations.append(f"{metric} (r={pearson_r:.2f})")
                elif pearson_r > 0.3:
                    weak_correlations.append(f"{metric} (r={pearson_r:.2f})")

        if strong_correlations:
            return f"Strong correlations found with: {', '.join(strong_correlations)}"
        elif weak_correlations:
            return f"Weak correlations found with: {', '.join(weak_correlations)}"
        else:
            return "No significant correlations between confidence scores and evaluation metrics"

    def generate_report(
        self,
        suggestions: List[RepairSuggestion],
        evaluations: List[RepairEvaluation],
        output_path: Optional[Path] = None,
    ) -> Dict[str, Any]:
        """
        Generate comprehensive repair quality report

        Args:
            suggestions: Repair suggestions to analyze
            evaluations: Human evaluations
            output_path: Optional path to save report

        Returns:
            Dictionary with complete analysis
        """
        logger.info(
            "Generating repair quality report for %d suggestions", len(suggestions)
        )

        # Calculate main metrics
        quality_metrics = self.calculate_metrics(suggestions, evaluations)

        # Additional analysis
        vulnerability_type_analysis = self._analyze_by_vulnerability_type(
            suggestions, evaluations
        )

        report_data = {
            "timestamp": json.dumps(None),  # Would use datetime in real implementation
            "summary": {
                "total_suggestions": len(suggestions),
                "total_evaluations": len(evaluations),
                "vulnerability_types": list(
                    set(s.vulnerability_type for s in suggestions)
                ),
                "repair_types": list(set(s.repair_type.value for s in suggestions)),
            },
            "quality_metrics": quality_metrics.to_dict(),
            "by_vulnerability_type": vulnerability_type_analysis,
            "configuration": {
                "expert_threshold": self.expert_threshold,
                "production_thresholds": self.production_thresholds,
            },
        }

        # Save report if path provided
        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(report_data, f, indent=2)
            logger.info("Saved repair quality report to %s", output_path)

        return report_data

    def _analyze_by_vulnerability_type(
        self, suggestions: List[RepairSuggestion], evaluations: List[RepairEvaluation]
    ) -> Dict[str, Any]:
        """Analyze repair quality by vulnerability type"""
        eval_dict = {e.sample_id: e for e in evaluations}

        vuln_groups = {}
        for suggestion in suggestions:
            if suggestion.sample_id in eval_dict:
                vuln_type = suggestion.vulnerability_type
                if vuln_type not in vuln_groups:
                    vuln_groups[vuln_type] = []
                vuln_groups[vuln_type].append(
                    (suggestion, eval_dict[suggestion.sample_id])
                )

        vuln_analysis = {}
        for vuln_type, pairs in vuln_groups.items():
            if len(pairs) >= 3:
                evaluations_list = [eval_data for _, eval_data in pairs]
                vuln_analysis[vuln_type] = {
                    "n_repairs": len(pairs),
                    "avg_correctness": sum(
                        e.correctness_score for e in evaluations_list
                    )
                    / len(evaluations_list),
                    "avg_security_effectiveness": sum(
                        e.security_effectiveness for e in evaluations_list
                    )
                    / len(evaluations_list),
                    "vulnerability_fix_rate": sum(
                        1 for e in evaluations_list if e.fixes_vulnerability
                    )
                    / len(evaluations_list),
                }

        return vuln_analysis


if __name__ == "__main__":
    # Example usage
    calculator = RepairQualityCalculator(expert_threshold=4)

    # Example suggestions and evaluations
    example_suggestions = [
        RepairSuggestion(
            "sample_1",
            "sql-injection",
            "query = 'SELECT * FROM users WHERE id = ' + userId",
            "query = 'SELECT * FROM users WHERE id = ?'; params = [userId]",
            RepairType.INPUT_VALIDATION,
            0.9,
        )
    ]

    example_evaluations = [
        RepairEvaluation("sample_1", 4, 4, 3, 5, True, True, True, False, 1, 4)
    ]

    # Calculate metrics
    example_quality_metrics = calculator.calculate_metrics(
        example_suggestions, example_evaluations
    )
    print(f"Overall Quality Score: {example_quality_metrics.overall_quality_score:.2f}")
    print(f"Expert Approval Rate: {example_quality_metrics.expert_approval_rate:.1%}")
    print(
        f"Vulnerability Fix Rate: {example_quality_metrics.vulnerability_fix_rate:.1%}"
    )

    # Generate report
    report = calculator.generate_report(example_suggestions, example_evaluations)
    print(f"Generated report for {report['summary']['total_suggestions']} suggestions")
