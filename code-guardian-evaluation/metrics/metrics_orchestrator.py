#!/usr/bin/env python3
"""
Main Metrics Orchestrator for Code Guardian VS Code Extension Evaluation

This module orchestrates the execution of all metrics calculators and provides
a unified interface for comprehensive evaluation of the Code Guardian extension.

Integrates:
- Accuracy Calculator
- Latency Calculator
- Repair Quality Calculator
- Robustness Calculator
- Usability Calculator

Academic Standards:
- Comprehensive evaluation framework
- Statistical rigor across all metrics
- Standardized reporting format
- Reproducible evaluation pipeline
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Any
from datetime import datetime
import statistics

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class MetricsOrchestrator:
    """
    Main orchestrator for all evaluation metrics

    Features:
    - Unified execution of all metric calculators
    - Comprehensive report generation
    - Statistical summary across all dimensions
    - Export capabilities for academic papers
    """

    def __init__(self, output_dir: Path):
        """
        Initialize the metrics orchestrator

        Args:
            output_dir: Directory to save all evaluation results
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Initialize calculators with default configurations
        self._init_calculators()

        logger.info(
            "Initialized MetricsOrchestrator with output directory: %s", output_dir
        )

    def _init_calculators(self):
        """Initialize all metric calculators"""
        try:
            # Import and initialize accuracy calculator
            import sys

            sys.path.append(str(self.output_dir.parent))

            from accuracy.accuracy_calculator import AccuracyCalculator

            self.accuracy_calculator = AccuracyCalculator(confidence_level=0.95)

            from latency.latency_calculator import LatencyCalculator

            self.latency_calculator = LatencyCalculator()

            # Import with correct module path (using hyphens in directory names)
            import importlib.util

            # Repair quality calculator
            repair_spec = importlib.util.spec_from_file_location(
                "repair_quality_calculator",
                Path(__file__).parent
                / "repair-quality"
                / "repair_quality_calculator.py",
            )
            repair_module = importlib.util.module_from_spec(repair_spec)
            repair_spec.loader.exec_module(repair_module)
            self.repair_quality_calculator = repair_module.RepairQualityCalculator(
                expert_threshold=4
            )

            # Robustness calculator
            robustness_spec = importlib.util.spec_from_file_location(
                "robustness_calculator",
                Path(__file__).parent / "robustness" / "robustness_calculator.py",
            )
            robustness_module = importlib.util.module_from_spec(robustness_spec)
            robustness_spec.loader.exec_module(robustness_module)
            self.robustness_calculator = robustness_module.RobustnessCalculator()

            # Usability calculator
            usability_spec = importlib.util.spec_from_file_location(
                "usability_calculator",
                Path(__file__).parent / "usability" / "usability_calculator.py",
            )
            usability_module = importlib.util.module_from_spec(usability_spec)
            usability_spec.loader.exec_module(usability_module)
            self.usability_calculator = usability_module.UsabilityCalculator()

            logger.info("All metric calculators initialized successfully")

        except ImportError as e:
            logger.warning("Some metric calculator imports failed: %s", str(e))
            # Initialize placeholder calculators for demonstration
            self.accuracy_calculator = None
            self.latency_calculator = None
            self.repair_quality_calculator = None
            self.robustness_calculator = None
            self.usability_calculator = None

    def run_complete_evaluation(
        self,
        detection_data: List[Dict[str, Any]],
        latency_data: List[Dict[str, Any]],
        repair_data: List[Dict[str, Any]],
        robustness_data: List[Dict[str, Any]],
        usability_data: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Run complete evaluation across all metrics

        Args:
            detection_data: Detection results data
            latency_data: Performance measurement data
            repair_data: Repair suggestion and evaluation data
            robustness_data: Robustness test data
            usability_data: User interaction data

        Returns:
            Comprehensive evaluation results dictionary
        """
        logger.info(
            "Starting complete evaluation with %d detection results, %d latency measurements",
            len(detection_data),
            len(latency_data),
        )

        evaluation_results = {}

        # 1. Accuracy Metrics
        logger.info("Calculating accuracy metrics...")
        try:
            if self.accuracy_calculator and detection_data:
                # Convert data and calculate metrics
                accuracy_metrics = self._calculate_accuracy_metrics(detection_data)
                evaluation_results["accuracy"] = accuracy_metrics
                logger.info("Accuracy evaluation completed")
            else:
                evaluation_results["accuracy"] = {
                    "error": "No accuracy calculator or data available"
                }

        except ValueError as e:
            logger.error("Accuracy evaluation failed: %s", str(e))
            evaluation_results["accuracy"] = {"error": str(e)}

        # 2. Latency Metrics
        logger.info("Calculating latency metrics...")
        try:
            if self.latency_calculator and latency_data:
                latency_metrics = self._calculate_latency_metrics(latency_data)
                evaluation_results["latency"] = latency_metrics
                logger.info("Latency evaluation completed")
            else:
                evaluation_results["latency"] = {
                    "error": "No latency calculator or data available"
                }

        except ValueError as e:
            logger.error("Latency evaluation failed: %s", str(e))
            evaluation_results["latency"] = {"error": str(e)}

        # 3. Repair Quality Metrics
        logger.info("Calculating repair quality metrics...")
        try:
            if self.repair_quality_calculator and repair_data:
                repair_metrics = self._calculate_repair_quality_metrics(repair_data)
                evaluation_results["repair_quality"] = repair_metrics
                logger.info("Repair quality evaluation completed")
            else:
                evaluation_results["repair_quality"] = {
                    "error": "No repair quality calculator or data available"
                }

        except ValueError as e:
            logger.error("Repair quality evaluation failed: %s", str(e))
            evaluation_results["repair_quality"] = {"error": str(e)}

        # 4. Robustness Metrics
        logger.info("Calculating robustness metrics...")
        try:
            if self.robustness_calculator and robustness_data:
                robustness_metrics = self._calculate_robustness_metrics(robustness_data)
                evaluation_results["robustness"] = robustness_metrics
                logger.info("Robustness evaluation completed")
            else:
                evaluation_results["robustness"] = {
                    "error": "No robustness calculator or data available"
                }

        except ValueError as e:
            logger.error("Robustness evaluation failed: %s", str(e))
            evaluation_results["robustness"] = {"error": str(e)}

        # 5. Usability Metrics
        logger.info("Calculating usability metrics...")
        try:
            if self.usability_calculator and usability_data:
                usability_metrics = self._calculate_usability_metrics(usability_data)
                evaluation_results["usability"] = usability_metrics
                logger.info("Usability evaluation completed")
            else:
                evaluation_results["usability"] = {
                    "error": "No usability calculator or data available"
                }

        except ValueError as e:
            logger.error("Usability evaluation failed: %s", str(e))
            evaluation_results["usability"] = {"error": str(e)}

        # Generate comprehensive summary
        evaluation_results["summary"] = self._generate_evaluation_summary(
            evaluation_results
        )
        evaluation_results["metadata"] = {
            "evaluation_timestamp": datetime.now().isoformat(),
            "total_detection_data": len(detection_data),
            "total_latency_data": len(latency_data),
            "total_repair_data": len(repair_data),
            "total_robustness_data": len(robustness_data),
            "total_usability_data": len(usability_data),
        }

        # Save master evaluation report
        master_report_path = self.output_dir / "master_evaluation_report.json"
        with open(master_report_path, "w", encoding="utf-8") as f:
            json.dump(evaluation_results, f, indent=2, default=str)

        logger.info(
            "Complete evaluation finished. Master report saved to: %s",
            master_report_path,
        )
        return evaluation_results

    def _calculate_accuracy_metrics(
        self, detection_data: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Calculate accuracy metrics from detection data"""
        if not detection_data:
            return {"error": "No detection data provided"}

        # Use the proper accuracy calculator if available
        if self.accuracy_calculator:
            try:
                # Convert to DetectionResult format expected by accuracy calculator
                from accuracy.accuracy_calculator import DetectionResult

                results = []
                for item in detection_data:
                    result = DetectionResult(
                        sample_id=item.get("sample_id", ""),
                        true_label=item.get(
                            "correct", False
                        ),  # Note: 'correct' means prediction was right
                        predicted_label=True,  # Assume detected (since it's in detection data)
                        confidence=item.get("confidence", 0.5),
                        detection_time_ms=item.get("detection_time_ms", 0),
                        vulnerability_type=item.get("vulnerability_type", "unknown"),
                        tool_name=item.get("tool_name", "code_guardian"),
                    )
                    results.append(result)

                # Calculate comprehensive metrics
                metrics = self.accuracy_calculator.calculate_metrics(results)
                return metrics.to_dict()

            except Exception as e:
                logger.warning("Failed to use accuracy calculator: %s", str(e))
                # Fall back to basic calculation

        # Basic accuracy calculation as fallback
        correct_detections = sum(
            1 for item in detection_data if item.get("correct", False)
        )
        total_detections = len(detection_data)

        accuracy = (
            correct_detections / total_detections if total_detections > 0 else 0.0
        )

        return {
            "accuracy": accuracy,
            "correct_detections": correct_detections,
            "total_detections": total_detections,
            "precision": accuracy,  # Simplified
            "recall": accuracy,  # Simplified
            "f1_score": accuracy,  # Simplified
        }

    def _calculate_latency_metrics(
        self, latency_data: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Calculate latency metrics from performance data"""
        if not latency_data:
            return {"error": "No latency data provided"}

        # Use the proper latency calculator if available
        if self.latency_calculator:
            try:
                # The latency calculator expects the data in the right format
                metrics = self.latency_calculator.calculate_metrics(latency_data)
                return metrics
            except Exception as e:
                logger.warning("Failed to use latency calculator: %s", str(e))
                # Fall back to basic calculation

        # Basic calculation as fallback
        latencies = [
            item.get("latency_ms", 0)
            for item in latency_data
            if item.get("latency_ms") is not None
        ]

        if not latencies:
            return {"error": "No valid latency measurements found"}

        return {
            "mean_latency_ms": statistics.mean(latencies),
            "median_latency_ms": statistics.median(latencies),
            "p95_latency_ms": self._percentile(latencies, 95),
            "p99_latency_ms": self._percentile(latencies, 99),
            "min_latency_ms": min(latencies),
            "max_latency_ms": max(latencies),
            "total_measurements": len(latencies),
        }

    def _calculate_repair_quality_metrics(
        self, repair_data: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Calculate repair quality metrics"""
        if not repair_data:
            return {"error": "No repair data provided"}

        quality_scores = [item.get("quality_score", 0) for item in repair_data]

        return {
            "avg_quality_score": statistics.mean(quality_scores),
            "median_quality_score": statistics.median(quality_scores),
            "high_quality_rate": sum(1 for score in quality_scores if score >= 4)
            / len(quality_scores),
            "total_repairs": len(repair_data),
        }

    def _calculate_robustness_metrics(
        self, robustness_data: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Calculate robustness metrics"""
        if not robustness_data:
            return {"error": "No robustness data provided"}

        success_count = sum(1 for item in robustness_data if item.get("success", False))
        total_tests = len(robustness_data)

        return {
            "success_rate": success_count / total_tests if total_tests > 0 else 0.0,
            "total_tests": total_tests,
            "successful_tests": success_count,
            "failed_tests": total_tests - success_count,
        }

    def _calculate_usability_metrics(
        self, usability_data: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Calculate usability metrics"""
        if not usability_data:
            return {"error": "No usability data provided"}

        completion_rate = sum(
            1 for item in usability_data if item.get("task_completed", False)
        ) / len(usability_data)
        satisfaction_scores = [
            item.get("satisfaction_rating", 0)
            for item in usability_data
            if item.get("satisfaction_rating")
        ]

        return {
            "task_completion_rate": completion_rate,
            "avg_satisfaction": (
                statistics.mean(satisfaction_scores) if satisfaction_scores else 0.0
            ),
            "total_interactions": len(usability_data),
        }

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

    def _generate_evaluation_summary(
        self, evaluation_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate high-level summary of evaluation results"""
        summary = {
            "overall_score": 0.0,
            "dimension_scores": {},
            "strengths": [],
            "weaknesses": [],
            "recommendations": [],
        }

        scores = []

        # Process each dimension
        for dimension, dimension_results in evaluation_results.items():
            if dimension in [
                "accuracy",
                "latency",
                "repair_quality",
                "robustness",
                "usability",
            ]:
                if "error" not in dimension_results:
                    # Extract key score for each dimension
                    if dimension == "accuracy":
                        score = dimension_results.get("f1_score", 0)
                    elif dimension == "latency":
                        # Convert latency to score (lower is better)
                        p95 = dimension_results.get("p95_latency_ms", 10000)
                        score = max(0, 1 - (p95 / 10000))
                    elif dimension == "repair_quality":
                        score = dimension_results.get("avg_quality_score", 0) / 5.0
                    elif dimension == "robustness":
                        score = dimension_results.get("success_rate", 0)
                    elif dimension == "usability":
                        score = dimension_results.get("task_completion_rate", 0)
                    else:
                        score = 0

                    summary["dimension_scores"][dimension] = score
                    scores.append(score)

                    # Assess performance
                    if score >= 0.8:
                        summary["strengths"].append(f"Strong {dimension} performance")
                    elif score < 0.6:
                        summary["weaknesses"].append(f"{dimension} needs improvement")

        # Calculate overall score
        if scores:
            summary["overall_score"] = statistics.mean(scores)

        # Generate recommendations
        if summary["overall_score"] >= 0.8:
            summary["recommendations"].append(
                "Extension ready for production deployment"
            )
        elif summary["overall_score"] >= 0.6:
            summary["recommendations"].append(
                "Address identified weaknesses before deployment"
            )
        else:
            summary["recommendations"].append(
                "Significant improvements needed before deployment"
            )

        return summary

    def generate_academic_summary(
        self, evaluation_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate academic-style summary suitable for research papers"""
        logger.info("Generating academic summary from evaluation results")

        summary = {
            "research_findings": {},
            "performance_benchmarks": {},
            "key_metrics_table": {},
            "limitations": [],
        }

        # Extract key findings
        if (
            "accuracy" in evaluation_results
            and "error" not in evaluation_results["accuracy"]
        ):
            acc_data = evaluation_results["accuracy"]
            summary["research_findings"]["detection_performance"] = {
                "finding": f"Achieved F1-score of {acc_data.get('f1_score', 0):.3f}",
                "precision": acc_data.get("precision", 0),
                "recall": acc_data.get("recall", 0),
            }

        if (
            "latency" in evaluation_results
            and "error" not in evaluation_results["latency"]
        ):
            lat_data = evaluation_results["latency"]
            summary["research_findings"]["performance"] = {
                "finding": f"Median response time of {lat_data.get('median_latency_ms', 0):.1f}ms",
                "p95_latency": lat_data.get("p95_latency_ms", 0),
            }

        # Performance benchmarks
        summary["performance_benchmarks"] = {
            "accuracy_threshold": 0.8,
            "latency_threshold_ms": 5000,
            "quality_threshold": 3.5,
            "usability_threshold": 0.7,
        }

        # Limitations
        summary["limitations"] = [
            "Dataset representativeness",
            "Human evaluation subjectivity",
            "Environment-specific performance",
        ]

        return summary


if __name__ == "__main__":
    # Example usage
    orchestrator = MetricsOrchestrator(Path("./evaluation_results"))

    # Example data
    example_detection_data = [
        {"correct": True, "vulnerability_type": "sql-injection"},
        {"correct": False, "vulnerability_type": "xss"},
        {"correct": True, "vulnerability_type": "sql-injection"},
    ]

    example_latency_data = [
        {"latency_ms": 150.0},
        {"latency_ms": 200.0},
        {"latency_ms": 180.0},
    ]

    # Run evaluation
    results = orchestrator.run_complete_evaluation(
        example_detection_data,
        example_latency_data,
        [],  # No repair data
        [],  # No robustness data
        [],  # No usability data
    )

    print("MetricsOrchestrator evaluation completed!")
    print(f"Overall Score: {results['summary']['overall_score']:.2f}")
    print(f"Results saved to: {orchestrator.output_dir}")
