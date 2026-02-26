#!/usr/bin/env python3
"""
Dataset Analyzer for SAST Baseline Testing
Integrates the Code Guardian evaluation datasets with SAST tools for baseline comparison.
"""

import json
import sys
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Any, Tuple
import argparse
from datetime import datetime

# Add the project root to Python path for imports
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


class SastDatasetAnalyzer:
    """Analyzes datasets using SAST tools and generates baseline metrics."""

    def __init__(self, sast_dir: Path, python_env: Path):
        self.sast_dir = sast_dir
        self.python_env = python_env
        self.semgrep_bin = python_env / "bin" / "semgrep"
        self.codeql_bin = sast_dir / "codeql_tools" / "codeql" / "codeql"
        self.results_dir = sast_dir / "results"
        self.results_dir.mkdir(exist_ok=True)

    def load_dataset(self, dataset_path: Path) -> Dict[str, Any]:
        """Load a dataset JSON file."""
        with open(dataset_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def extract_code_files(
        self, dataset: Dict[str, Any], output_dir: Path
    ) -> List[Tuple[str, Path, Dict]]:
        """Extract code samples from dataset to temporary files."""
        output_dir.mkdir(exist_ok=True)
        file_mappings = []

        for sample in dataset.get("samples", []):
            # Create filename based on sample ID
            filename = f"{sample['id']}.js"
            file_path = output_dir / filename

            # Write code to file with metadata as comments
            code_content = f"""// Sample ID: {sample['id']}
// CWE: {sample['cwe_id']}
// Category: {sample['category']}
// Severity: {sample['severity']}
// Description: {sample['description']}
// Vulnerable lines: {sample.get('vulnerable_lines', [])}

{sample['code']}
"""

            with open(file_path, "w", encoding="utf-8") as f:
                f.write(code_content)

            file_mappings.append((sample["id"], file_path, sample))

        return file_mappings

    def run_semgrep_on_dataset(
        self, dataset_dir: Path, output_file: Path
    ) -> Dict[str, Any]:
        """Run Semgrep analysis on dataset files."""
        print(f"Running Semgrep analysis on {dataset_dir}...")

        cmd = [
            str(self.semgrep_bin),
            "--config=p/security-audit",
            "--config=p/javascript",
            "--config=p/typescript",
            "--config=p/owasp-top-ten",
            "--json",
            f"--output={output_file}",
            "--metrics=off",
            "--quiet",
            str(dataset_dir),
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if result.returncode not in [0, 1]:  # Semgrep returns 1 when findings exist
                print(f"Semgrep warning/error: {result.stderr}")

            # Load and return results
            if output_file.exists():
                with open(output_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            else:
                return {"results": []}

        except (
            subprocess.SubprocessError,
            FileNotFoundError,
            json.JSONDecodeError,
        ) as e:
            print(f"Error running Semgrep: {e}")
            return {"results": []}

    def run_codeql_on_dataset(
        self, dataset_dir: Path, output_file: Path
    ) -> Dict[str, Any]:
        """Run CodeQL analysis on dataset files."""
        print(f"Running CodeQL analysis on {dataset_dir}...")

        # Create database
        db_path = self.results_dir / f"codeql_db_{dataset_dir.name}"
        if db_path.exists():
            subprocess.run(["rm", "-rf", str(db_path)], check=False)

        # Create database
        create_cmd = [
            str(self.codeql_bin),
            "database",
            "create",
            "--language=javascript",
            f"--source-root={dataset_dir}",
            "--threads=4",
            str(db_path),
        ]

        try:
            result = subprocess.run(
                create_cmd, capture_output=True, text=True, check=False
            )
            if result.returncode != 0:
                print(f"CodeQL database creation error: {result.stderr}")
                return {"runs": [{"results": []}]}

            # Analyze database
            analyze_cmd = [
                str(self.codeql_bin),
                "database",
                "analyze",
                str(db_path),
                "codeql/javascript-queries:codeql-suites/javascript-security-and-quality.qls",
                "--format=sarif-latest",
                f"--output={output_file}",
                "--threads=4",
                "--ram=8192",
            ]

            result = subprocess.run(
                analyze_cmd, capture_output=True, text=True, check=False
            )
            if result.returncode != 0:
                print(f"CodeQL analysis error: {result.stderr}")
                return {"runs": [{"results": []}]}

            # Load and return results
            if output_file.exists():
                with open(output_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            else:
                return {"runs": [{"results": []}]}

        except (
            subprocess.SubprocessError,
            FileNotFoundError,
            json.JSONDecodeError,
        ) as e:
            print(f"Error running CodeQL: {e}")
            return {"runs": [{"results": []}]}

    def map_results_to_samples(
        self,
        semgrep_results: Dict,
        codeql_results: Dict,
        file_mappings: List[Tuple[str, Path, Dict]],
    ) -> Dict[str, Any]:
        """Map SAST tool results back to original dataset samples."""

        mapped_results = {
            "sample_results": {},
            "detection_summary": {
                "total_samples": len(file_mappings),
                "semgrep_detections": 0,
                "codeql_detections": 0,
                "both_detected": 0,
                "neither_detected": 0,
            },
        }

        # Process each sample
        for sample_id, file_path, sample_data in file_mappings:
            file_str = str(file_path)

            # Find Semgrep results for this file
            semgrep_findings = []
            for result in semgrep_results.get("results", []):
                if file_str in result.get("path", ""):
                    semgrep_findings.append(
                        {
                            "rule_id": result.get("check_id", ""),
                            "message": result.get("extra", {}).get("message", ""),
                            "severity": result.get("extra", {}).get("severity", ""),
                            "line": result.get("start", {}).get("line", 0),
                            "cwe": result.get("extra", {})
                            .get("metadata", {})
                            .get("cwe", []),
                        }
                    )

            # Find CodeQL results for this file
            codeql_findings = []
            for run in codeql_results.get("runs", []):
                for result in run.get("results", []):
                    for location in result.get("locations", []):
                        uri = (
                            location.get("physicalLocation", {})
                            .get("artifactLocation", {})
                            .get("uri", "")
                        )
                        if file_path.name in uri:
                            codeql_findings.append(
                                {
                                    "rule_id": result.get("ruleId", ""),
                                    "message": result.get("message", {}).get(
                                        "text", ""
                                    ),
                                    "level": result.get("level", ""),
                                    "line": location.get("physicalLocation", {})
                                    .get("region", {})
                                    .get("startLine", 0),
                                }
                            )

            # Determine detection status
            semgrep_detected = len(semgrep_findings) > 0
            codeql_detected = len(codeql_findings) > 0

            mapped_results["sample_results"][sample_id] = {
                "sample_metadata": sample_data,
                "semgrep_detected": semgrep_detected,
                "codeql_detected": codeql_detected,
                "semgrep_findings": semgrep_findings,
                "codeql_findings": codeql_findings,
                "detection_status": {
                    "both_tools": semgrep_detected and codeql_detected,
                    "semgrep_only": semgrep_detected and not codeql_detected,
                    "codeql_only": codeql_detected and not semgrep_detected,
                    "neither_tool": not semgrep_detected and not codeql_detected,
                },
            }

            # Update summary
            if semgrep_detected:
                mapped_results["detection_summary"]["semgrep_detections"] += 1
            if codeql_detected:
                mapped_results["detection_summary"]["codeql_detections"] += 1
            if semgrep_detected and codeql_detected:
                mapped_results["detection_summary"]["both_detected"] += 1
            if not semgrep_detected and not codeql_detected:
                mapped_results["detection_summary"]["neither_detected"] += 1

        return mapped_results

    def calculate_baseline_metrics(self, mapped_results: Dict) -> Dict[str, Any]:
        """Calculate precision, recall, and F1 metrics for SAST tools."""

        metrics = {
            "semgrep": {"tp": 0, "fp": 0, "tn": 0, "fn": 0},
            "codeql": {"tp": 0, "fp": 0, "tn": 0, "fn": 0},
        }

        # For this baseline, we assume all samples in our dataset are vulnerable (true positives)
        # This is a simplification - in a real evaluation, we'd need clean samples too

        for result in mapped_results["sample_results"].values():
            # Semgrep metrics
            if result["semgrep_detected"]:
                metrics["semgrep"]["tp"] += 1  # Correctly detected vulnerability
            else:
                metrics["semgrep"]["fn"] += 1  # Missed vulnerability

            # CodeQL metrics
            if result["codeql_detected"]:
                metrics["codeql"]["tp"] += 1  # Correctly detected vulnerability
            else:
                metrics["codeql"]["fn"] += 1  # Missed vulnerability

        # Calculate precision, recall, F1
        baseline_metrics = {}
        for tool in ["semgrep", "codeql"]:
            tp = metrics[tool]["tp"]
            fp = metrics[tool]["fp"]
            fn = metrics[tool]["fn"]

            precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            f1 = (
                2 * precision * recall / (precision + recall)
                if (precision + recall) > 0
                else 0
            )

            baseline_metrics[tool] = {
                "true_positives": tp,
                "false_positives": fp,
                "false_negatives": fn,
                "precision": precision,
                "recall": recall,
                "f1_score": f1,
                "detection_rate": recall,  # For vulnerable-only dataset, recall = detection rate
            }

        return baseline_metrics

    def analyze_dataset(self, dataset_name: str, dataset_path: Path) -> Dict[str, Any]:
        """Complete analysis of a dataset."""
        print(f"\n=== Analyzing Dataset: {dataset_name} ===")

        # Load dataset
        dataset = self.load_dataset(dataset_path)
        print(f"Loaded {len(dataset.get('samples', []))} samples")

        # Create temporary directory for code files
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Extract code files
            file_mappings = self.extract_code_files(dataset, temp_path)
            print(f"Extracted {len(file_mappings)} code files")

            # Run SAST tools
            semgrep_output = self.results_dir / f"{dataset_name}_semgrep.json"
            codeql_output = self.results_dir / f"{dataset_name}_codeql.sarif"

            semgrep_results = self.run_semgrep_on_dataset(temp_path, semgrep_output)
            codeql_results = self.run_codeql_on_dataset(temp_path, codeql_output)

            # Map results to samples
            mapped_results = self.map_results_to_samples(
                semgrep_results, codeql_results, file_mappings
            )

            # Calculate metrics
            baseline_metrics = self.calculate_baseline_metrics(mapped_results)

            # Create comprehensive analysis report
            analysis_report = {
                "dataset_info": {
                    "name": dataset_name,
                    "total_samples": len(dataset.get("samples", [])),
                    "categories": dataset.get("metadata", {}).get("categories", []),
                    "cwe_ids": dataset.get("metadata", {}).get("cwe_ids", []),
                },
                "analysis_timestamp": datetime.now().isoformat(),
                "detection_summary": mapped_results["detection_summary"],
                "baseline_metrics": baseline_metrics,
                "detailed_results": mapped_results["sample_results"],
            }

            # Save analysis report
            report_file = self.results_dir / f"{dataset_name}_analysis_report.json"
            with open(report_file, "w", encoding="utf-8") as f:
                json.dump(analysis_report, f, indent=2)

            print(f"Analysis complete. Report saved to: {report_file}")

            return analysis_report

    def generate_summary_report(self, all_analyses: List[Dict]) -> None:
        """Generate a summary report across all datasets."""

        summary = {
            "evaluation_timestamp": datetime.now().isoformat(),
            "datasets_analyzed": len(all_analyses),
            "total_samples": sum(
                a["dataset_info"]["total_samples"] for a in all_analyses
            ),
            "overall_metrics": {
                "semgrep": {"total_tp": 0, "total_fn": 0},
                "codeql": {"total_tp": 0, "total_fn": 0},
            },
            "dataset_summaries": [],
        }

        for analysis in all_analyses:
            dataset_name = analysis["dataset_info"]["name"]
            metrics = analysis["baseline_metrics"]

            summary["dataset_summaries"].append(
                {
                    "dataset": dataset_name,
                    "samples": analysis["dataset_info"]["total_samples"],
                    "semgrep_detection_rate": metrics["semgrep"]["detection_rate"],
                    "codeql_detection_rate": metrics["codeql"]["detection_rate"],
                    "both_detected": analysis["detection_summary"]["both_detected"],
                    "neither_detected": analysis["detection_summary"][
                        "neither_detected"
                    ],
                }
            )

            # Aggregate metrics
            summary["overall_metrics"]["semgrep"]["total_tp"] += metrics["semgrep"][
                "true_positives"
            ]
            summary["overall_metrics"]["semgrep"]["total_fn"] += metrics["semgrep"][
                "false_negatives"
            ]
            summary["overall_metrics"]["codeql"]["total_tp"] += metrics["codeql"][
                "true_positives"
            ]
            summary["overall_metrics"]["codeql"]["total_fn"] += metrics["codeql"][
                "false_negatives"
            ]

        # Calculate overall detection rates
        for tool in ["semgrep", "codeql"]:
            tp = summary["overall_metrics"][tool]["total_tp"]
            fn = summary["overall_metrics"][tool]["total_fn"]
            overall_detection_rate = tp / (tp + fn) if (tp + fn) > 0 else 0
            summary["overall_metrics"][tool][
                "overall_detection_rate"
            ] = overall_detection_rate

        # Save summary
        summary_file = self.results_dir / "dataset_analysis_summary.json"
        with open(summary_file, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)

        print("\n=== SAST Baseline Analysis Summary ===")
        print(f"Total datasets: {summary['datasets_analyzed']}")
        print(f"Total samples: {summary['total_samples']}")
        print(
            f"Semgrep overall detection rate: {summary['overall_metrics']['semgrep']['overall_detection_rate']:.2%}"
        )
        print(
            f"CodeQL overall detection rate: {summary['overall_metrics']['codeql']['overall_detection_rate']:.2%}"
        )
        print(f"Summary saved to: {summary_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Analyze datasets with SAST tools for baseline metrics"
    )
    parser.add_argument(
        "--dataset",
        choices=["benchmark", "extended", "adversarial", "real-world", "all"],
        default="all",
        help="Dataset to analyze",
    )
    parser.add_argument(
        "--sast-dir",
        type=Path,
        help="SAST baseline directory",
        default=Path(__file__).parent,
    )
    parser.add_argument(
        "--python-env",
        type=Path,
        help="Python virtual environment path",
        default=Path(__file__).parent.parent.parent / ".venv",
    )

    args = parser.parse_args()

    # Initialize analyzer
    analyzer = SastDatasetAnalyzer(args.sast_dir, args.python_env)

    # Define dataset paths
    datasets_dir = args.sast_dir.parent.parent / "datasets"
    available_datasets = {
        "benchmark": datasets_dir / "benchmark" / "benchmark_dataset.json",
        "extended": datasets_dir / "extended" / "extended_dataset.json",
        "adversarial": datasets_dir / "adversarial" / "adversarial_dataset.json",
        "real-world": datasets_dir / "real-world" / "real-world_dataset.json",
    }

    # Analyze specified datasets
    analyses = []
    if args.dataset == "all":
        for name, path in available_datasets.items():
            if path.exists():
                analysis = analyzer.analyze_dataset(name, path)
                analyses.append(analysis)
            else:
                print(f"Warning: Dataset {name} not found at {path}")
    else:
        if args.dataset in available_datasets:
            path = available_datasets[args.dataset]
            if path.exists():
                analysis = analyzer.analyze_dataset(args.dataset, path)
                analyses.append(analysis)
            else:
                print(f"Error: Dataset {args.dataset} not found at {path}")
                return 1
        else:
            print(f"Error: Unknown dataset {args.dataset}")
            return 1

    # Generate summary report
    if analyses:
        analyzer.generate_summary_report(analyses)
    else:
        print("No datasets analyzed")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
