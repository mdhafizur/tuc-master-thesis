"""
Configuration management for Code Guardian evaluation framework.
"""

from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
import yaml


@dataclass
class DatasetConfig:
    """Configuration for datasets."""

    path: str
    juliet_cases: int = 100
    owasp_cases: int = 50
    node_cves: int = 10
    target_languages: List[str] = field(
        default_factory=lambda: ["javascript", "typescript"]
    )


@dataclass
class ModelConfig:
    """Configuration for LLM models."""

    name: str
    version: str
    quantization: str = "q4_0"
    temperature: float = 0.0
    max_tokens: int = 2048


@dataclass
class SASTConfig:
    """Configuration for SAST tools."""

    semgrep_enabled: bool = True
    semgrep_rules: str = "javascript,typescript"
    codeql_enabled: bool = True
    codeql_queries: str = "security-and-quality"


@dataclass
class MetricsConfig:
    """Configuration for evaluation metrics."""

    confidence_interval: float = 0.95
    bootstrap_samples: int = 1000
    significance_test: str = "mcnemar"


@dataclass
class UserStudyConfig:
    """Configuration for user studies."""

    participants: int
    tasks: int = 5
    duration_minutes: int = 60
    data_collection: List[str] = field(default_factory=list)


@dataclass
class EvaluationConfig:
    """Main configuration class for evaluation framework."""

    # General settings
    name: str = "code_guardian_evaluation"
    version: str = "1.0.0"
    timestamp: Optional[str] = None

    # Phases
    phases: Dict[str, bool] = field(default_factory=dict)

    # Datasets
    datasets: Dict[str, Any] = field(default_factory=dict)

    # Baselines
    baselines: Dict[str, Any] = field(default_factory=dict)

    # Metrics
    metrics: Dict[str, Any] = field(default_factory=dict)

    # User study
    user_study: Dict[str, Any] = field(default_factory=dict)

    # Analysis
    analysis: Dict[str, Any] = field(default_factory=dict)

    # Code Guardian specific
    code_guardian: Dict[str, Any] = field(default_factory=dict)

    # Environment
    environment: Dict[str, Any] = field(default_factory=dict)

    # Logging
    logging: Dict[str, Any] = field(default_factory=dict)

    # Reporting
    reporting: Dict[str, Any] = field(default_factory=dict)

    # Reproducibility
    reproducibility: Dict[str, Any] = field(default_factory=dict)

    # Quality assurance
    quality_assurance: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_yaml(cls, config_path: str) -> "EvaluationConfig":
        """Load configuration from YAML file."""
        with open(config_path, "r") as f:
            config_data = yaml.safe_load(f)

        # Set timestamp if not provided
        if not config_data.get("evaluation", {}).get("timestamp"):
            config_data.setdefault("evaluation", {})[
                "timestamp"
            ] = datetime.now().isoformat()

        return cls(
            name=config_data.get("evaluation", {}).get(
                "name", "code_guardian_evaluation"
            ),
            version=config_data.get("evaluation", {}).get("version", "1.0.0"),
            timestamp=config_data.get("evaluation", {}).get("timestamp"),
            phases=config_data.get("phases", {}),
            datasets=config_data.get("datasets", {}),
            baselines=config_data.get("baselines", {}),
            metrics=config_data.get("metrics", {}),
            user_study=config_data.get("user_study", {}),
            analysis=config_data.get("analysis", {}),
            code_guardian=config_data.get("code_guardian", {}),
            environment=config_data.get("environment", {}),
            logging=config_data.get("logging", {}),
            reporting=config_data.get("reporting", {}),
            reproducibility=config_data.get("reproducibility", {}),
            quality_assurance=config_data.get("quality_assurance", {}),
        )

    def to_yaml(self, output_path: str):
        """Save configuration to YAML file."""
        config_dict = {
            "evaluation": {
                "name": self.name,
                "version": self.version,
                "timestamp": self.timestamp,
            },
            "phases": self.phases,
            "datasets": self.datasets,
            "baselines": self.baselines,
            "metrics": self.metrics,
            "user_study": self.user_study,
            "analysis": self.analysis,
            "code_guardian": self.code_guardian,
            "environment": self.environment,
            "logging": self.logging,
            "reporting": self.reporting,
            "reproducibility": self.reproducibility,
            "quality_assurance": self.quality_assurance,
        }

        with open(output_path, "w") as f:
            yaml.dump(config_dict, f, default_flow_style=False, indent=2)

    def validate(self) -> List[str]:
        """Validate configuration and return list of issues."""
        issues = []

        # Check required phases
        required_phases = ["benchmark_evaluation", "repair_quality_evaluation"]
        for phase in required_phases:
            if not self.phases.get(phase):
                issues.append(f"Required phase '{phase}' is disabled")

        # Check dataset paths
        for dataset_name, dataset_config in self.datasets.items():
            if "path" in dataset_config:
                path = Path(dataset_config["path"])
                if not path.exists():
                    issues.append(f"Dataset path does not exist: {path}")

        # Check model configurations
        if "llm_only" in self.baselines:
            models = self.baselines["llm_only"].get("models", [])
            if not models:
                issues.append("No LLM models configured for baseline comparison")

        # Check user study configuration
        if self.phases.get("user_study"):
            pilot_participants = self.user_study.get("pilot", {}).get("participants", 0)
            main_participants = self.user_study.get("main", {}).get("participants", 0)

            if pilot_participants < 10:
                issues.append("Pilot study should have at least 10 participants")
            if main_participants < 30:
                issues.append("Main study should have at least 30 participants")

        return issues

    def get_model_configs(self) -> List[ModelConfig]:
        """Extract model configurations."""
        models = []

        if "llm_only" in self.baselines:
            for model_data in self.baselines["llm_only"].get("models", []):
                models.append(ModelConfig(**model_data))

        return models

    def get_dataset_config(self, dataset_name: str) -> Optional[DatasetConfig]:
        """Get configuration for specific dataset."""
        if dataset_name in self.datasets:
            return DatasetConfig(**self.datasets[dataset_name])
        return None

    def get_sast_config(self) -> SASTConfig:
        """Get SAST configuration."""
        sast_data = self.baselines.get("sast", {})

        semgrep_config = sast_data.get("tools", {}).get("semgrep", {})
        codeql_config = sast_data.get("tools", {}).get("codeql", {})

        return SASTConfig(
            semgrep_enabled=semgrep_config.get("enabled", True),
            semgrep_rules=semgrep_config.get("rules", "javascript,typescript"),
            codeql_enabled=codeql_config.get("enabled", True),
            codeql_queries=codeql_config.get("queries", "security-and-quality"),
        )

    def get_metrics_config(self) -> MetricsConfig:
        """Get metrics configuration."""
        accuracy_config = self.metrics.get("accuracy", {})

        return MetricsConfig(
            confidence_interval=accuracy_config.get("confidence_interval", 0.95),
            bootstrap_samples=accuracy_config.get("bootstrap_samples", 1000),
            significance_test=accuracy_config.get("significance_test", "mcnemar"),
        )

    def get_user_study_config(self, study_type: str) -> Optional[UserStudyConfig]:
        """Get user study configuration."""
        if study_type in self.user_study:
            study_data = self.user_study[study_type]
            return UserStudyConfig(**study_data)
        return None

    def freeze_environment(self) -> Dict[str, str]:
        """Freeze current environment for reproducibility."""
        import platform
        import sys
        import subprocess

        frozen_env = {
            "python_version": sys.version,
            "platform": platform.platform(),
            "architecture": platform.architecture()[0],
            "processor": platform.processor(),
            "timestamp": datetime.now().isoformat(),
        }

        # Get package versions
        try:
            result = subprocess.run(["pip", "freeze"], capture_output=True, text=True)
            frozen_env["pip_packages"] = result.stdout
        except Exception:
            frozen_env["pip_packages"] = "Unable to capture pip packages"

        # Get Node.js version
        try:
            result = subprocess.run(
                ["node", "--version"], capture_output=True, text=True
            )
            frozen_env["nodejs_version"] = result.stdout.strip()
        except Exception:
            frozen_env["nodejs_version"] = "Node.js not available"

        # Get npm packages
        try:
            result = subprocess.run(
                ["npm", "list", "-g", "--depth=0"], capture_output=True, text=True
            )
            frozen_env["npm_packages"] = result.stdout
        except Exception:
            frozen_env["npm_packages"] = "Unable to capture npm packages"

        return frozen_env
