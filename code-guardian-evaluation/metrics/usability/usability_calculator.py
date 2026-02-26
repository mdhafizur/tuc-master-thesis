#!/usr/bin/env python3
"""
Usability Metrics Calculator for Code Guardian VS Code Extension

This module evaluates the usability and user experience aspects of Code Guardian:
- User interface responsiveness
- Workflow integration effectiveness
- Learning curve and adoption metrics
- User satisfaction and perceived utility

Academic Standards:
- Human-Computer Interaction (HCI) evaluation
- User experience (UX) metrics
- Workflow efficiency measurement
- Cognitive load assessment
"""

import json
import logging
import statistics
import numpy as np
import pandas as pd
from scipy import stats
from scipy.stats import mannwhitneyu, wilcoxon, kruskal
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from pathlib import Path
from enum import Enum

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class InteractionType(Enum):
    """Types of user interactions with the extension"""

    VULNERABILITY_SCAN = "vulnerability_scan"
    QUICK_FIX_APPLY = "quick_fix_apply"
    MANUAL_REVIEW = "manual_review"
    SETTINGS_CONFIG = "settings_config"
    EXPLANATION_VIEW = "explanation_view"
    BULK_OPERATIONS = "bulk_operations"
    INTEGRATION_SETUP = "integration_setup"


class UserExperienceLevel(Enum):
    """User experience levels"""

    BEGINNER = "beginner"
    INTERMEDIATE = "intermediate"
    EXPERT = "expert"


class TaskComplexity(Enum):
    """Complexity levels of tasks"""

    SIMPLE = "simple"
    MODERATE = "moderate"
    COMPLEX = "complex"


@dataclass
class UserInteraction:
    """Individual user interaction with the extension"""

    session_id: str
    user_id: str
    interaction_type: InteractionType
    task_complexity: TaskComplexity
    user_experience_level: UserExperienceLevel

    # Timing metrics
    task_start_time: float
    task_completion_time: float
    time_to_first_action_ms: Optional[float] = None

    # Success metrics
    task_completed: bool = False
    errors_encountered: int = 0
    help_requests: int = 0

    # User behavior
    clicks_required: int = 0
    keystrokes_required: int = 0
    context_switches: int = 0  # Between VS Code and other apps

    # Satisfaction metrics (1-5 scale)
    ease_of_use_rating: Optional[int] = None
    usefulness_rating: Optional[int] = None
    satisfaction_rating: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "session_id": self.session_id,
            "user_id": self.user_id,
            "interaction_type": self.interaction_type.value,
            "task_complexity": self.task_complexity.value,
            "user_experience_level": self.user_experience_level.value,
            "task_start_time": self.task_start_time,
            "task_completion_time": self.task_completion_time,
            "time_to_first_action_ms": self.time_to_first_action_ms,
            "task_completed": self.task_completed,
            "errors_encountered": self.errors_encountered,
            "help_requests": self.help_requests,
            "clicks_required": self.clicks_required,
            "keystrokes_required": self.keystrokes_required,
            "context_switches": self.context_switches,
            "ease_of_use_rating": self.ease_of_use_rating,
            "usefulness_rating": self.usefulness_rating,
            "satisfaction_rating": self.satisfaction_rating,
        }


@dataclass
class LearningCurveData:
    """Learning curve measurement data"""

    user_id: str
    session_number: int
    task_type: InteractionType

    # Performance progression
    completion_time_minutes: float
    success_rate: float
    error_rate: float
    efficiency_score: float  # Tasks completed per minute

    # Knowledge progression
    help_dependency: float  # 0-1 scale, lower is better
    feature_discovery_rate: float  # New features used
    automation_adoption: float  # Use of advanced features

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "user_id": self.user_id,
            "session_number": self.session_number,
            "task_type": self.task_type.value,
            "completion_time_minutes": self.completion_time_minutes,
            "success_rate": self.success_rate,
            "error_rate": self.error_rate,
            "efficiency_score": self.efficiency_score,
            "help_dependency": self.help_dependency,
            "feature_discovery_rate": self.feature_discovery_rate,
            "automation_adoption": self.automation_adoption,
        }


@dataclass
class UsabilityMetrics:
    """Comprehensive usability metrics"""

    n_interactions: int
    n_users: int
    n_sessions: int

    # Task completion metrics
    overall_success_rate: float
    avg_completion_time_minutes: float
    median_completion_time_minutes: float

    # Efficiency metrics
    avg_clicks_per_task: float
    avg_keystrokes_per_task: float
    avg_context_switches: float

    # Error and help metrics
    avg_errors_per_task: float
    help_request_rate: float
    time_to_first_action_ms: float

    # User satisfaction
    avg_ease_of_use: float
    avg_usefulness: float
    avg_satisfaction: float

    # Learning curve metrics
    learning_efficiency: float  # Improvement rate over sessions
    feature_adoption_rate: float
    expert_user_percentage: float

    # Segmented analysis
    by_experience_level: Dict[str, Dict[str, float]]
    by_task_complexity: Dict[str, Dict[str, float]]
    by_interaction_type: Dict[str, Dict[str, float]]

    # Optional metrics
    net_promoter_score: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "overview": {
                "n_interactions": self.n_interactions,
                "n_users": self.n_users,
                "n_sessions": self.n_sessions,
            },
            "task_completion": {
                "overall_success_rate": self.overall_success_rate,
                "avg_completion_time_minutes": self.avg_completion_time_minutes,
                "median_completion_time_minutes": self.median_completion_time_minutes,
            },
            "efficiency_metrics": {
                "avg_clicks_per_task": self.avg_clicks_per_task,
                "avg_keystrokes_per_task": self.avg_keystrokes_per_task,
                "avg_context_switches": self.avg_context_switches,
            },
            "error_and_help": {
                "avg_errors_per_task": self.avg_errors_per_task,
                "help_request_rate": self.help_request_rate,
                "time_to_first_action_ms": self.time_to_first_action_ms,
            },
            "user_satisfaction": {
                "avg_ease_of_use": self.avg_ease_of_use,
                "avg_usefulness": self.avg_usefulness,
                "avg_satisfaction": self.avg_satisfaction,
                "net_promoter_score": self.net_promoter_score,
            },
            "learning_curve": {
                "learning_efficiency": self.learning_efficiency,
                "feature_adoption_rate": self.feature_adoption_rate,
                "expert_user_percentage": self.expert_user_percentage,
            },
            "segmented_analysis": {
                "by_experience_level": self.by_experience_level,
                "by_task_complexity": self.by_task_complexity,
                "by_interaction_type": self.by_interaction_type,
            },
        }


class UsabilityCalculator:
    """
    Main class for calculating usability metrics

    Features:
    - Task completion and efficiency analysis
    - User satisfaction measurement
    - Learning curve assessment
    - Workflow integration evaluation
    - Cognitive load analysis
    """

    def __init__(
        self,
        target_completion_time_minutes: float = 5.0,
        max_acceptable_errors: int = 2,
        efficiency_threshold: float = 0.8,
    ):
        """
        Initialize usability calculator

        Args:
            target_completion_time_minutes: Target time for task completion
            max_acceptable_errors: Maximum acceptable errors per task
            efficiency_threshold: Minimum efficiency score for good usability
        """
        self.target_completion_time = target_completion_time_minutes
        self.max_acceptable_errors = max_acceptable_errors
        self.efficiency_threshold = efficiency_threshold
        logger.info(
            "Initialized UsabilityCalculator with target time: %.1f min",
            target_completion_time_minutes,
        )

    def calculate_metrics(
        self,
        interactions: List[UserInteraction],
        learning_data: Optional[List[LearningCurveData]] = None,
    ) -> UsabilityMetrics:
        """
        Calculate comprehensive usability metrics using pandas and numpy

        Args:
            interactions: List of user interactions
            learning_data: Optional learning curve data

        Returns:
            UsabilityMetrics object with all computed metrics
        """
        logger.info(
            "Calculating usability metrics for %d interactions", len(interactions)
        )

        if not interactions:
            raise ValueError("User interactions are required")

        # Create DataFrame for analysis
        interactions_df = pd.DataFrame([i.to_dict() for i in interactions])

        # Basic statistics
        n_interactions = len(interactions_df)
        n_users = len(interactions_df["user_id"].unique())
        n_sessions = len(interactions_df["session_id"].unique())

        # Task completion metrics using pandas
        success_rate = float(interactions_df["task_completed"].mean())

        # Calculate completion times for successful tasks
        completed_tasks = interactions_df[interactions_df["task_completed"] == True]
        if not completed_tasks.empty:
            completion_times = (
                completed_tasks["task_completion_time"]
                - completed_tasks["task_start_time"]
            ) / 60
            avg_completion_time = float(completion_times.mean())
            median_completion_time = float(completion_times.median())
        else:
            avg_completion_time = 0.0
            median_completion_time = 0.0

        # Efficiency metrics using pandas
        avg_clicks = float(interactions_df["clicks_required"].mean())
        avg_keystrokes = float(interactions_df["keystrokes_required"].mean())
        avg_context_switches = float(interactions_df["context_switches"].mean())

        # Error and help metrics
        avg_errors = float(interactions_df["errors_encountered"].mean())
        help_request_rate = float(
            interactions_df["help_requests"].sum() / n_interactions
        )

        # Time to first action using pandas
        first_action_times = interactions_df["time_to_first_action_ms"].dropna()
        avg_first_action_time = (
            float(first_action_times.mean()) if not first_action_times.empty else 0.0
        )

        # User satisfaction using pandas-based calculations
        satisfaction_scores = self._calculate_satisfaction_scores_pandas(
            interactions_df
        )

        # Learning curve metrics
        learning_metrics = self._calculate_learning_metrics_pandas(
            interactions_df, learning_data
        )

        # Segmented analysis using pandas groupby
        segmented_analysis = self._calculate_segmented_analysis_pandas(interactions_df)

        usability_metrics = UsabilityMetrics(
            n_interactions=n_interactions,
            n_users=n_users,
            n_sessions=n_sessions,
            overall_success_rate=success_rate,
            avg_completion_time_minutes=avg_completion_time,
            median_completion_time_minutes=median_completion_time,
            avg_clicks_per_task=avg_clicks,
            avg_keystrokes_per_task=avg_keystrokes,
            avg_context_switches=avg_context_switches,
            avg_errors_per_task=avg_errors,
            help_request_rate=help_request_rate,
            time_to_first_action_ms=avg_first_action_time,
            avg_ease_of_use=satisfaction_scores["ease_of_use"],
            avg_usefulness=satisfaction_scores["usefulness"],
            avg_satisfaction=satisfaction_scores["satisfaction"],
            net_promoter_score=satisfaction_scores["nps"],
            learning_efficiency=learning_metrics["efficiency"],
            feature_adoption_rate=learning_metrics["adoption_rate"],
            expert_user_percentage=learning_metrics["expert_percentage"],
            by_experience_level=segmented_analysis["by_experience"],
            by_task_complexity=segmented_analysis["by_complexity"],
            by_interaction_type=segmented_analysis["by_interaction_type"],
        )

        logger.info(
            "Calculated usability metrics: success=%.1f%%, satisfaction=%.1f, efficiency=%.2f",
            success_rate * 100,
            satisfaction_scores["satisfaction"],
            learning_metrics["efficiency"],
        )

        return usability_metrics

    def assess_workflow_integration(
        self, interactions: List[UserInteraction]
    ) -> Dict[str, Any]:
        """
        Assess how well the extension integrates into user workflows

        Args:
            interactions: User interaction data

        Returns:
            Dictionary with workflow integration analysis
        """
        logger.info(
            "Assessing workflow integration for %d interactions", len(interactions)
        )

        # Context switching analysis
        context_switches = [i.context_switches for i in interactions]
        avg_context_switches = statistics.mean(context_switches)
        high_context_switch_rate = sum(1 for cs in context_switches if cs > 3) / len(
            context_switches
        )

        # Task flow efficiency
        quick_tasks = [
            i
            for i in interactions
            if (i.task_completion_time - i.task_start_time) / 60 < 2.0
        ]
        quick_task_rate = len(quick_tasks) / len(interactions)

        # Integration with VS Code features
        bulk_operations = [
            i
            for i in interactions
            if i.interaction_type == InteractionType.BULK_OPERATIONS
        ]
        bulk_usage_rate = len(bulk_operations) / len(interactions)

        # Feature discovery and adoption
        feature_types = [i.interaction_type for i in interactions]
        unique_features_used = len(set(feature_types))
        feature_diversity = unique_features_used / len(InteractionType)

        return {
            "context_switching": {
                "avg_context_switches": avg_context_switches,
                "high_context_switch_rate": high_context_switch_rate,
                "workflow_disruption_score": min(avg_context_switches / 5.0, 1.0),
            },
            "task_flow_efficiency": {
                "quick_task_rate": quick_task_rate,
                "avg_completion_time_minutes": statistics.mean(
                    [
                        (i.task_completion_time - i.task_start_time) / 60
                        for i in interactions
                    ]
                ),
            },
            "feature_adoption": {
                "bulk_usage_rate": bulk_usage_rate,
                "feature_diversity": feature_diversity,
                "unique_features_used": unique_features_used,
            },
        }

    def calculate_cognitive_load(
        self, interactions: List[UserInteraction]
    ) -> Dict[str, float]:
        """
        Calculate cognitive load indicators from user behavior

        Args:
            interactions: User interaction data

        Returns:
            Dictionary with cognitive load metrics
        """
        logger.info("Calculating cognitive load for %d interactions", len(interactions))

        # Mental effort indicators
        avg_errors = statistics.mean([i.errors_encountered for i in interactions])
        avg_help_requests = statistics.mean([i.help_requests for i in interactions])

        # Decision complexity indicators
        avg_clicks = statistics.mean([i.clicks_required for i in interactions])
        avg_keystrokes = statistics.mean([i.keystrokes_required for i in interactions])

        # Time pressure indicators
        first_action_times = [
            i.time_to_first_action_ms
            for i in interactions
            if i.time_to_first_action_ms is not None
        ]
        avg_hesitation_time = (
            statistics.mean(first_action_times) if first_action_times else 0.0
        )

        # Composite cognitive load score (0-1, lower is better)
        error_load = min(avg_errors / 5.0, 1.0)  # Normalize to 0-1
        help_load = min(avg_help_requests / 3.0, 1.0)
        interaction_load = min((avg_clicks + avg_keystrokes / 10) / 20.0, 1.0)
        hesitation_load = min(avg_hesitation_time / 5000.0, 1.0)  # 5 seconds max

        cognitive_load_score = (
            error_load + help_load + interaction_load + hesitation_load
        ) / 4.0

        return {
            "cognitive_load_score": cognitive_load_score,
            "error_load": error_load,
            "help_load": help_load,
            "interaction_load": interaction_load,
            "hesitation_load": hesitation_load,
            "avg_hesitation_time_ms": avg_hesitation_time,
        }

    def analyze_user_journey(
        self, interactions: List[UserInteraction]
    ) -> Dict[str, Any]:
        """
        Analyze the user journey and identify pain points

        Args:
            interactions: User interaction data sorted by time

        Returns:
            Dictionary with user journey analysis
        """
        logger.info("Analyzing user journey for %d interactions", len(interactions))

        # Group by user and session
        user_sessions = {}
        for interaction in interactions:
            key = f"{interaction.user_id}_{interaction.session_id}"
            if key not in user_sessions:
                user_sessions[key] = []
            user_sessions[key].append(interaction)

        # Analyze journey patterns
        session_lengths = [len(session) for session in user_sessions.values()]
        avg_session_length = statistics.mean(session_lengths)

        # Drop-off analysis
        incomplete_sessions = [
            session
            for session in user_sessions.values()
            if not session[-1].task_completed
        ]
        drop_off_rate = len(incomplete_sessions) / len(user_sessions)

        # Common failure points
        error_points = {}
        for session in user_sessions.values():
            for i, interaction in enumerate(session):
                if interaction.errors_encountered > 0:
                    step = f"step_{i}"
                    error_points[step] = error_points.get(step, 0) + 1

        # Success patterns
        successful_sessions = [
            session for session in user_sessions.values() if session[-1].task_completed
        ]
        avg_successful_session_time = 0.0
        if successful_sessions:
            successful_times = [
                (session[-1].task_completion_time - session[0].task_start_time) / 60
                for session in successful_sessions
            ]
            avg_successful_session_time = statistics.mean(successful_times)

        return {
            "session_metrics": {
                "avg_session_length": avg_session_length,
                "drop_off_rate": drop_off_rate,
                "avg_successful_session_time_minutes": avg_successful_session_time,
            },
            "failure_analysis": {
                "error_points": error_points,
                "most_common_failure_step": (
                    max(error_points.items(), key=lambda x: x[1])[0]
                    if error_points
                    else None
                ),
            },
            "success_patterns": {
                "successful_session_rate": len(successful_sessions)
                / len(user_sessions),
                "avg_success_time_minutes": avg_successful_session_time,
            },
        }

    def _calculate_satisfaction_scores_pandas(
        self, df: pd.DataFrame
    ) -> Dict[str, float]:
        """Calculate user satisfaction scores using pandas"""
        # Filter interactions with satisfaction ratings
        rated_df = df[
            df["satisfaction_rating"].notna() & (df["satisfaction_rating"] > 0)
        ]

        if rated_df.empty:
            return {
                "avg_satisfaction": 0.0,
                "satisfaction_std": 0.0,
                "high_satisfaction_rate": 0.0,
                "satisfaction_distribution": {},
            }

        avg_satisfaction = float(rated_df["satisfaction_rating"].mean())
        satisfaction_std = (
            float(rated_df["satisfaction_rating"].std()) if len(rated_df) > 1 else 0.0
        )
        high_satisfaction_rate = float((rated_df["satisfaction_rating"] >= 4).mean())

        # Satisfaction distribution
        satisfaction_dist = (
            rated_df["satisfaction_rating"]
            .value_counts(normalize=True)
            .round(3)
            .to_dict()
        )

        return {
            "avg_satisfaction": avg_satisfaction,
            "satisfaction_std": satisfaction_std,
            "high_satisfaction_rate": high_satisfaction_rate,
            "satisfaction_distribution": satisfaction_dist,
        }

    def _calculate_learning_metrics_pandas(
        self, df: pd.DataFrame, learning_data: Optional[List[LearningCurveData]] = None
    ) -> Dict[str, float]:
        """Calculate learning curve metrics using pandas"""
        if learning_data is None:
            return {"learning_slope": 0.0, "proficiency_threshold_sessions": 0}

        learning_df = pd.DataFrame([ld.to_dict() for ld in learning_data])

        if learning_df.empty:
            return {"learning_slope": 0.0, "proficiency_threshold_sessions": 0}

        # Calculate learning slope using linear regression
        if len(learning_df) > 1:
            # Use scipy for linear regression
            from scipy.stats import linregress

            slope, intercept, r_value, p_value, std_err = linregress(
                learning_df["session_number"], learning_df["competency_score"]
            )
            learning_slope = float(slope)
        else:
            learning_slope = 0.0

        # Find sessions to reach proficiency threshold
        proficient_sessions = learning_df[
            learning_df["competency_score"] >= self.proficiency_threshold
        ]
        proficiency_threshold_sessions = (
            int(proficient_sessions["session_number"].min())
            if not proficient_sessions.empty
            else 0
        )

        return {
            "learning_slope": learning_slope,
            "proficiency_threshold_sessions": proficiency_threshold_sessions,
        }

    def _calculate_segmented_analysis_pandas(
        self, df: pd.DataFrame
    ) -> Dict[str, Dict[str, float]]:
        """Calculate segmented analysis using pandas groupby operations"""
        segmented_analysis = {}

        # By experience level
        if "experience_level" in df.columns:
            exp_stats = (
                df.groupby("experience_level")
                .agg(
                    {
                        "task_completed": "mean",
                        "clicks_required": "mean",
                        "errors_encountered": "mean",
                        "satisfaction_rating": "mean",
                    }
                )
                .round(3)
            )
            segmented_analysis["by_experience"] = exp_stats.to_dict("index")

        # By interaction type
        if "interaction_type" in df.columns:
            int_stats = (
                df.groupby("interaction_type")
                .agg(
                    {
                        "task_completed": "mean",
                        "time_to_first_action_ms": "mean",
                        "errors_encountered": "mean",
                    }
                )
                .round(3)
            )
            segmented_analysis["by_interaction_type"] = int_stats.to_dict("index")

        # By task complexity
        if "task_complexity" in df.columns:
            comp_stats = (
                df.groupby("task_complexity")
                .agg(
                    {
                        "task_completed": "mean",
                        "clicks_required": "mean",
                        "context_switches": "mean",
                        "help_requests": "mean",
                    }
                )
                .round(3)
            )
            segmented_analysis["by_complexity"] = comp_stats.to_dict("index")

        return segmented_analysis

    def _calculate_satisfaction_scores(
        self, interactions: List[UserInteraction]
    ) -> Dict[str, float]:
        """Calculate user satisfaction scores"""
        rated_interactions = [
            i
            for i in interactions
            if all(
                [
                    i.ease_of_use_rating is not None,
                    i.usefulness_rating is not None,
                    i.satisfaction_rating is not None,
                ]
            )
        ]

        if not rated_interactions:
            return {
                "ease_of_use": 0.0,
                "usefulness": 0.0,
                "satisfaction": 0.0,
                "nps": None,
            }

        ease_of_use = statistics.mean(
            [i.ease_of_use_rating for i in rated_interactions]
        )
        usefulness = statistics.mean([i.usefulness_rating for i in rated_interactions])
        satisfaction = statistics.mean(
            [i.satisfaction_rating for i in rated_interactions]
        )

        # Calculate Net Promoter Score (simplified)
        # Assuming satisfaction 4-5 are promoters, 3 is neutral, 1-2 are detractors
        promoters = sum(1 for i in rated_interactions if i.satisfaction_rating >= 4)
        detractors = sum(1 for i in rated_interactions if i.satisfaction_rating <= 2)
        nps = (promoters - detractors) / len(rated_interactions) * 100

        return {
            "ease_of_use": ease_of_use,
            "usefulness": usefulness,
            "satisfaction": satisfaction,
            "nps": nps,
        }

    def _calculate_learning_metrics(
        self,
        interactions: List[UserInteraction],
        learning_data: Optional[List[LearningCurveData]],
    ) -> Dict[str, float]:
        """Calculate learning curve metrics"""
        # Experience level distribution
        experience_counts = {}
        for interaction in interactions:
            level = interaction.user_experience_level.value
            experience_counts[level] = experience_counts.get(level, 0) + 1

        total_interactions = len(interactions)
        expert_percentage = experience_counts.get("expert", 0) / total_interactions

        # Simple learning efficiency based on error reduction over time
        user_sessions = {}
        for interaction in interactions:
            if interaction.user_id not in user_sessions:
                user_sessions[interaction.user_id] = []
            user_sessions[interaction.user_id].append(interaction)

        learning_improvements = []
        for _, user_interactions in user_sessions.items():
            if len(user_interactions) >= 2:
                # Sort by start time
                sorted_interactions = sorted(
                    user_interactions, key=lambda x: x.task_start_time
                )
                first_errors = statistics.mean(
                    [
                        i.errors_encountered
                        for i in sorted_interactions[: len(sorted_interactions) // 2]
                    ]
                )
                last_errors = statistics.mean(
                    [
                        i.errors_encountered
                        for i in sorted_interactions[len(sorted_interactions) // 2 :]
                    ]
                )

                if first_errors > 0:
                    improvement = (first_errors - last_errors) / first_errors
                    learning_improvements.append(max(improvement, 0))

        learning_efficiency = (
            statistics.mean(learning_improvements) if learning_improvements else 0.0
        )

        # Feature adoption rate (users trying multiple interaction types)
        user_feature_usage = {}
        for interaction in interactions:
            if interaction.user_id not in user_feature_usage:
                user_feature_usage[interaction.user_id] = set()
            user_feature_usage[interaction.user_id].add(interaction.interaction_type)

        avg_features_per_user = statistics.mean(
            [len(features) for features in user_feature_usage.values()]
        )
        feature_adoption_rate = avg_features_per_user / len(InteractionType)

        return {
            "efficiency": learning_efficiency,
            "adoption_rate": feature_adoption_rate,
            "expert_percentage": expert_percentage,
        }

    def _calculate_segmented_analysis(
        self, interactions: List[UserInteraction]
    ) -> Dict[str, Dict[str, Dict[str, float]]]:
        """Calculate metrics segmented by different dimensions"""

        # By experience level
        by_experience = {}
        for level in UserExperienceLevel:
            level_interactions = [
                i for i in interactions if i.user_experience_level == level
            ]
            if level_interactions:
                by_experience[level.value] = {
                    "success_rate": sum(
                        1 for i in level_interactions if i.task_completed
                    )
                    / len(level_interactions),
                    "avg_completion_time": statistics.mean(
                        [
                            (i.task_completion_time - i.task_start_time) / 60
                            for i in level_interactions
                            if i.task_completed
                        ]
                    ),
                    "avg_errors": statistics.mean(
                        [i.errors_encountered for i in level_interactions]
                    ),
                }

        # By task complexity
        by_complexity = {}
        for complexity in TaskComplexity:
            complexity_interactions = [
                i for i in interactions if i.task_complexity == complexity
            ]
            if complexity_interactions:
                by_complexity[complexity.value] = {
                    "success_rate": sum(
                        1 for i in complexity_interactions if i.task_completed
                    )
                    / len(complexity_interactions),
                    "avg_completion_time": statistics.mean(
                        [
                            (i.task_completion_time - i.task_start_time) / 60
                            for i in complexity_interactions
                            if i.task_completed
                        ]
                    ),
                    "avg_errors": statistics.mean(
                        [i.errors_encountered for i in complexity_interactions]
                    ),
                }

        # By interaction type
        by_interaction_type = {}
        for interaction_type in InteractionType:
            type_interactions = [
                i for i in interactions if i.interaction_type == interaction_type
            ]
            if type_interactions:
                by_interaction_type[interaction_type.value] = {
                    "success_rate": sum(
                        1 for i in type_interactions if i.task_completed
                    )
                    / len(type_interactions),
                    "avg_completion_time": statistics.mean(
                        [
                            (i.task_completion_time - i.task_start_time) / 60
                            for i in type_interactions
                            if i.task_completed
                        ]
                    ),
                    "avg_errors": statistics.mean(
                        [i.errors_encountered for i in type_interactions]
                    ),
                }

        return {
            "by_experience": by_experience,
            "by_complexity": by_complexity,
            "by_interaction_type": by_interaction_type,
        }

    def generate_report(
        self,
        interactions: List[UserInteraction],
        learning_data: Optional[List[LearningCurveData]] = None,
        output_path: Optional[Path] = None,
    ) -> Dict[str, Any]:
        """
        Generate comprehensive usability report

        Args:
            interactions: User interaction data
            learning_data: Optional learning curve data
            output_path: Optional path to save report

        Returns:
            Dictionary with complete analysis
        """
        logger.info(
            "Generating usability report for %d interactions", len(interactions)
        )

        # Calculate main metrics
        usability_metrics = self.calculate_metrics(interactions, learning_data)

        # Additional analysis
        workflow_integration = self.assess_workflow_integration(interactions)
        cognitive_load = self.calculate_cognitive_load(interactions)
        user_journey = self.analyze_user_journey(interactions)

        report_data = {
            "timestamp": json.dumps(None),  # Would use datetime in real implementation
            "summary": {
                "total_interactions": len(interactions),
                "unique_users": len(set(i.user_id for i in interactions)),
                "unique_sessions": len(set(i.session_id for i in interactions)),
                "interaction_types": list(
                    set(i.interaction_type.value for i in interactions)
                ),
            },
            "usability_metrics": usability_metrics.to_dict(),
            "workflow_integration": workflow_integration,
            "cognitive_load_analysis": cognitive_load,
            "user_journey_analysis": user_journey,
            "configuration": {
                "target_completion_time_minutes": self.target_completion_time,
                "max_acceptable_errors": self.max_acceptable_errors,
                "efficiency_threshold": self.efficiency_threshold,
            },
        }

        # Save report if path provided
        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(report_data, f, indent=2)
            logger.info("Saved usability report to %s", output_path)

        return report_data


if __name__ == "__main__":
    # Example usage
    calculator = UsabilityCalculator(
        target_completion_time_minutes=3.0, max_acceptable_errors=1
    )

    # Example interactions
    example_interactions = [
        UserInteraction(
            "session_1",
            "user_1",
            InteractionType.VULNERABILITY_SCAN,
            TaskComplexity.SIMPLE,
            UserExperienceLevel.INTERMEDIATE,
            0.0,
            180.0,
            500.0,
            True,
            0,
            0,
            3,
            15,
            1,
            4,
            5,
            4,
        ),
        UserInteraction(
            "session_1",
            "user_1",
            InteractionType.QUICK_FIX_APPLY,
            TaskComplexity.MODERATE,
            UserExperienceLevel.INTERMEDIATE,
            180.0,
            300.0,
            200.0,
            True,
            1,
            0,
            2,
            8,
            0,
            3,
            4,
            4,
        ),
    ]

    # Calculate metrics
    example_usability_metrics = calculator.calculate_metrics(example_interactions)
    print(f"Overall Success Rate: {example_usability_metrics.overall_success_rate:.1%}")
    print(f"Average Satisfaction: {example_usability_metrics.avg_satisfaction:.1f}/5")
    print(
        f"Average Completion Time: {example_usability_metrics.avg_completion_time_minutes:.1f} minutes"
    )

    # Generate report
    report = calculator.generate_report(example_interactions)
    print(
        f"Generated usability report for {report['summary']['total_interactions']} interactions"
    )
