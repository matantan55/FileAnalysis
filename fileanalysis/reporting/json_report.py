"""Serializes analysis results to JSON format."""

from __future__ import annotations

import json
from dataclasses import asdict

from fileanalysis.analyzers.base import AnalysisResult


class JsonReporter:
    """Exports analysis results to standard JSON structure."""

    def render(self, result: AnalysisResult) -> str:
        """Serialize AnalysisResult dataclass to JSON string."""
        data = asdict(result)

        # Convert enum types to their string values in the JSON output
        data["risk_level"] = result.risk_level.value
        data["nn_risk_level"] = result.nn_risk_level.value
        data["nn_score"] = result.nn_score
        data["nn_confidence"] = result.nn_confidence
        data["ml_risk_level"] = result.ml_risk_level.value
        data["ml_score"] = result.ml_score
        data["ml_confidence"] = result.ml_confidence
        data["ensemble_risk_level"] = result.ensemble_risk_level.value
        data["ensemble_score"] = result.ensemble_score
        data["scoring_method"] = result.scoring_method

        # Convert ThreatCategory keys/values inside indicators and capabilities
        for indicator in data["indicators"]:
            indicator["category"] = indicator["category"].value

        for capability in data["capabilities"]:
            capability["category"] = capability["category"].value

        return json.dumps(data, indent=2)
