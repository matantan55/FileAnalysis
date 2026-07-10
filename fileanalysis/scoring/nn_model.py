"""Neural network threat scoring model (ThreatNet) and inference wrapper."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

import numpy as np

if TYPE_CHECKING:
    from fileanalysis.analyzers.base import AnalysisResult

from fileanalysis.analyzers.base import RiskLevel
from fileanalysis.scoring.features import NUM_FEATURES, FeatureExtractor

logger = logging.getLogger(__name__)

# Default model weights path (alongside this file)
DEFAULT_MODEL_PATH = Path(__file__).parent / "threat_model.pt"


def _import_torch():
    """Lazily import torch, raising a clear message if unavailable."""
    try:
        import torch
        return torch
    except ImportError:
        raise ImportError(
            "PyTorch is required for neural network scoring. "
            "Install it with: pip install torch>=2.0"
        )


def _build_model(torch_module):
    """Construct the ThreatNet model architecture.

    Architecture: 31 → 64 → 32 → 16 → 1 with ReLU, Dropout, and Sigmoid output.
    """
    torch = torch_module
    nn = torch.nn

    class ThreatNet(nn.Module):
        """Multi-layer perceptron for malware threat scoring.

        Input:  31-dimensional feature vector from FeatureExtractor
        Output: Single scalar in [0, 1] representing threat probability
        """

        def __init__(self) -> None:
            super().__init__()
            self.network = nn.Sequential(
                nn.Linear(NUM_FEATURES, 64),
                nn.ReLU(),
                nn.Dropout(0.3),
                nn.Linear(64, 32),
                nn.ReLU(),
                nn.Dropout(0.3),
                nn.Linear(32, 16),
                nn.ReLU(),
                nn.Linear(16, 1),
                nn.Sigmoid(),
            )

        def forward(self, x: torch.Tensor) -> torch.Tensor:
            return self.network(x)

    return ThreatNet


class NNThreatScorer:
    """Neural network-based threat scorer.

    Loads a pre-trained ThreatNet model and uses it to score files.
    Falls back to a clear error if PyTorch is unavailable or weights are missing.
    """

    def __init__(self, model_path: str | Path | None = None) -> None:
        self.torch = _import_torch()
        self.model_path = Path(model_path) if model_path else DEFAULT_MODEL_PATH
        self.extractor = FeatureExtractor()
        self.model = self._load_model()

    def _load_model(self):
        """Load the ThreatNet model with pre-trained weights."""
        ThreatNet = _build_model(self.torch)
        model = ThreatNet()

        if not self.model_path.exists():
            raise FileNotFoundError(
                f"Model weights not found at {self.model_path}. "
                f"Run 'python -m fileanalysis.scoring.train' to generate them."
            )

        state_dict = self.torch.load(
            self.model_path,
            map_location=self.torch.device("cpu"),
            weights_only=True,
        )
        model.load_state_dict(state_dict)
        model.eval()
        logger.info("Loaded ThreatNet model from %s", self.model_path)
        return model

    def calculate_score(self, result: AnalysisResult) -> None:
        """Run NN inference on the AnalysisResult and set score/level.

        This method has the same signature as ThreatScorer.calculate_score
        so they are interchangeable in the CLI pipeline.
        """
        # Extract features
        features = self.extractor.extract(result)
        tensor = self.torch.tensor(features, dtype=self.torch.float32).unsqueeze(0)

        # Inference (no gradient tracking needed)
        with self.torch.no_grad():
            raw_output = self.model(tensor)

        # Convert sigmoid output [0, 1] → score [0, 100]
        confidence = raw_output.item()
        final_score = round(confidence * 100.0, 1)
        final_score = max(0.0, min(100.0, final_score))

        result.risk_score = final_score
        result.nn_confidence = round(confidence, 4)
        result.scoring_method = "neural_network"

        # Determine risk level (same thresholds as heuristic)
        if final_score <= 20.0:
            result.risk_level = RiskLevel.CLEAN
        elif final_score <= 40.0:
            result.risk_level = RiskLevel.LOW
        elif final_score <= 60.0:
            result.risk_level = RiskLevel.MODERATE
        elif final_score <= 80.0:
            result.risk_level = RiskLevel.HIGH
        else:
            result.risk_level = RiskLevel.CRITICAL
