"""Neural network threat scoring model (ThreatNet) and inference wrapper."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING
import numpy as np
import torch
import torch.nn as nn

if TYPE_CHECKING:
    from fileanalysis.analyzers.base import AnalysisResult

from fileanalysis.analyzers.base import RiskLevel
from fileanalysis.scoring.features import NUM_FEATURES, FeatureExtractor

logger = logging.getLogger(__name__)

# Default model weights path (alongside this file)
DEFAULT_MODEL_PATH = Path(__file__).parent / "threat_model.pt"
DEFAULT_SCALER_PATH = Path(__file__).parent / "feature_scaler.npz"


class ThreatNet(nn.Module):
    """Multi-layer perceptron for malware threat scoring.

    Input:  30-dimensional feature vector from FeatureExtractor
    Output: Single scalar in [0, 1] representing threat probability
    """

    def __init__(self) -> None:
        super().__init__()
        self.network = nn.Sequential(
            nn.Linear(NUM_FEATURES, 128),
            nn.BatchNorm1d(128),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(128, 64),
            nn.BatchNorm1d(64),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(64, 32),
            nn.BatchNorm1d(32),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(32, 16),
            nn.ReLU(),
            nn.Linear(16, 1),
            nn.Sigmoid(),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.network(x)


class NNThreatScorer:
    """Neural network-based threat scorer.

    Loads a pre-trained ThreatNet model and uses it to score files.
    Falls back to a clear error if PyTorch is unavailable or weights are missing.
    """

    def __init__(self, model_path: str | Path | None = None) -> None:
        self.torch = torch
        self.model_path = Path(model_path) if model_path else DEFAULT_MODEL_PATH
        self.scaler_path = self.model_path.parent / "feature_scaler.npz"
        self.extractor = FeatureExtractor()
        self.feat_mean, self.feat_std = self._load_scaler()
        self.model = self._load_model()

    def _load_scaler(self):
        """Load saved feature normalization parameters."""
        if self.scaler_path.exists():
            data = np.load(self.scaler_path)
            logger.info("Loaded feature scaler from %s", self.scaler_path)
            return data["mean"], data["std"]
        else:
            logger.warning("No feature scaler found at %s, using raw features", self.scaler_path)
            return np.zeros(NUM_FEATURES, dtype=np.float32), np.ones(NUM_FEATURES, dtype=np.float32)

    def _load_model(self):
        """Load the ThreatNet model with pre-trained weights."""
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
        """Run NN inference on the AnalysisResult and set nn_score/nn_risk_level.

        This writes to the nn_* fields on AnalysisResult so it can coexist
        with the heuristic scorer's risk_score/risk_level fields.
        """
        # Extract and normalize features
        features = self.extractor.extract(result)
        features = (features - self.feat_mean) / (self.feat_std + 1e-8)
        tensor = self.torch.tensor(features, dtype=self.torch.float32).unsqueeze(0)

        # Inference (no gradient tracking needed)
        with self.torch.no_grad():
            raw_output = self.model(tensor)

        # Convert sigmoid output [0, 1] → score [0, 100]
        confidence = raw_output.item()
        final_score = round(confidence * 100.0, 1)
        final_score = max(0.0, min(100.0, final_score))

        result.nn_score = final_score
        result.nn_confidence = round(confidence, 4)

        # Determine risk level (same thresholds as heuristic)
        if final_score <= 20.0:
            result.nn_risk_level = RiskLevel.CLEAN
        elif final_score <= 40.0:
            result.nn_risk_level = RiskLevel.LOW
        elif final_score <= 60.0:
            result.nn_risk_level = RiskLevel.MODERATE
        elif final_score <= 80.0:
            result.nn_risk_level = RiskLevel.HIGH
        else:
            result.nn_risk_level = RiskLevel.CRITICAL
