"""Machine learning threat scoring model (LightGBM) and inference wrapper."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING
import numpy as np
import lightgbm as lgb

if TYPE_CHECKING:
    from fileanalysis.analyzers.base import AnalysisResult

from fileanalysis.analyzers.base import RiskLevel
from fileanalysis.scoring.features import NUM_FEATURES, FeatureExtractor

logger = logging.getLogger(__name__)

# Default model weights path (alongside this file)
DEFAULT_MODEL_PATH = Path(__file__).parent / "threat_model_lgb.txt"
DEFAULT_SCALER_PATH = Path(__file__).parent / "feature_scaler.npz"


class LightGBMThreatScorer:
    """Gradient-Boosted Tree-based threat scorer.

    Loads a pre-trained LightGBM model and uses it to score files.
    Falls back to a clear error if LightGBM is unavailable or weights are missing.
    """

    def __init__(self, model_path: str | Path | None = None) -> None:
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
        """Load the LightGBM model with pre-trained weights."""
        if not self.model_path.exists():
            raise FileNotFoundError(
                f"Model weights not found at {self.model_path}. "
                f"Run 'python -m fileanalysis.scoring.sandbox_train' to generate them."
            )

        model = lgb.Booster(model_file=str(self.model_path))
        logger.info("Loaded LightGBM model from %s", self.model_path)
        return model

    def calculate_score(self, result: AnalysisResult) -> None:
        """Run ML inference on the AnalysisResult and set ml_score/ml_risk_level.

        This writes to the ml_* fields on AnalysisResult so it can coexist
        with the heuristic scorer's risk_score/risk_level fields and the nn_* fields.
        """
        # Extract and normalize features
        features = self.extractor.extract(result)
        features = (features - self.feat_mean) / (self.feat_std + 1e-8)
        
        # Inference
        raw_output = self.model.predict(features.reshape(1, -1))[0]

        # Convert output [0, 1] → score [0, 100]
        confidence = float(raw_output)
        final_score = round(confidence * 100.0, 1)
        final_score = max(0.0, min(100.0, final_score))

        result.ml_score = final_score
        result.ml_confidence = round(confidence, 4)

        # Determine risk level (same thresholds as heuristic)
        if final_score <= 20.0:
            result.ml_risk_level = RiskLevel.CLEAN
        elif final_score <= 40.0:
            result.ml_risk_level = RiskLevel.LOW
        elif final_score <= 60.0:
            result.ml_risk_level = RiskLevel.MODERATE
        elif final_score <= 80.0:
            result.ml_risk_level = RiskLevel.HIGH
        else:
            result.ml_risk_level = RiskLevel.CRITICAL
