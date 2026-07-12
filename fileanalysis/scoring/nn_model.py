"""Neural network threat scoring model (MalConv) and inference wrapper."""

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

logger = logging.getLogger(__name__)

# Default model weights path (alongside this file)
DEFAULT_MODEL_PATH = Path(__file__).parent / "threat_model_malconv.pt"

# Maximum length for MalConv byte sequences
MAX_LEN = 1048576  # 1MB

class MalConv(nn.Module):
    """MalConv architecture for raw-byte malware detection.
    
    Reads raw bytes up to 1MB and learns temporal spatial features
    without any manual feature engineering.
    """

    def __init__(self, embed_dim=8, channels=128, window_size=500):
        super().__init__()
        # 256 for bytes, +1 for padding (index 256)
        self.embed = nn.Embedding(257, embed_dim, padding_idx=256)
        
        # Gated convolutions
        self.conv_1 = nn.Conv1d(embed_dim, channels, window_size, stride=window_size)
        self.conv_2 = nn.Conv1d(embed_dim, channels, window_size, stride=window_size)
        
        self.pooling = nn.AdaptiveMaxPool1d(1)
        self.fc1 = nn.Linear(channels, channels)
        self.fc2 = nn.Linear(channels, 1)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x is (batch_size, MAX_LEN)
        x = self.embed(x)             # (batch, len, embed_dim)
        x = x.transpose(1, 2)         # (batch, embed_dim, len)
        
        conv1 = self.conv_1(x)
        conv2 = torch.sigmoid(self.conv_2(x))
        x = conv1 * conv2             # gated convolution
        
        x = self.pooling(x).squeeze(-1) # (batch, channels)
        x = torch.relu(self.fc1(x))
        x = self.fc2(x)
        return torch.sigmoid(x)


class NNThreatScorer:
    """Raw-byte Deep Learning threat scorer.

    Loads a pre-trained MalConv model and uses it to score files directly from bytes.
    """

    def __init__(self, model_path: str | Path | None = None) -> None:
        self.torch = torch
        self.model_path = Path(model_path) if model_path else DEFAULT_MODEL_PATH
        self.model = self._load_model()

    def _load_model(self):
        """Load the MalConv model with pre-trained weights."""
        model = MalConv()

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
        logger.info("Loaded MalConv model from %s", self.model_path)
        return model

    def _get_file_bytes(self, path: str) -> np.ndarray:
        """Read up to MAX_LEN bytes, padded with 256."""
        tensor = np.full((MAX_LEN,), 256, dtype=np.int16)
        
        try:
            with open(path, "rb") as f:
                b = f.read(MAX_LEN)
                length = len(b)
                if length > 0:
                    tensor[:length] = np.frombuffer(b, dtype=np.uint8)
        except Exception as e:
            logger.warning(f"Failed to read {path} for MalConv: {e}")
            
        return tensor

    def calculate_score(self, result: AnalysisResult) -> None:
        """Run NN inference on the raw file bytes and set nn_score/nn_risk_level."""
        # Read raw bytes directly from file path
        if not result.metadata.path:
            return
            
        raw_bytes = self._get_file_bytes(result.metadata.path)
        tensor = self.torch.tensor(raw_bytes, dtype=self.torch.long).unsqueeze(0)

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
