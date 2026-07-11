"""Feature extraction layer: converts AnalysisResult → fixed-length numeric vector."""

from __future__ import annotations
import math
from typing import TYPE_CHECKING
import numpy as np
if TYPE_CHECKING:
    from fileanalysis.analyzers.base import AnalysisResult

# Total number of features extracted
NUM_FEATURES = 30


def _safe_log(x: float) -> float:
    """Log-scale a value safely (log1p to handle zero)."""
    return math.log1p(max(x, 0.0))


def _cap(value: float, maximum: float = 50.0) -> float:
    """Cap a value at a maximum for normalization."""
    return min(value, maximum)


class FeatureExtractor:
    """Extracts a fixed-length numeric feature vector from an AnalysisResult.

    The resulting vector has ``NUM_FEATURES`` (30) dimensions, designed to
    capture the most discriminative signals from every analyzer stage.
    """

    def extract(self, result: AnalysisResult) -> np.ndarray:
        """Return a 1-D float32 numpy array of shape (NUM_FEATURES,)."""
        features: list[float] = []

        # --- 1. File metadata (2 features) ---
        features.append(_safe_log(result.metadata.size))           # [0] file size (log)
        # Entropy
        features.append(result.entropy.overall)                    # [1] overall entropy (0-8)

        # --- 2. Entropy flags (2 features) ---
        features.append(1.0 if result.entropy.is_packed else 0.0)  # [2] packed flag
        # Max section entropy
        section_entropies = [s.entropy for s in result.sections if s.entropy > 0]
        features.append(max(section_entropies) if section_entropies else 0.0)  # [3]

        # --- 3. Section anomalies (2 features) ---
        suspicious_sections = sum(1 for s in result.sections if s.suspicious)
        features.append(float(suspicious_sections))                # [4]
        features.append(float(len(result.sections)))               # [5]

        # --- 4. String counts (9 features) ---
        s = result.strings
        features.append(_cap(len(s.urls)))                         # [6]
        features.append(_cap(len(s.ips)))                          # [7]
        features.append(_cap(len(s.crypto_wallets), 10.0))         # [8]
        features.append(_cap(len(s.shell_commands), 30.0))         # [9]
        features.append(_cap(len(s.api_calls), 50.0))              # [10]
        features.append(_cap(len(s.base64_blobs), 20.0))           # [11]
        features.append(_cap(len(s.registry_keys), 20.0))          # [12]
        features.append(_cap(len(s.email_addresses), 10.0))        # [13]
        features.append(_cap(len(s.file_paths), 30.0))             # [14]

        # --- 5. Indicators (3 features) ---
        indicators = result.indicators
        features.append(_cap(len(indicators), 20.0))               # [15]
        if indicators:
            sevs = [ind.severity for ind in indicators]
            features.append(max(sevs))                             # [16]
            features.append(sum(sevs) / len(sevs))                 # [17]
        else:
            features.append(0.0)                                   # [16]
            features.append(0.0)                                   # [17]

        # --- 6. Capabilities (3 features) ---
        caps = result.capabilities
        features.append(_cap(len(caps), 10.0))                     # [18]
        if caps:
            risks = [c.risk_contribution for c in caps]
            features.append(max(risks))                            # [19]
            features.append(min(sum(risks), 5.0))                  # [20]
        else:
            features.append(0.0)                                   # [19]
            features.append(0.0)                                   # [20]

        # --- 7. YARA matches (4 features) ---
        yara = result.yara_matches
        features.append(_cap(len(yara), 10.0))                     # [21]
        has_critical = any(m.severity.lower() == "critical" for m in yara)
        has_high = any(m.severity.lower() == "high" for m in yara)
        features.append(1.0 if has_critical else 0.0)              # [22]
        features.append(1.0 if has_high else 0.0)                  # [23]
        # Weighted YARA severity score
        severity_map = {"critical": 4.0, "high": 3.0, "medium": 2.0, "low": 1.0}
        yara_score = sum(severity_map.get(m.severity.lower(), 1.0) for m in yara)
        features.append(min(yara_score, 20.0))                     # [24]

        # --- 8. File type one-hot (5 features) ---
        ft = result.metadata.file_type
        features.append(1.0 if ft == "pe" else 0.0)               # [25]
        features.append(1.0 if ft == "elf" else 0.0)              # [26]
        features.append(1.0 if ft == "script" else 0.0)           # [27]
        features.append(1.0 if ft == "document" else 0.0)         # [28]
        features.append(1.0 if ft == "macho" else 0.0)            # [29]

        assert len(features) == NUM_FEATURES, f"Expected {NUM_FEATURES} features, got {len(features)}"
        return np.array(features, dtype=np.float32)
