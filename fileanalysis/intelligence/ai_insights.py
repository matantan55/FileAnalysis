"""Local ML-based Insights Generator."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING
import numpy as np

if TYPE_CHECKING:
    from fileanalysis.analyzers.base import AnalysisResult

from fileanalysis.scoring.features import FeatureExtractor

logger = logging.getLogger(__name__)

FEATURE_NAMES = [
    "File Size",                                # 0
    "Overall File Entropy",                     # 1
    "Packed Signature Detection",               # 2
    "Maximum Section Entropy",                  # 3
    "Suspicious Section Count",                 # 4
    "Total Number of Sections",                 # 5
    "Embedded URLs",                            # 6
    "Embedded IP Addresses",                    # 7
    "Embedded Cryptocurrency Wallets",          # 8
    "Embedded Shell Commands",                  # 9
    "Suspicious API Imports",                   # 10
    "Base64 Encoded Strings",                   # 11
    "Windows Registry Keys",                    # 12
    "Embedded Email Addresses",                 # 13
    "Embedded File Paths",                      # 14
    "Heuristic Indicator Count",                # 15
    "Maximum Indicator Severity",               # 16
    "Average Indicator Severity",               # 17
    "MITRE ATT&CK Capabilities",                # 18
    "Maximum Capability Risk",                  # 19
    "Aggregate Capability Risk",                # 20
    "YARA Signature Hits",                      # 21
    "Critical YARA Matches",                    # 22
    "High Severity YARA Matches",               # 23
    "Weighted YARA Threat Score",               # 24
    "PE Executable Format",                     # 25
    "ELF Executable Format",                    # 26
    "Script File Format",                       # 27
    "Document File Format",                     # 28
    "Mach-O Executable Format",                 # 29
]

class AIInsightsGenerator:
    """Generates accurate insights using LightGBM feature contributions (SHAP)."""
    
    def __init__(self):
        self._scorer = None

    def _load_model(self):
        """Lazily load the LightGBM scorer."""
        if self._scorer is None:
            try:
                from fileanalysis.scoring.ml_model import LightGBMThreatScorer
                self._scorer = LightGBMThreatScorer()
                logger.info("ML Insight engine initialized.")
            except Exception as e:
                logger.error("Failed to load LightGBMThreatScorer: %s", e)
                raise e

    def generate(self, result: AnalysisResult) -> str:
        """Generate a threat summary based on the highest-contributing features."""
        try:
            self._load_model()
            
            features = self._scorer.extractor.extract(result)
            norm_features = (features - self._scorer.feat_mean) / (self._scorer.feat_std + 1e-8)
            
            # Use LightGBM's native SHAP values
            contributions = self._scorer.model.predict(norm_features.reshape(1, -1), pred_contrib=True)[0]
            
            # The last element is the expected value (base score)
            feature_shap = contributions[:-1]
            base_score = contributions[-1]
            total_score = np.sum(contributions)
            
            is_malicious = total_score > 0  # In log-odds, >0 means >50% probability
            
            # Find the top 3 features that pushed the score in the final direction
            if is_malicious:
                # We care about positive contributions
                top_indices = np.argsort(feature_shap)[-3:][::-1]
                direction_text = "malicious"
                filtered_indices = [i for i in top_indices if feature_shap[i] > 0]
            else:
                # We care about negative contributions
                top_indices = np.argsort(feature_shap)[:3]
                direction_text = "benign"
                filtered_indices = [i for i in top_indices if feature_shap[i] < 0]

            if not filtered_indices:
                return "The model did not find any strong discriminative features for this file."

            insights = []
            insights.append(f"The model classified this file as {direction_text} primarily due to:")
            
            for i in filtered_indices:
                feat_name = FEATURE_NAMES[i]
                val = features[i]
                
                # Format the raw value nicely
                if i == 0:
                    val_str = f"approx {int(np.expm1(val))} bytes"
                elif i in [1, 3]:
                    val_str = f"{val:.2f}"
                elif val.is_integer():
                    val_str = str(int(val))
                else:
                    val_str = f"{val:.2f}"
                    
                insights.append(f"• {feat_name} (Value: {val_str})")
                
            if getattr(result, 'ml_score', None) is not None:
                insights.append(f"\nFinal ML Score: {result.ml_score}/100 ({result.ml_confidence * 100:.1f}% confidence)")
                
            return "\n".join(insights)
            
        except FileNotFoundError as e:
            logger.warning(f"ML insights unavailable: {e}")
            return "ML insights unavailable: Model weights not found. Run 'python -m fileanalysis.scoring.sandbox_train' to generate them."
        except Exception as e:
            logger.error(f"Failed to generate ML insights: {e}")
            return "Insights failed to generate due to an internal error."
