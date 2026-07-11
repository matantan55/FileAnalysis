"""Local LLM Insights Generator."""

from __future__ import annotations

import logging

from fileanalysis.analyzers.base import AnalysisResult
from transformers import pipeline
import torch

logger = logging.getLogger(__name__)

class AIInsightsGenerator:
    """Generates offline AI insights using HuggingFace Transformers."""
    
    def __init__(self):
        self.model_id = "Qwen/Qwen2.5-0.5B-Instruct"
        self._pipe = None

    def _load_model(self):
        """Lazily load the model so we don't block normal initialization."""
        if self._pipe is None:
            logger.info("Initializing offline AI engine. Downloading weights if first run (1.5GB)...")
            
            # Use CPU to maximize compatibility across all machines
            self._pipe = pipeline(
                "text-generation",
                model=self.model_id,
                torch_dtype=torch.float32,
                device="cpu",
            )
            logger.info("AI engine initialized.")

    def generate(self, result: AnalysisResult) -> str:
        """Generate a threat summary from the analysis result."""
        try:
            self._load_model()
            
            # Serialize the findings to present to the LLM
            prompt = self._build_prompt(result)
            
            messages = [
                {"role": "system", "content": "You are an expert malware analyst. Provide a concise, highly technical 2-sentence executive summary of the file's capabilities based on the provided static analysis. Focus on the most severe threat vectors. Do not use filler text."},
                {"role": "user", "content": prompt}
            ]
            
            out = self._pipe(messages, max_new_tokens=150, temperature=0.3, do_sample=True)
            text = out[0]["generated_text"][-1]["content"].strip()
            
            return text
            
        except Exception as e:
            logger.error(f"Failed to generate AI insights: {e}")
            return "AI Insights failed to generate due to an internal error."

    def _build_prompt(self, result: AnalysisResult) -> str:
        """Constructs the data prompt for the LLM."""
        lines = []
        lines.append(f"Filename: {result.metadata.name}")
        lines.append(f"File Type: {result.metadata.magic_description}")
        lines.append(f"Entropy: {result.entropy.overall} (Packed: {result.entropy.is_packed})")
        lines.append(f"Calculated Threat Level: {result.risk_level.value}")
        
        if result.yara_matches:
            lines.append("YARA Hits: " + ", ".join([y.rule_name for y in result.yara_matches]))
            
        if result.capabilities:
            caps = []
            for c in result.capabilities:
                caps.append(f"{c.name}: {c.description}")
            lines.append("Detected MITRE Capabilities:\n" + "\n".join(caps))
            
        return "\n".join(lines)
