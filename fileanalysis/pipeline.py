"""Shared analysis pipeline used by both the CLI and MCP server."""

from __future__ import annotations

import logging

from fileanalysis.loader import load_file
from fileanalysis.analyzers.base import AnalysisResult, RiskLevel
from fileanalysis.analyzers.dll_analyzer import DLLAnalyzer
from fileanalysis.analyzers.document_analyzer import DocumentAnalyzer
from fileanalysis.analyzers.elf_analyzer import ELFAnalyzer
from fileanalysis.analyzers.entropy import EntropyAnalyzer
from fileanalysis.analyzers.hashing import HashAnalyzer
from fileanalysis.analyzers.macho_analyzer import MachOAnalyzer
from fileanalysis.analyzers.pe_analyzer import PEAnalyzer
from fileanalysis.analyzers.script_analyzer import ScriptAnalyzer
from fileanalysis.analyzers.strings import StringAnalyzer
from fileanalysis.intelligence.capability_mapper import CapabilityMapper
from fileanalysis.intelligence.yara_scanner import YaraScanner
from fileanalysis.scoring.scorer import ThreatScorer
from fileanalysis.scoring.nn_model import NNThreatScorer
from fileanalysis.scoring.ml_model import LightGBMThreatScorer
from fileanalysis.intelligence.ai_insights import AIInsightsGenerator

logger = logging.getLogger("malown.pipeline")

# ── Ensemble scoring weights ────────────────────────────────────────
_W_HEURISTIC_TRIPLE = 0.4
_W_ML_TRIPLE = 0.4
_W_NN_TRIPLE = 0.2

_W_HEURISTIC_DUAL = 0.6
_W_NN_DUAL = 0.4

_W_HEURISTIC_DUAL_ML = 0.6
_W_ML_DUAL_ML = 0.4


def _classify_risk_level(score: float) -> RiskLevel:
    """Map a numeric score to a RiskLevel enum."""
    if score <= 20.0:
        return RiskLevel.CLEAN
    elif score <= 40.0:
        return RiskLevel.LOW
    elif score <= 60.0:
        return RiskLevel.MODERATE
    elif score <= 80.0:
        return RiskLevel.HIGH
    return RiskLevel.CRITICAL


def _compute_ensemble(result: AnalysisResult) -> None:
    """Compute the ensemble score and risk level from individual scorers."""
    method = getattr(result, "scoring_method", "heuristic")

    if method == "triple":
        base_score = (
            _W_HEURISTIC_TRIPLE * result.risk_score
            + _W_ML_TRIPLE * result.ml_score
            + _W_NN_TRIPLE * getattr(result, "nn_score", result.risk_score)
        )
    elif method == "dual":
        base_score = (
            _W_HEURISTIC_DUAL * result.risk_score
            + _W_NN_DUAL * getattr(result, "nn_score", result.risk_score)
        )
    elif method == "dual_ml":
        base_score = (
            _W_HEURISTIC_DUAL_ML * result.risk_score
            + _W_ML_DUAL_ML * getattr(result, "ml_score", result.risk_score)
        )
    else:
        base_score = result.risk_score

    # Anti-False-Positive Filter
    if result.metadata.file_type not in ["pe", "elf", "macho"]:
        if result.risk_score < 20.0:
            base_score = min(base_score, 20.0)  # Cap at CLEAN
    else:
        if result.risk_score < 10.0:
            base_score = min(base_score, 40.0)  # Cap at LOW

    result.ensemble_score = round(base_score, 1)
    result.ensemble_risk_level = _classify_risk_level(result.ensemble_score)


def run_pipeline(file_path: str, yara_rules: str | None = None) -> AnalysisResult:
    """Execute the full analysis pipeline and return a populated AnalysisResult.

    This is the single source of truth for the analysis logic shared
    between the CLI, MCP server, and any future entry points.
    """
    logger.info("Starting analysis pipeline for: %s", file_path)

    # 1. Load file
    file_bytes, result = load_file(file_path)

    # 2. Common analyzers
    HashAnalyzer().analyze(file_path, file_bytes, result)
    EntropyAnalyzer().analyze(file_path, file_bytes, result)
    StringAnalyzer().analyze(file_path, file_bytes, result)

    # 3. Format-specific analyzers
    file_type = result.metadata.file_type
    if file_type == "pe":
        PEAnalyzer().analyze(file_path, file_bytes, result)
        if result.format_info.get("is_dll"):
            DLLAnalyzer().analyze(file_path, file_bytes, result)
    elif file_type == "elf":
        ELFAnalyzer().analyze(file_path, file_bytes, result)
    elif file_type == "macho":
        MachOAnalyzer().analyze(file_path, file_bytes, result)
    elif file_type == "script":
        ScriptAnalyzer().analyze(file_path, file_bytes, result)
    elif file_type == "document":
        DocumentAnalyzer().analyze(file_path, file_bytes, result)

    # 4. YARA scanning
    scanner = YaraScanner(custom_rules_dir=yara_rules)
    scanner.scan(file_path, result)

    # 5. MITRE ATT&CK capability mapping
    mapper = CapabilityMapper()
    mapper.map_capabilities(result)

    # 6. Heuristic scoring
    heuristic_scorer = ThreatScorer()
    heuristic_scorer.calculate_score(result)

    # 7. Neural network scoring
    try:
        nn_scorer = NNThreatScorer()
        nn_scorer.calculate_score(result)
        result.scoring_method = "dual"
    except (FileNotFoundError, ImportError, Exception):
        pass

    # 8. LightGBM scoring
    try:
        ml_scorer = LightGBMThreatScorer()
        ml_scorer.calculate_score(result)
        if result.scoring_method == "dual":
            result.scoring_method = "triple"
        else:
            result.scoring_method = "dual_ml"
    except (FileNotFoundError, ImportError, Exception):
        if result.scoring_method != "dual":
            result.scoring_method = "heuristic"

    # 9. Ensemble score
    _compute_ensemble(result)

    # 10. AI Insights
    try:
        ai_gen = AIInsightsGenerator()
        result.ai_summary = ai_gen.generate(result)
    except Exception:
        pass

    logger.info(
        "Pipeline complete for %s — ensemble_score=%.1f (%s)",
        file_path,
        result.ensemble_score,
        result.ensemble_risk_level.value,
    )
    return result
