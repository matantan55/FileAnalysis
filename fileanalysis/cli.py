"""Main CLI entry point for the FileAnalysis tool."""

from __future__ import annotations

import os
import sys

# Prevent OpenMP segmentation fault on macOS when LightGBM and PyTorch run in same process
os.environ["KMP_DUPLICATE_LIB_OK"] = "TRUE"
os.environ["OMP_NUM_THREADS"] = "1"

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

from fileanalysis.analyzers.base import RiskLevel
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
from fileanalysis.loader import load_file
from fileanalysis.reporting.json_report import JsonReporter
from fileanalysis.reporting.terminal_report import TerminalReporter
from fileanalysis.scoring.scorer import ThreatScorer
from fileanalysis.scoring.nn_model import NNThreatScorer
from fileanalysis.scoring.ml_model import LightGBMThreatScorer
from fileanalysis.intelligence.ai_insights import AIInsightsGenerator


@click.command()
@click.argument("file_path", type=click.Path(exists=True, dir_okay=False))
@click.option("--json", "json_format", is_flag=True, help="Output results in JSON format.")
@click.option("--yara-rules", type=click.Path(file_okay=False), help="Custom directory containing YARA rules (.yar/.yara).")
def cli(file_path: str, json_format: bool, yara_rules: str | None) -> None:
    """Analyze a file for malicious indicators, capabilities, and threat environment impact."""
    console = Console(stderr=True)
    show_progress = not json_format  # suppress spinner for JSON output

    with Progress(
        SpinnerColumn("dots"),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=30),
        TaskProgressColumn(),
        console=console,
        transient=True,
        disable=not show_progress,
    ) as progress:
        # Total steps: load(1) + common(3) + format(1) + yara(1) + mitre(1) + heuristic(1) + nn(1) + ai(1) = 10
        task = progress.add_task("Scanning…", total=10)

        # 1. Load file
        progress.update(task, description="📂 Loading file…")
        try:
            file_bytes, result = load_file(file_path)
        except Exception as e:
            click.secho(f"[-] Error loading file: {e}", fg="red", err=True)
            sys.exit(1)
        progress.advance(task)

        # 2. Common analyzers
        progress.update(task, description="🔑 Computing hashes…")
        HashAnalyzer().analyze(file_path, file_bytes, result)
        progress.advance(task)

        progress.update(task, description="🔥 Analyzing entropy…")
        EntropyAnalyzer().analyze(file_path, file_bytes, result)
        progress.advance(task)

        progress.update(task, description="🔍 Extracting strings…")
        StringAnalyzer().analyze(file_path, file_bytes, result)
        progress.advance(task)

        # 3. Format-specific analyzers
        file_type = result.metadata.file_type
        format_label = file_type.upper() if file_type else "generic"
        progress.update(task, description=f"🧬 Running {format_label} analyzer…")

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
        progress.advance(task)

        # 4. YARA rule scanner
        progress.update(task, description="🕵️ Matching YARA signatures…")
        scanner = YaraScanner(custom_rules_dir=yara_rules)
        scanner.scan(file_path, result)
        progress.advance(task)

        # 5. MITRE ATT&CK capability mapper
        progress.update(task, description="🎯 Mapping MITRE ATT&CK…")
        mapper = CapabilityMapper()
        mapper.map_capabilities(result)
        progress.advance(task)

        # 6. Heuristic scoring
        progress.update(task, description="📊 Heuristic scoring…")
        heuristic_scorer = ThreatScorer()
        heuristic_scorer.calculate_score(result)
        progress.advance(task)

        # 7. Neural network scoring
        progress.update(task, description="🧠 Neural network scoring…")
        try:
            nn_scorer = NNThreatScorer()
            nn_scorer.calculate_score(result)
            result.scoring_method = "dual"
        except (FileNotFoundError, ImportError, Exception):
            pass

        # 7.5 LightGBM Machine Learning scoring
        progress.update(task, description="🌲 Machine learning scoring…")
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
                
        # 7.6 Calculate Ensemble Score
        if result.scoring_method == "triple":
            # Smart weighted ensemble: 40% Heuristic, 40% LightGBM, 20% MalConv
            base_score = 0.4 * result.risk_score + 0.4 * result.ml_score + 0.2 * getattr(result, 'nn_score', result.risk_score)
        elif result.scoring_method == "dual":
            base_score = 0.6 * result.risk_score + 0.4 * getattr(result, 'nn_score', result.risk_score)
        elif result.scoring_method == "dual_ml":
            base_score = 0.6 * result.risk_score + 0.4 * getattr(result, 'ml_score', result.risk_score)
        else:
            base_score = result.risk_score
            
        # Anti-False-Positive Filter
        # Our ML models were primarily trained on PE/ELF binaries.
        # They are prone to wildly overfitting on innocent PDFs, text files, and empty files.
        if result.metadata.file_type not in ["pe", "elf", "macho"]:
            # For documents/scripts/generic files, heavily trust the heuristic
            if result.risk_score < 20.0:
                base_score = min(base_score, 20.0)  # Cap at CLEAN
        else:
            # For executables, if heuristic found absolutely zero suspicious capabilities or strings
            if result.risk_score < 10.0:
                base_score = min(base_score, 40.0)  # Cap at LOW

        result.ensemble_score = round(base_score, 1)
            
        # Determine ensemble risk level
        if result.ensemble_score <= 20.0:
            result.ensemble_risk_level = RiskLevel.CLEAN
        elif result.ensemble_score <= 40.0:
            result.ensemble_risk_level = RiskLevel.LOW
        elif result.ensemble_score <= 60.0:
            result.ensemble_risk_level = RiskLevel.MODERATE
        elif result.ensemble_score <= 80.0:
            result.ensemble_risk_level = RiskLevel.HIGH
        else:
            result.ensemble_risk_level = RiskLevel.CRITICAL
            
        progress.advance(task)

        # 8. AI Insights Generation
        progress.update(task, description="💡 Generating AI insights…")
        try:
            ai_gen = AIInsightsGenerator()
            result.ai_summary = ai_gen.generate(result)
        except Exception:
            pass
        progress.advance(task)

    # Render report (to stdout, after progress is cleared)
    if json_format:
        json_data = JsonReporter().render(result)
        click.echo(json_data)
    else:
        reporter = TerminalReporter()
        reporter.render(result)


if __name__ == "__main__":
    cli()
