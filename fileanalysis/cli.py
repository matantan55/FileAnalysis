"""Main CLI entry point for the FileAnalysis tool."""

from __future__ import annotations

import socket
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

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
from fileanalysis.intelligence.virustotal import VirusTotalClient
from fileanalysis.intelligence.yara_scanner import YaraScanner
from fileanalysis.loader import load_file
from fileanalysis.reporting.json_report import JsonReporter
from fileanalysis.reporting.terminal_report import TerminalReporter
from fileanalysis.scoring.scorer import ThreatScorer
from fileanalysis.scoring.nn_model import NNThreatScorer


def _has_internet() -> bool:
    """Quick connectivity check — try to reach DNS root (no HTTP overhead)."""
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=2).close()
        return True
    except OSError:
        return False


@click.command()
@click.argument("file_path", type=click.Path(exists=True, dir_okay=False))
@click.option("--vt-api-key", envvar="VT_API_KEY", help="VirusTotal API Key (also checks VT_API_KEY env var).")
@click.option("--no-vt", is_flag=True, help="Disable VirusTotal lookup even if an API key is available.")
@click.option("--json", "json_format", is_flag=True, help="Output results in JSON format.")
@click.option("--yara-rules", type=click.Path(file_okay=False), help="Custom directory containing YARA rules (.yar/.yara).")
def cli(file_path: str, vt_api_key: str | None, no_vt: bool, json_format: bool, yara_rules: str | None) -> None:
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
        # Total steps: load(1) + common(3) + format(1) + yara(1) + mitre(1) + vt(1) + heuristic(1) + nn(1) = 10
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

        # 6. VirusTotal lookup (default ON if API key exists + internet available)
        progress.update(task, description="🌐 VirusTotal lookup…")
        if not no_vt:
            vt_client = VirusTotalClient(api_key=vt_api_key)
            if vt_client.enabled:
                if _has_internet():
                    vt_client.lookup_hash(result.hashes.sha256, result)
                else:
                    result.errors.append("VirusTotal skipped: no internet connection detected.")
        progress.advance(task)

        # 7. Heuristic scoring
        progress.update(task, description="📊 Heuristic scoring…")
        heuristic_scorer = ThreatScorer()
        heuristic_scorer.calculate_score(result)
        progress.advance(task)

        # 8. Neural network scoring
        progress.update(task, description="🧠 Neural network scoring…")
        try:
            nn_scorer = NNThreatScorer()
            nn_scorer.calculate_score(result)
            result.scoring_method = "dual"
        except (FileNotFoundError, Exception):
            result.scoring_method = "heuristic"
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
