"""Main CLI entry point for the FileAnalysis tool."""

from __future__ import annotations

import sys
from pathlib import Path

import click

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


@click.command()
@click.argument("file_path", type=click.Path(exists=True, dir_okay=False))
@click.option("--vt", is_flag=True, help="Perform optional VirusTotal API hash lookup.")
@click.option("--vt-api-key", envvar="VT_API_KEY", help="VirusTotal API Key (also checks VT_API_KEY env var).")
@click.option("--json", "json_format", is_flag=True, help="Output results in JSON format.")
@click.option("--yara-rules", type=click.Path(file_okay=False), help="Custom directory containing YARA rules (.yar/.yara).")
@click.option("--nn", "use_nn", is_flag=True, help="Use neural network model for threat scoring instead of heuristic rules.")
def cli(file_path: str, vt: bool, vt_api_key: str | None, json_format: bool, yara_rules: str | None, use_nn: bool) -> None:
    """Analyze a file for malicious indicators, capabilities, and threat environment impact."""
    # 1. Load file and initialize result
    try:
        file_bytes, result = load_file(file_path)
    except Exception as e:
        click.secho(f"[-] Error loading file: {e}", fg="red", err=True)
        sys.exit(1)

    # 2. Run common analyzers
    HashAnalyzer().analyze(file_path, file_bytes, result)
    EntropyAnalyzer().analyze(file_path, file_bytes, result)
    StringAnalyzer().analyze(file_path, file_bytes, result)

    # 3. Run format-specific analyzers
    file_type = result.metadata.file_type

    if file_type == "pe":
        # Run PE analyzer
        pe_analyzer = PEAnalyzer()
        pe_analyzer.analyze(file_path, file_bytes, result)

        # If it's a DLL, also run DLL analyzer
        if result.format_info.get("is_dll"):
            dll_analyzer = DLLAnalyzer()
            dll_analyzer.analyze(file_path, file_bytes, result)

    elif file_type == "elf":
        ELFAnalyzer().analyze(file_path, file_bytes, result)

    elif file_type == "macho":
        MachOAnalyzer().analyze(file_path, file_bytes, result)

    elif file_type == "script":
        ScriptAnalyzer().analyze(file_path, file_bytes, result)

    elif file_type == "document":
        DocumentAnalyzer().analyze(file_path, file_bytes, result)

    # 4. YARA rule scanner signature matching
    scanner = YaraScanner(custom_rules_dir=yara_rules)
    scanner.scan(file_path, result)

    # 5. MITRE ATT&CK capability mapper
    mapper = CapabilityMapper()
    mapper.map_capabilities(result)

    # 6. Optional VirusTotal API lookup
    if vt:
        vt_client = VirusTotalClient(api_key=vt_api_key)
        if vt_client.enabled:
            vt_client.lookup_hash(result.hashes.sha256, result)
        else:
            result.errors.append("VirusTotal check requested but no API key configured.")

    # 7. Threat scoring and RiskLevel determination
    if use_nn:
        try:
            scorer = NNThreatScorer()
        except FileNotFoundError as e:
            click.secho(f"[-] {e}", fg="yellow", err=True)
            click.secho("[*] Falling back to heuristic scorer.", fg="yellow", err=True)
            scorer = ThreatScorer()
    else:
        scorer = ThreatScorer()
    scorer.calculate_score(result)

    # 8. Render report
    if json_format:
        json_data = JsonReporter().render(result)
        click.echo(json_data)
    else:
        reporter = TerminalReporter()
        reporter.render(result)


if __name__ == "__main__":
    cli()
