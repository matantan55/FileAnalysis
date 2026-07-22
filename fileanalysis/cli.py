"""Main CLI entry point for the FileAnalysis tool."""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Prevent OpenMP segmentation fault on macOS when LightGBM and PyTorch run in same process
os.environ["KMP_DUPLICATE_LIB_OK"] = "TRUE"
os.environ["OMP_NUM_THREADS"] = "1"

import click
import pyfiglet
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.prompt import Prompt
from rich.panel import Panel
from rich.table import Table

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

console = Console(stderr=True)

def run_analysis(file_path: str, json_format: bool, yara_rules: str | None) -> None:
    """Run standard full scanning analysis."""
    show_progress = not json_format

    if show_progress:
        console.print("[bold cyan]Starting file analysis...[/]", justify="center")

    with Progress(
        SpinnerColumn("dots"),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=30),
        TaskProgressColumn(),
        console=console,
        disable=not show_progress,
    ) as progress:
        # 1. Load file
        t_load = progress.add_task("📂 Loading file…", total=1)
        try:
            file_bytes, result = load_file(file_path)
        except Exception as e:
            console.print(f"[bold red][-] Error loading file: {e}[/]")
            return
        progress.advance(t_load)

        # 2. Common analyzers
        t_hash = progress.add_task("🔑 Computing hashes…", total=1)
        HashAnalyzer().analyze(file_path, file_bytes, result)
        progress.advance(t_hash)

        t_entropy = progress.add_task("🔥 Analyzing entropy…", total=1)
        EntropyAnalyzer().analyze(file_path, file_bytes, result)
        progress.advance(t_entropy)

        t_strings = progress.add_task("🔍 Extracting strings…", total=1)
        StringAnalyzer().analyze(file_path, file_bytes, result)
        progress.advance(t_strings)

        # 3. Format-specific analyzers
        file_type = result.metadata.file_type
        format_label = file_type.upper() if file_type else "generic"
        t_format = progress.add_task(f"🧬 Running {format_label} analyzer…", total=1)

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
        progress.advance(t_format)

        # 4. YARA rule scanner
        t_yara = progress.add_task("🕵️ Matching YARA signatures…", total=1)
        scanner = YaraScanner(custom_rules_dir=yara_rules)
        scanner.scan(file_path, result)
        progress.advance(t_yara)

        # 5. MITRE ATT&CK capability mapper
        t_mitre = progress.add_task("🎯 Mapping MITRE ATT&CK…", total=1)
        mapper = CapabilityMapper()
        mapper.map_capabilities(result)
        progress.advance(t_mitre)

        # 6. Heuristic scoring
        t_heur = progress.add_task("📊 Heuristic scoring…", total=1)
        heuristic_scorer = ThreatScorer()
        heuristic_scorer.calculate_score(result)
        progress.advance(t_heur)

        # 7. Neural network scoring
        t_nn = progress.add_task("🧠 Neural network scoring…", total=1)
        try:
            nn_scorer = NNThreatScorer()
            nn_scorer.calculate_score(result)
            result.scoring_method = "dual"
        except (FileNotFoundError, ImportError, Exception):
            pass
        progress.advance(t_nn)

        # 7.5 LightGBM Machine Learning scoring
        t_ml = progress.add_task("🌲 Machine learning scoring…", total=1)
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
        progress.advance(t_ml)
                
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
        if result.metadata.file_type not in ["pe", "elf", "macho"]:
            if result.risk_score < 20.0:
                base_score = min(base_score, 20.0)  # Cap at CLEAN
        else:
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

        # 8. AI Insights Generation
        t_ai = progress.add_task("💡 Generating AI insights…", total=1)
        try:
            ai_gen = AIInsightsGenerator()
            result.ai_summary = ai_gen.generate(result)
        except Exception:
            pass
        progress.advance(t_ai)

    # Render report
    if json_format:
        json_data = JsonReporter().render(result)
        click.echo(json_data)
    else:
        reporter = TerminalReporter()
        reporter.render(result)


def interactive_menu():
    """Run an interactive CLI menu."""
    menu_console = Console()
    loaded_files = []
    error_msg = None
    
    while True:
        # Clear screen for menu loop
        menu_console.clear()
        
        # Print Banner
        ascii_text = pyfiglet.figlet_format("ThreatsNet", font="slant")
        menu_console.print(f"[bold red]{ascii_text}[/]", justify="center")
        
        if error_msg:
            menu_console.print(f"[bold red]{error_msg}[/]", justify="center")
            error_msg = None

        
        if loaded_files:
            file_table = Table(title="[bold blue]Loaded Files[/]", show_header=True, header_style="bold magenta", expand=True)
            file_table.add_column("Index", justify="right", style="cyan", no_wrap=True)
            file_table.add_column("Path", style="white")
            
            for idx, f in enumerate(loaded_files):
                file_table.add_row(str(idx + 1), f)
            menu_console.print(file_table)
            menu_console.print()
        else:
            menu_console.print("[dim italic]No files currently loaded.[/]\n", justify="center")
        
        # Build Table
        menu_table = Table(show_header=False, box=None, padding=(0, 2))
        menu_table.add_column("Key", style="bold green", justify="right")
        menu_table.add_column("Action", style="bold white")
        menu_table.add_column("Description", style="dim")
        
        menu_table.add_row("1.", "Standard File Analysis", "Run the full scanning pipeline with ML scoring, capabilities mapping, and YARA")
        menu_table.add_row("2.", "Interactive Binary Research", "Open the hex viewer with disassembled code and threat annotations")
        menu_table.add_row("3.", "Clear Files", "Remove all loaded files from the workspace")
        menu_table.add_row("4.", "Quit", "Exit the application")
        
        # Build Panel
        menu_panel = Panel(
            menu_table,
            title="[bold cyan]Interactive Console[/]",
            border_style="cyan",
            expand=False,
            padding=(1, 2)
        )
        
        menu_console.print(menu_panel, justify="center")

        # Allow any input; choices parameter restricts it, so we don't use it.
        choice = Prompt.ask("\n[bold yellow]Select an option or paste a file path to load[/]")

        if choice == "4":
            menu_console.print("[bold cyan]Exiting...[/]")
            break
            
        elif choice == "3":
            loaded_files.clear()
            
        elif choice in ["1", "2"]:
            if not loaded_files:
                menu_console.print("[bold red]No files loaded! Please paste a file path first.[/]")
                Prompt.ask("\n[bold dim]Press Enter to continue...[/]")
                continue
                
            selected_file = loaded_files[0]
            if len(loaded_files) > 1:
                file_idx = Prompt.ask(
                    "\n[bold yellow]Select a file by index[/]",
                    choices=[str(i+1) for i in range(len(loaded_files))]
                )
                selected_file = loaded_files[int(file_idx)-1]
                
            if choice == "1":
                run_analysis(selected_file, json_format=False, yara_rules=None)
                Prompt.ask("\n[bold dim]Press Enter to return to the main menu...[/]")
            elif choice == "2":
                from fileanalysis.research.hex_viewer import HexViewer
                viewer = HexViewer(selected_file)
                viewer.run()
                
        else:
            # Not a recognized option number; try to load it as a file path
            file_path = choice.strip("'\"")
            if not os.path.exists(file_path):
                error_msg = f"Invalid option or file not found: {file_path}"
            elif not os.path.isfile(file_path):
                error_msg = f"Not a file: {file_path}"
            else:
                if file_path not in loaded_files:
                    loaded_files.append(file_path)


@click.command()
@click.argument("file_path", required=False, type=click.Path(exists=True, dir_okay=False))
@click.option("--json", "json_format", is_flag=True, help="Output results in JSON format.")
@click.option("--research", is_flag=True, help="Open interactive hex viewer with binary annotations.")
@click.option("--yara-rules", type=click.Path(file_okay=False), help="Custom directory containing YARA rules (.yar/.yara).")
def cli(file_path: str | None, json_format: bool, research: bool, yara_rules: str | None) -> None:
    """Analyze a file for malicious indicators, capabilities, and threat environment impact."""
    if not file_path:
        # Interactive mode
        interactive_menu()
    else:
        # One-shot CLI mode
        if research:
            from fileanalysis.research.hex_viewer import HexViewer
            viewer = HexViewer(file_path)
            viewer.run()
        else:
            run_analysis(file_path, json_format, yara_rules)

if __name__ == "__main__":
    cli()
