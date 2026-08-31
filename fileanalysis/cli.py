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
from rich.align import Align
from rich.text import Text

from prompt_toolkit import PromptSession
from prompt_toolkit.key_binding import KeyBindings

from fileanalysis.analyzers.base import RiskLevel
from fileanalysis.loader import load_file
from fileanalysis.reporting.json_report import JsonReporter
from fileanalysis.reporting.terminal_report import TerminalReporter
from fileanalysis.pipeline import run_pipeline
from fileanalysis.research.hex_viewer import HexViewer

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
        t_pipeline = progress.add_task("🔬 Running analysis pipeline…", total=1)
        result = run_pipeline(file_path, yara_rules)
        progress.advance(t_pipeline)

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
    
    kb = KeyBindings()
    
    @kb.add("up")
    def _(event):
        b = event.app.current_buffer
        if b.text in ["1", "2", "3", "4"]:
            val = int(b.text)
            b.text = str(max(1, val - 1))
            b.cursor_position = len(b.text)
        elif not b.text:
            b.text = "4"
            b.cursor_position = len(b.text)
            
    @kb.add("down")
    def _(event):
        b = event.app.current_buffer
        if b.text in ["1", "2", "3", "4"]:
            val = int(b.text)
            b.text = str(min(4, val + 1))
            b.cursor_position = len(b.text)
        elif not b.text:
            b.text = "1"
            b.cursor_position = len(b.text)
            
    session = PromptSession(key_bindings=kb)
    
    running = True
    while running:
        # Clear screen for menu loop
        menu_console.clear()
        
        # Print Banner
        ascii_text = pyfiglet.figlet_format("MalOwn", font="block")
        menu_console.print(Align.center(Text(ascii_text, style="bold red")))
        
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
        menu_console.print("\n[bold yellow]Select an option (Up/Down) or paste a file path to load[/]")
        try:
            choice = session.prompt("> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            menu_console.print("[bold cyan]Exiting...[/]")
            running = False

        if not running:
            pass
        elif choice in ["4", "q", "quit"]:
            menu_console.print("[bold cyan]Exiting...[/]")
            running = False
            
        elif choice == "3":
            loaded_files.clear()
            
        elif choice in ["1", "2"]:
            if loaded_files:
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
                    viewer = HexViewer(selected_file)
                    viewer.run()
            else:
                error_msg = "No files loaded! Please paste a file path first."
                
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
            viewer = HexViewer(file_path)
            viewer.run()
        else:
            run_analysis(file_path, json_format, yara_rules)

if __name__ == "__main__":
    cli()
