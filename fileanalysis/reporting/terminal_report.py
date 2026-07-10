"""Renders analysis results to console using Rich library."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from fileanalysis.analyzers.base import AnalysisResult, RiskLevel


class TerminalReporter:
    """Beautiful CLI terminal reports."""

    def __init__(self):
        self.console = Console()

    def render(self, result: AnalysisResult) -> None:
        """Render results to terminal."""

        # Header Panel
        self.console.print()
        header_text = Text("⚡ FileAnalysis — Malware Threat Report", style="bold cyan")
        self.console.print(Panel(header_text, border_style="cyan", expand=False))

        # Basic Metadata
        m = result.metadata
        self.console.print(f"[bold]📁 File:[/] {m.name}")
        self.console.print(f"[bold]📊 Type:[/] {m.magic_description}")
        self.console.print(f"[bold]📏 Size:[/] {m.size_human} ({m.size:,} bytes)")
        self.console.print(f"[bold]🛡️ Perms:[/] {m.permissions}")
        self.console.print()

        # Risk Score Panel
        color = self._get_risk_color(result.risk_level)
        badge = f"[bold {color}]⛔ RISK SCORE: {result.risk_score}/100 — {result.risk_level.value.upper()}[/]"
        if result.scoring_method == "neural_network":
            badge += f"  [bold magenta]🧠 Neural Network[/] [dim](confidence: {result.nn_confidence:.2%})[/]"
        self.console.print(Panel(badge, border_style=color, expand=False))
        self.console.print()

        # Hashes Table
        hash_table = Table(title="🔒 File Hashes", show_header=True, header_style="bold green")
        hash_table.add_column("Type", style="dim", width=12)
        hash_table.add_column("Value", style="cyan")
        hash_table.add_row("MD5", result.hashes.md5)
        hash_table.add_row("SHA-1", result.hashes.sha1)
        hash_table.add_row("SHA-256", result.hashes.sha256)
        if result.hashes.ssdeep:
            hash_table.add_row("ssdeep", result.hashes.ssdeep)
        if result.hashes.imphash and result.hashes.imphash != "N/A":
            hash_table.add_row("imphash", result.hashes.imphash)
        self.console.print(hash_table)
        self.console.print()

        # Entropy Section
        self.console.print(f"[bold]🔥 File Entropy:[/] {result.entropy.overall}/8.0")
        if result.entropy.is_packed:
            self.console.print("[bold red]⚠️ File is highly likely packed or encrypted.[/]")
        self.console.print()

        # Capabilities (MITRE Mapping)
        if result.capabilities:
            self.console.print("[bold underline yellow]🎯 Threat Capabilities[/]")
            for cap in result.capabilities:
                self.console.print(f"  • [bold red]{cap.name}[/] ({cap.technique_id}) — {cap.description}")
                for ev in cap.evidence:
                    self.console.print(f"    [dim]↳ {ev}[/]")
            self.console.print()

        # Environmental Impact
        self.console.print("[bold underline yellow]⚠️ Environment Impact[/]")
        for i, impact in enumerate(result.environment_impact, 1):
            self.console.print(f"  {i}. {impact}")
        self.console.print()

        # Yara Matches
        if result.yara_matches:
            yara_table = Table(title="🕵️ YARA Matches", show_header=True, header_style="bold red")
            yara_table.add_column("Rule Name", style="bold red")
            yara_table.add_column("Description", style="dim")
            yara_table.add_column("Severity", style="yellow")
            for match in result.yara_matches:
                yara_table.add_row(match.rule_name, match.description, match.severity)
            self.console.print(yara_table)
            self.console.print()

        # VirusTotal
        if result.virustotal:
            vt = result.virustotal
            self.console.print("[bold underline cyan]🌐 VirusTotal Consensus[/]")
            self.console.print(f"  [bold]Detection Ratio:[/] {vt.detection_ratio}")
            if vt.malware_family:
                self.console.print(f"  [bold]Malware Family:[/] [bold red]{vt.malware_family}[/]")
            if vt.permalink:
                self.console.print(f"  [bold]Link:[/] [underline cyan]{vt.permalink}[/]")
            self.console.print()

        # Errors list
        if result.errors:
            self.console.print("[bold red]❌ Processing Errors[/]")
            for err in result.errors:
                self.console.print(f"  • {err}")
            self.console.print()

    def _get_risk_color(self, level: RiskLevel) -> str:
        mapping = {
            RiskLevel.CLEAN: "green",
            RiskLevel.LOW: "blue",
            RiskLevel.MODERATE: "yellow",
            RiskLevel.HIGH: "orange3",
            RiskLevel.CRITICAL: "red",
        }
        return mapping.get(level, "white")

    def _render_plain(self, result: AnalysisResult) -> None:
        """Plain terminal prints fallback if rich is not available."""
        print("=" * 60)
        print("  FileAnalysis — Malware Threat Report")
        print("=" * 60)
        print(f"File: {result.metadata.name}")
        print(f"Type: {result.metadata.magic_description}")
        print(f"Size: {result.metadata.size_human}")
        print("-" * 60)
        print(f"RISK SCORE: {result.risk_score}/100 — {result.risk_level.value.upper()}")
        print("-" * 60)
        print(f"MD5:    {result.hashes.md5}")
        print(f"SHA256: {result.hashes.sha256}")
        print(f"Entropy: {result.entropy.overall}")
        print("-" * 60)
        if result.capabilities:
            print("Threat Capabilities:")
            for cap in result.capabilities:
                print(f"  - {cap.name} ({cap.technique_id}): {cap.description}")
        print("\nEnvironment Impact:")
        for i, imp in enumerate(result.environment_impact, 1):
            print(f"  {i}. {imp}")
        if result.errors:
            print("\nErrors:")
            for err in result.errors:
                print(f"  ! {err}")
        print("=" * 60)
