"""Office and PDF document analyzer."""

from __future__ import annotations
import re
from fileanalysis.analyzers.base import (
    AnalysisResult,
    BaseAnalyzer,
    Indicator,
    ThreatCategory,
)


# Dangerous patterns inside PDF/Office documents
PDF_PATTERNS = {
    b"/JavaScript": "Embedded JavaScript execution (potential exploitation/C2)",
    b"/JS": "Embedded JavaScript execution",
    b"/OpenAction": "Automatic execution trigger on opening document",
    b"/AA": "Additional Action trigger (auto-execution on page view/hover)",
    b"/Launch": "External process execution command",
    b"/URI": "Embedded URI link (potential phishing/drive-by download)",
    b"/EmbeddedFile": "Embedded file payload (dropper technique)",
}

OFFICE_PATTERNS = {
    b"VBA_PROJECT_CUR": "Contains OLE VBA macro code",
    b"word/vbaProject.bin": "Contains OOXML VBA macro code",
    b"PROJECTwm": "VBA macro project metadata signature",
    b"AutoOpen": "VBA AutoOpen macro trigger (auto-executes on open)",
    b"Auto_Open": "VBA Auto_Open macro trigger",
    b"Document_Open": "VBA Document_Open macro trigger",
    b"Workbook_Open": "VBA Workbook_Open macro trigger",
    b"Shell": "VBA code containing Shell execution capability",
    b"WScript.Shell": "VBA code creating ActiveX WScript.Shell",
}


class DocumentAnalyzer(BaseAnalyzer):
    """Analyzes Office documents and PDFs for active content, macros, and embedded payloads."""

    @property
    def name(self) -> str:
        return "Document Analyzer"

    def analyze(self, file_path: str, file_bytes: bytes, result: AnalysisResult) -> None:
        """Run document-specific analysis."""
        mime = result.metadata.magic_description.lower()

        if "pdf" in mime or file_bytes.startswith(b"%PDF"):
            self._analyze_pdf(file_bytes, result)
        else:
            # Check for generic Office macros/active content regardless of extension
            self._analyze_office(file_bytes, result)

    def _analyze_pdf(self, file_bytes: bytes, result: AnalysisResult) -> None:
        """Scan PDF structure for indicators."""
        found = []
        for pat, desc in PDF_PATTERNS.items():
            count = file_bytes.count(pat)
            if count > 0:
                found.append((pat.decode("ascii"), count, desc))

        if found:
            evidence = [f"Pattern '{pat}' found {count} times — {desc}" for pat, count, desc in found]
            # Elevated severity if automatic execution triggers are combined with scripting
            has_script = any(pat in ("/JavaScript", "/JS") for pat, _, _ in found)
            has_trigger = any(pat in ("/OpenAction", "/AA", "/Launch") for pat, _, _ in found)
            severity = 0.85 if (has_script and has_trigger) else 0.5

            result.indicators.append(Indicator(
                category=ThreatCategory.EXECUTION,
                name="Suspicious PDF Active Content",
                description="Document contains interactive elements, scripting, or auto-run triggers.",
                evidence=evidence,
                severity=severity,
            ))

    def _analyze_office(self, file_bytes: bytes, result: AnalysisResult) -> None:
        """Scan Office document (OLE or OOXML zip) for macros and active content."""
        found = []
        for pat, desc in OFFICE_PATTERNS.items():
            count = file_bytes.count(pat)
            if count > 0:
                # Use printable representation of byte pattern
                pat_str = pat.decode("ascii", errors="replace")
                found.append((pat_str, count, desc))

        if found:
            evidence = [f"Pattern '{pat}' found {count} times — {desc}" for pat, count, desc in found]
            has_macro = any("macro" in desc or "VBA" in desc for _, _, desc in found)
            has_exec = any("Shell" in pat or "Open" in pat for pat, _, _ in found)
            severity = 0.9 if (has_macro and has_exec) else 0.6

            result.indicators.append(Indicator(
                category=ThreatCategory.EXECUTION,
                name="Office Document Macros Detected",
                description="The Office document contains macro project markers or auto-run triggers.",
                evidence=evidence,
                severity=severity,
            ))
