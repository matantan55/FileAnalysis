"""macOS Mach-O binary analyzer."""

from __future__ import annotations

import lief

from fileanalysis.analyzers.base import (
    AnalysisResult,
    BaseAnalyzer,
    Indicator,
    ThreatCategory,
)


# Suspicious macOS API imports mapped to threat categories
SUSPICIOUS_MACOS_APIS = {
    # Execution
    "system": (ThreatCategory.EXECUTION, "Command execution via system"),
    "popen": (ThreatCategory.EXECUTION, "Process execution with pipeline capture"),
    "execve": (ThreatCategory.EXECUTION, "Process execution via execve"),
    "fork": (ThreatCategory.EXECUTION, "Process spawning / forking"),
    "NSTask": (ThreatCategory.EXECUTION, "Cocoa process execution wrapper"),
    # Anti-analysis
    "ptrace": (ThreatCategory.DEFENSE_EVASION, "Anti-debugging trace control via ptrace"),
    "sysctl": (ThreatCategory.DEFENSE_EVASION, "Environment inspection (often used for VM/debugger checks)"),
    "isDebuggerPresent": (ThreatCategory.DEFENSE_EVASION, "Debugger presence check"),
    # Injection / memory manipulation
    "task_for_pid": (ThreatCategory.DEFENSE_EVASION, "Retrieving host task port (process injection pre-requisite)"),
    "mach_vm_write": (ThreatCategory.DEFENSE_EVASION, "Writing to target process memory (injection)"),
    "mach_vm_allocate": (ThreatCategory.DEFENSE_EVASION, "Allocating target process memory (injection)"),
    "thread_create_running": (ThreatCategory.DEFENSE_EVASION, "Running thread creation in remote process"),
    "vm_write": (ThreatCategory.DEFENSE_EVASION, "Process memory writing"),
    # Network
    "socket": (ThreatCategory.COMMAND_AND_CONTROL, "Raw socket creation"),
    "connect": (ThreatCategory.COMMAND_AND_CONTROL, "Network connection establishment"),
    # System manipulation
    "AuthorizationCreate": (ThreatCategory.PRIVILEGE_ESCALATION, "macOS Authorization Services privilege prompt"),
}


class MachOAnalyzer(BaseAnalyzer):
    """Analyzes macOS Mach-O binaries for malware indicators."""

    @property
    def name(self) -> str:
        return "Mach-O Analyzer"

    def analyze(self, file_path: str, file_bytes: bytes, result: AnalysisResult) -> None:
        """Run Mach-O-specific analysis."""

        try:
            # Parse Mach-O using lief
            binary = lief.parse(file_path)
            if not binary:
                result.errors.append("Not a valid Mach-O binary or failed to parse")
                return

            # Handle Mach-O fat/universal binaries
            if isinstance(binary, lief.MachO.FatBinary):
                result.format_info["is_universal"] = True
                result.format_info["slice_count"] = len(binary.binaries)
                # Analyze the first slice
                if len(binary.binaries) > 0:
                    self._analyze_single_binary(binary.binaries[0], result)
            else:
                result.format_info["is_universal"] = False
                self._analyze_single_binary(binary, result)

        except Exception as e:
            result.errors.append(f"Mach-O parsing error: {e}")

    def _analyze_single_binary(self, binary, result: AnalysisResult) -> None:
        """Analyze a parsed single Mach-O binary."""
        self._parse_headers(binary, result)
        self._analyze_sections(binary, result)
        self._analyze_imports(binary, result)
        self._check_code_signature(binary, result)

    def _parse_headers(self, binary, result: AnalysisResult) -> None:
        """Parse Mach-O headers for metadata."""
        info = result.format_info

        info["cpu_type"] = str(binary.header.cpu_type)
        info["cpu_subtype"] = binary.header.cpu_subtype
        info["file_type"] = str(binary.header.file_type)
        info["entry_point"] = f"0x{binary.entrypoint:08X}"

    def _analyze_sections(self, binary, result: AnalysisResult) -> None:
        """Analyze Mach-O segments and sections."""
        sections_list = []
        for segment in binary.segments:
            seg_name = segment.name
            for section in segment.sections:
                sec_name = section.name
                full_name = f"{seg_name}:{sec_name}"

                # Calculate entropy
                try:
                    entropy = 0.0
                    content = bytes(section.content)
                    if content:
                        from fileanalysis.analyzers.entropy import EntropyAnalyzer
                        entropy = EntropyAnalyzer.calculate_section_entropy(content)
                except Exception:
                    entropy = 0.0

                sections_list.append({
                    "name": full_name,
                    "size": section.size,
                    "entropy": round(entropy, 4),
                })
                result.entropy.sections[full_name] = round(entropy, 4)

        result.format_info["sections"] = sections_list

    def _analyze_imports(self, binary, result: AnalysisResult) -> None:
        """Analyze imported libraries and symbols."""
        imports = []
        suspicious_imports = []

        # Gather library dependencies
        libraries = []
        for command in binary.commands:
            if isinstance(command, lief.MachO.DylibCommand):
                libraries.append(command.name)
        result.format_info["dependencies"] = libraries

        # Gather imported symbols
        for symbol in binary.symbols:
            name = symbol.name
            # Strip leading underscore commonly found in macOS symbol names
            clean_name = name[1:] if name.startswith("_") else name
            imports.append(clean_name)

            if clean_name in SUSPICIOUS_MACOS_APIS:
                cat, desc = SUSPICIOUS_MACOS_APIS[clean_name]
                suspicious_imports.append((clean_name, cat, desc))

        result.format_info["imports"] = imports
        result.format_info["import_count"] = len(imports)

        if suspicious_imports:
            categories: dict[ThreatCategory, list[tuple[str, str]]] = {}
            for func, cat, desc in suspicious_imports:
                categories.setdefault(cat, []).append((func, desc))

            for cat, funcs in categories.items():
                result.indicators.append(Indicator(
                    category=cat,
                    name=f"Suspicious macOS Imports ({cat.value})",
                    description=f"Found {len(funcs)} suspicious macOS API import(s) related to {cat.value}.",
                    evidence=[f"{func} — {desc}" for func, desc in funcs[:10]],
                    severity=min(0.3 + len(funcs) * 0.1, 0.9),
                ))

    def _check_code_signature(self, binary, result: AnalysisResult) -> None:
        """Check for code signing information."""
        info = result.format_info
        has_signature = False

        # Check if code signature load command is present
        for command in binary.commands:
            if isinstance(command, lief.MachO.CodeSignature):
                has_signature = True
                break

        info["code_signed"] = has_signature

        if not has_signature:
            result.indicators.append(Indicator(
                category=ThreatCategory.DEFENSE_EVASION,
                name="Unsigned Mach-O Binary",
                description=(
                    "The Mach-O binary is not code-signed. Legitimate macOS applications "
                    "are virtually always code-signed to comply with Apple's Gatekeeper."
                ),
                evidence=["Missing CodeSignature load command"],
                severity=0.5,
            ))
