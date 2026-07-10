"""Linux ELF binary analyzer."""

from __future__ import annotations
import lief
from fileanalysis.analyzers.base import (
    AnalysisResult,
    BaseAnalyzer,
    Indicator,
    SectionInfo,
    ThreatCategory,
)
from fileanalysis.analyzers.entropy import EntropyAnalyzer


# Suspicious ELF section names often related to packers or dynamic resolvers
SUSPICIOUS_ELF_SECTIONS = {
    ".upx", "UPX0", "UPX1", "UPX2",
    ".shstrtab_old", ".symtab_old", ".strtab_old",
    ".bogus",
}

# Suspicious Linux syscalls / imports
SUSPICIOUS_SYSCALLS = {
    "ptrace": (ThreatCategory.DEFENSE_EVASION, "Anti-debugging / tracing capability via ptrace"),
    "execve": (ThreatCategory.EXECUTION, "Process execution capability via execve"),
    "fork": (ThreatCategory.EXECUTION, "Process spawning / forking"),
    "system": (ThreatCategory.EXECUTION, "Command execution via system"),
    "popen": (ThreatCategory.EXECUTION, "Process execution with pipeline capture"),
    "socket": (ThreatCategory.COMMAND_AND_CONTROL, "Raw network socket creation"),
    "connect": (ThreatCategory.COMMAND_AND_CONTROL, "Outbound network connection establishment"),
    "send": (ThreatCategory.COMMAND_AND_CONTROL, "Data transmission"),
    "recv": (ThreatCategory.COMMAND_AND_CONTROL, "Data reception"),
    "listen": (ThreatCategory.COMMAND_AND_CONTROL, "Inbound network port listening (backdoor)"),
    "accept": (ThreatCategory.COMMAND_AND_CONTROL, "Inbound connection acceptance"),
    "bind": (ThreatCategory.COMMAND_AND_CONTROL, "Socket binding to port"),
    "unlink": (ThreatCategory.IMPACT, "File deletion capability (possible evasion/wiper)"),
    "rmdir": (ThreatCategory.IMPACT, "Directory deletion capability"),
    "chmod": (ThreatCategory.DEFENSE_EVASION, "File permission modification"),
    "chown": (ThreatCategory.DEFENSE_EVASION, "File ownership modification"),
    "mprotect": (ThreatCategory.DEFENSE_EVASION, "Memory protection modification (possible injection/execution)"),
    "mmap": (ThreatCategory.DEFENSE_EVASION, "Memory mapping (possible shellcode execution)"),
}


class ELFAnalyzer(BaseAnalyzer):
    """Analyzes Linux ELF binaries for malware indicators."""

    @property
    def name(self) -> str:
        return "ELF Analyzer"

    def analyze(self, file_path: str, file_bytes: bytes, result: AnalysisResult) -> None:
        """Run ELF-specific analysis."""

        try:
            # Parse ELF using lief
            binary = lief.parse(file_path)
            if not binary or not isinstance(binary, lief.ELF.Binary):
                result.errors.append("Not a valid ELF binary or failed to parse")
                return
        except Exception as e:
            result.errors.append(f"ELF parsing error: {e}")
            return

        try:
            self._parse_headers(binary, result)
            self._analyze_sections(binary, result)
            self._analyze_imports(binary, result)
            self._analyze_security_mitigations(binary, result)
        except Exception as e:
            result.errors.append(f"Error during ELF analysis: {e}")

    def _parse_headers(self, binary, result: AnalysisResult) -> None:
        """Parse ELF headers for metadata."""
        info = result.format_info

        # Machine type / architecture
        info["architecture"] = str(binary.header.machine_type)
        info["entry_point"] = f"0x{binary.entrypoint:08X}"
        info["identity_class"] = str(binary.header.identity_class)
        info["identity_data"] = str(binary.header.identity_data)
        info["object_type"] = str(binary.header.file_type)

    def _analyze_sections(self, binary, result: AnalysisResult) -> None:
        """Analyze ELF sections for suspicious patterns."""
        for section in binary.sections:
            name = section.name
            entropy = EntropyAnalyzer.calculate_section_entropy(bytes(section.content))

            # Determine permissions
            flags = section.flags
            perms = ""
            # LIEF ELF section flags
            if flags & int(lief.ELF.Section.FLAGS.EXECINSTR):
                perms += "X"
            if flags & int(lief.ELF.Section.FLAGS.ALLOC):
                perms += "R"
            if flags & int(lief.ELF.Section.FLAGS.WRITE):
                perms += "W"

            suspicious = False
            reason = ""

            # Check for suspicious section names
            if name in SUSPICIOUS_ELF_SECTIONS:
                suspicious = True
                reason = f"Suspicious section name: {name}"

            # Check for high entropy sections
            if entropy > 7.0:
                suspicious = True
                reason = (reason + "; " if reason else "") + f"Very high entropy ({entropy:.2f})"

            # Check for executable + writable
            if "X" in perms and "W" in perms:
                suspicious = True
                reason = (reason + "; " if reason else "") + "Section is both writable and executable"

            sec_info = SectionInfo(
                name=name,
                virtual_size=section.size,
                raw_size=section.original_size,
                entropy=round(entropy, 4),
                permissions=perms,
                suspicious=suspicious,
                reason=reason,
            )
            result.sections.append(sec_info)
            result.entropy.sections[name] = round(entropy, 4)

            if suspicious:
                result.indicators.append(Indicator(
                    category=ThreatCategory.DEFENSE_EVASION,
                    name=f"Suspicious ELF Section: {name}",
                    description=reason,
                    evidence=[
                        f"Entropy: {entropy:.2f}",
                        f"Permissions: {perms}",
                        f"Size: {section.size}",
                    ],
                    severity=0.6,
                ))

    def _analyze_imports(self, binary, result: AnalysisResult) -> None:
        """Analyze imported symbols and library dependencies."""
        imports = []
        suspicious_imports = []

        # Get dynamic symbols / imports
        for symbol in binary.imported_symbols:
            name = symbol.name
            imports.append(name)

            if name in SUSPICIOUS_SYSCALLS:
                cat, desc = SUSPICIOUS_SYSCALLS[name]
                suspicious_imports.append((name, cat, desc))

        result.format_info["imports"] = imports
        result.format_info["import_count"] = len(imports)

        # Get library dependencies
        libraries = [lib for lib in binary.libraries]
        result.format_info["dependencies"] = libraries

        if suspicious_imports:
            categories: dict[ThreatCategory, list[tuple[str, str]]] = {}
            for func, cat, desc in suspicious_imports:
                categories.setdefault(cat, []).append((func, desc))

            for cat, funcs in categories.items():
                result.indicators.append(Indicator(
                    category=cat,
                    name=f"Suspicious ELF Imports ({cat.value})",
                    description=f"Found {len(funcs)} suspicious import(s)/syscall(s) related to {cat.value}.",
                    evidence=[f"{func} — {desc}" for func, desc in funcs[:10]],
                    severity=min(0.3 + len(funcs) * 0.1, 0.9),
                ))

    def _analyze_security_mitigations(self, binary, result: AnalysisResult) -> None:
        """Check for standard ELF binary hardening features."""
        mitigations = {}

        # Canary check (typically presence of __stack_chk_fail symbol)
        has_canary = False
        for symbol in binary.symbols:
            if "__stack_chk_fail" in symbol.name:
                has_canary = True
                break
        mitigations["stack_canary"] = has_canary

        # NX (No Execute) check
        nx_enabled = False
        try:
            for segment in binary.segments:
                if segment.type == lief.ELF.Segment.TYPE.GNU_STACK:
                    # GNU_STACK segment flags: R, W, but not X (typically 1 | 2 = 3, execute is 4)
                    nx_enabled = not (segment.flags & int(lief.ELF.Segment.FLAGS.X))
                    break
        except Exception:
            pass
        mitigations["nx"] = nx_enabled

        # PIE (Position Independent Executable)
        mitigations["pie"] = binary.is_pie

        result.format_info["security_mitigations"] = mitigations

        # Flag missing mitigations as potential risks or characteristics of malware stubs
        missing = []
        if not nx_enabled:
            missing.append("NX (No-Execute) is disabled (stack/heap executable)")
        if not has_canary:
            missing.append("Stack Canary is missing (vulnerable to buffer overflows)")

        if missing:
            result.indicators.append(Indicator(
                category=ThreatCategory.DEFENSE_EVASION,
                name="Missing Security Mitigations",
                description="The ELF binary lacks basic compile-time hardening features, common in malware stubs.",
                evidence=missing,
                severity=0.3,
            ))
