"""Windows PE (EXE/DLL) binary analyzer."""

from __future__ import annotations
from datetime import datetime, timezone
import pefile
from fileanalysis.analyzers.base import (
    AnalysisResult,
    BaseAnalyzer,
    Indicator,
    SectionInfo,
    ThreatCategory,
)
from fileanalysis.analyzers.entropy import EntropyAnalyzer


# Suspicious section names often seen in packed/malicious PE files
SUSPICIOUS_SECTION_NAMES = {
    "UPX0", "UPX1", "UPX2", ".UPX",                     # UPX packer
    ".aspack", ".adata",                                   # ASPack
    ".nsp0", ".nsp1", ".nsp2",                             # NsPack
    ".perplex",                                             # Perplex
    ".packed",                                              # Generic
    ".petite",                                              # Petite
    ".yP", ".y0da",                                         # yoda Protector
    ".themida", ".winlice",                                 # Themida
    ".vmprotect", ".vmp0", ".vmp1", ".vmp2",               # VMProtect
    ".enigma1", ".enigma2",                                 # Enigma
    ".sforce",                                              # StarForce
    ".svkp",                                                # SVK Protector
    ".MPress1", ".MPress2",                                 # MPress
    ".RLPack",                                              # RLPack
    ".ccg",                                                 # CCG packer
    ".boom",                                                # The Boomerang
    ".pec", ".pec1", ".pec2",                               # PECompact
}

# Known packer entry point signatures (first bytes at EP)
PACKER_SIGNATURES: dict[bytes, str] = {
    b"\x60\xBE": "UPX",
    b"\x83\xEC\x04\x50": "ASPack",
    b"\xEB\x06\x68": "Borland Delphi stub",
}

# Suspicious imports mapped to threat categories
IMPORT_THREAT_MAP: dict[str, tuple[ThreatCategory, str]] = {
    # Process injection
    "CreateRemoteThread": (ThreatCategory.DEFENSE_EVASION, "Process injection via remote thread creation"),
    "VirtualAllocEx": (ThreatCategory.DEFENSE_EVASION, "Remote process memory allocation (injection)"),
    "WriteProcessMemory": (ThreatCategory.DEFENSE_EVASION, "Writing to remote process memory (injection)"),
    "NtUnmapViewOfSection": (ThreatCategory.DEFENSE_EVASION, "Process hollowing technique"),
    "QueueUserAPC": (ThreatCategory.DEFENSE_EVASION, "APC injection technique"),
    # Execution
    "WinExec": (ThreatCategory.EXECUTION, "Command execution via WinExec"),
    "ShellExecuteA": (ThreatCategory.EXECUTION, "Shell command execution"),
    "ShellExecuteW": (ThreatCategory.EXECUTION, "Shell command execution"),
    "CreateProcessA": (ThreatCategory.EXECUTION, "Process creation"),
    "CreateProcessW": (ThreatCategory.EXECUTION, "Process creation"),
    "system": (ThreatCategory.EXECUTION, "C runtime system() call"),
    # Persistence
    "RegSetValueExA": (ThreatCategory.PERSISTENCE, "Registry modification for persistence"),
    "RegSetValueExW": (ThreatCategory.PERSISTENCE, "Registry modification for persistence"),
    "RegCreateKeyExA": (ThreatCategory.PERSISTENCE, "Registry key creation for persistence"),
    "CreateServiceA": (ThreatCategory.PERSISTENCE, "Service creation for persistence"),
    "CreateServiceW": (ThreatCategory.PERSISTENCE, "Service creation for persistence"),
    # Credential access
    "MiniDumpWriteDump": (ThreatCategory.CREDENTIAL_ACCESS, "Process memory dumping (LSASS credentials)"),
    "CredEnumerateA": (ThreatCategory.CREDENTIAL_ACCESS, "Credential store enumeration"),
    "LsaRetrievePrivateData": (ThreatCategory.CREDENTIAL_ACCESS, "LSA private data retrieval"),
    # Network / C2
    "InternetOpenA": (ThreatCategory.COMMAND_AND_CONTROL, "HTTP communication capability"),
    "InternetOpenW": (ThreatCategory.COMMAND_AND_CONTROL, "HTTP communication capability"),
    "HttpSendRequestA": (ThreatCategory.COMMAND_AND_CONTROL, "HTTP request sending"),
    "URLDownloadToFileA": (ThreatCategory.COMMAND_AND_CONTROL, "File download from URL"),
    "URLDownloadToFileW": (ThreatCategory.COMMAND_AND_CONTROL, "File download from URL"),
    "WSAStartup": (ThreatCategory.COMMAND_AND_CONTROL, "Winsock initialization (raw networking)"),
    # Anti-analysis
    "IsDebuggerPresent": (ThreatCategory.DEFENSE_EVASION, "Debugger detection (anti-analysis)"),
    "CheckRemoteDebuggerPresent": (ThreatCategory.DEFENSE_EVASION, "Remote debugger detection"),
    "NtQueryInformationProcess": (ThreatCategory.DEFENSE_EVASION, "Process information query (anti-debug)"),
    "OutputDebugStringA": (ThreatCategory.DEFENSE_EVASION, "Debug string output (anti-debug timing)"),
    # Privilege escalation
    "AdjustTokenPrivileges": (ThreatCategory.PRIVILEGE_ESCALATION, "Token privilege adjustment"),
    "LookupPrivilegeValueA": (ThreatCategory.PRIVILEGE_ESCALATION, "Privilege lookup for escalation"),
    "ImpersonateLoggedOnUser": (ThreatCategory.PRIVILEGE_ESCALATION, "User impersonation"),
    # Keylogging / collection
    "SetWindowsHookExA": (ThreatCategory.COLLECTION, "Keyboard/mouse hook (keylogger)"),
    "SetWindowsHookExW": (ThreatCategory.COLLECTION, "Keyboard/mouse hook (keylogger)"),
    "GetAsyncKeyState": (ThreatCategory.COLLECTION, "Keystroke capture"),
    "GetKeyState": (ThreatCategory.COLLECTION, "Keystroke capture"),
    "GetClipboardData": (ThreatCategory.COLLECTION, "Clipboard data access"),
    # Crypto
    "CryptEncrypt": (ThreatCategory.IMPACT, "Encryption capability (ransomware indicator)"),
    "CryptGenKey": (ThreatCategory.IMPACT, "Cryptographic key generation"),
    "CryptAcquireContextA": (ThreatCategory.IMPACT, "Cryptographic provider acquisition"),
    # Discovery
    "GetComputerNameA": (ThreatCategory.DISCOVERY, "Computer name enumeration"),
    "GetUserNameA": (ThreatCategory.DISCOVERY, "Username enumeration"),
    "EnumProcesses": (ThreatCategory.DISCOVERY, "Process enumeration"),
    "CreateToolhelp32Snapshot": (ThreatCategory.DISCOVERY, "System snapshot for enumeration"),
    "GetSystemInfo": (ThreatCategory.DISCOVERY, "System information gathering"),
    "NetShareEnum": (ThreatCategory.DISCOVERY, "Network share enumeration"),
}


class PEAnalyzer(BaseAnalyzer):
    """Analyzes Windows PE executables (EXE/DLL) for malware indicators."""

    @property
    def name(self) -> str:
        return "PE Analyzer"

    def analyze(self, file_path: str, file_bytes: bytes, result: AnalysisResult) -> None:
        """Run PE-specific analysis."""

        try:
            pe = pefile.PE(file_path, fast_load=False)
        except pefile.PEFormatError as e:
            result.errors.append(f"Invalid PE file: {e}")
            return
        except Exception as e:
            result.errors.append(f"PE parsing error: {e}")
            return

        try:
            self._parse_headers(pe, result)
            self._analyze_sections(pe, file_bytes, result)
            self._analyze_imports(pe, result)
            self._analyze_exports(pe, result)
            self._detect_packers(pe, file_bytes, result)
            self._check_tls_callbacks(pe, result)
            self._check_anomalies(pe, result)
            self._check_resources(pe, result)
        finally:
            pe.close()

    def _parse_headers(self, pe, result: AnalysisResult) -> None:
        """Parse PE headers for metadata."""
        info = result.format_info

        # Machine type
        machine_map = {0x14c: "i386", 0x8664: "AMD64", 0x1c0: "ARM", 0xAA64: "ARM64"}
        machine = pe.FILE_HEADER.Machine
        info["machine"] = machine_map.get(machine, f"0x{machine:X}")

        # Compilation timestamp
        try:
            ts = pe.FILE_HEADER.TimeDateStamp
            if ts > 0:
                compile_time = datetime.fromtimestamp(ts, tz=timezone.utc)
                info["compile_time"] = compile_time.strftime("%Y-%m-%d %H:%M:%S UTC")

                # Flag suspicious timestamps
                now = datetime.now(tz=timezone.utc)
                if compile_time.year < 2000 or compile_time > now:
                    result.indicators.append(Indicator(
                        category=ThreatCategory.DEFENSE_EVASION,
                        name="Suspicious Compilation Timestamp",
                        description=(
                            f"PE compilation timestamp is {info['compile_time']}, which is "
                            "likely forged (timestomping)."
                        ),
                        evidence=[f"Timestamp: {info['compile_time']}"],
                        severity=0.5,
                    ))
            else:
                info["compile_time"] = "N/A (zeroed)"
        except Exception:
            info["compile_time"] = "N/A"

        # Subsystem
        subsystem_map = {
            1: "Native", 2: "Windows GUI", 3: "Windows Console",
            7: "POSIX Console", 9: "Windows CE", 14: "EFI Application",
        }
        subsys = pe.OPTIONAL_HEADER.Subsystem
        info["subsystem"] = subsystem_map.get(subsys, f"Unknown ({subsys})")

        # DLL flag
        is_dll = bool(pe.FILE_HEADER.Characteristics & 0x2000)
        info["is_dll"] = is_dll

        # Entry point
        info["entry_point"] = f"0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:08X}"

        # Image size
        info["image_size"] = pe.OPTIONAL_HEADER.SizeOfImage

    def _analyze_sections(self, pe, file_bytes: bytes, result: AnalysisResult) -> None:
        """Analyze PE sections for suspicious characteristics."""
        for section in pe.sections:
            try:
                name = section.Name.decode("utf-8", errors="replace").strip("\x00")
            except Exception:
                name = "<unknown>"

            entropy = EntropyAnalyzer.calculate_section_entropy(section.get_data())

            # Determine permissions
            chars = section.Characteristics
            perms = ""
            if chars & 0x20000000:
                perms += "X"
            if chars & 0x40000000:
                perms += "R"
            if chars & 0x80000000:
                perms += "W"

            suspicious = False
            reason = ""

            # Check for suspicious section names
            if name in SUSPICIOUS_SECTION_NAMES:
                suspicious = True
                reason = f"Known packer section name: {name}"

            # Check for high entropy sections
            if entropy > 7.0:
                suspicious = True
                reason = (reason + "; " if reason else "") + f"Very high entropy ({entropy:.2f})"

            # Check for executable + writable
            if "X" in perms and "W" in perms:
                suspicious = True
                reason = (reason + "; " if reason else "") + "Section is both writable and executable"

            # Size mismatch
            size_ratio = section.SizeOfRawData / max(section.Misc_VirtualSize, 1)
            if section.Misc_VirtualSize > 0 and (size_ratio > 10 or size_ratio < 0.01):
                suspicious = True
                reason = (reason + "; " if reason else "") + "Unusual raw/virtual size ratio"

            sec_info = SectionInfo(
                name=name,
                virtual_size=section.Misc_VirtualSize,
                raw_size=section.SizeOfRawData,
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
                    name=f"Suspicious Section: {name}",
                    description=reason,
                    evidence=[
                        f"Entropy: {entropy:.2f}",
                        f"Permissions: {perms}",
                        f"Raw size: {section.SizeOfRawData}",
                        f"Virtual size: {section.Misc_VirtualSize}",
                    ],
                    severity=0.6,
                ))

    def _analyze_imports(self, pe, result: AnalysisResult) -> None:
        """Analyze import table for suspicious API calls."""
        if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            return

        import_list = []
        suspicious_imports = []

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            try:
                dll_name = entry.dll.decode("utf-8", errors="replace")
            except Exception:
                dll_name = "<unknown>"

            for imp in entry.imports:
                if imp.name:
                    try:
                        func_name = imp.name.decode("utf-8", errors="replace")
                    except Exception:
                        func_name = str(imp.ordinal)
                else:
                    func_name = f"ordinal_{imp.ordinal}"

                import_list.append(f"{dll_name}:{func_name}")

                if func_name in IMPORT_THREAT_MAP:
                    cat, desc = IMPORT_THREAT_MAP[func_name]
                    suspicious_imports.append((func_name, cat, desc, dll_name))

        result.format_info["imports"] = import_list
        result.format_info["import_count"] = len(import_list)

        # Group suspicious imports by category
        if suspicious_imports:
            categories: dict[ThreatCategory, list[tuple[str, str, str]]] = {}
            for func, cat, desc, dll in suspicious_imports:
                categories.setdefault(cat, []).append((func, desc, dll))

            for cat, funcs in categories.items():
                result.indicators.append(Indicator(
                    category=cat,
                    name=f"Suspicious Imports ({cat.value})",
                    description=f"Found {len(funcs)} suspicious import(s) related to {cat.value}.",
                    evidence=[f"{dll}:{func} — {desc}" for func, desc, dll in funcs[:10]],
                    severity=min(0.3 + len(funcs) * 0.1, 0.9),
                ))

    def _analyze_exports(self, pe, result: AnalysisResult) -> None:
        """Analyze export table."""
        if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            return

        exports = []
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                try:
                    exports.append(exp.name.decode("utf-8", errors="replace"))
                except Exception:
                    exports.append(f"ordinal_{exp.ordinal}")
            else:
                exports.append(f"ordinal_{exp.ordinal}")

        result.format_info["exports"] = exports
        result.format_info["export_count"] = len(exports)

    def _detect_packers(self, pe, file_bytes: bytes, result: AnalysisResult) -> None:
        """Detect known packers and protectors."""
        detected_packers = []

        # Check section names for packer signatures
        for section in pe.sections:
            try:
                name = section.Name.decode("utf-8", errors="replace").strip("\x00")
            except Exception:
                continue

            if name in SUSPICIOUS_SECTION_NAMES:
                packer_name = "Unknown packer"
                if "UPX" in name.upper():
                    packer_name = "UPX"
                elif "aspack" in name.lower():
                    packer_name = "ASPack"
                elif "themida" in name.lower() or "winlice" in name.lower():
                    packer_name = "Themida/WinLicense"
                elif "vmp" in name.lower() or "vmprotect" in name.lower():
                    packer_name = "VMProtect"
                elif "enigma" in name.lower():
                    packer_name = "Enigma Protector"
                elif "MPress" in name:
                    packer_name = "MPress"
                elif "RLPack" in name:
                    packer_name = "RLPack"
                elif "pec" in name.lower():
                    packer_name = "PECompact"
                detected_packers.append(packer_name)

        # Check entry point bytes
        try:
            ep_offset = pe.get_offset_from_rva(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
            if ep_offset and ep_offset < len(file_bytes) - 4:
                ep_bytes = file_bytes[ep_offset:ep_offset + 4]
                for sig, packer in PACKER_SIGNATURES.items():
                    if ep_bytes[:len(sig)] == sig:
                        detected_packers.append(packer)
        except Exception:
            pass

        if detected_packers:
            unique_packers = list(set(detected_packers))
            result.format_info["packers"] = unique_packers
            result.indicators.append(Indicator(
                category=ThreatCategory.DEFENSE_EVASION,
                name="Packer/Protector Detected",
                description=(
                    f"File appears to be packed with: {', '.join(unique_packers)}. "
                    "Packing is used to obfuscate code and evade static analysis."
                ),
                evidence=unique_packers,
                severity=0.6,
            ))

    def _check_tls_callbacks(self, pe, result: AnalysisResult) -> None:
        """Check for TLS callbacks (anti-debug technique)."""
        if hasattr(pe, "DIRECTORY_ENTRY_TLS"):
            try:
                callbacks = pe.DIRECTORY_ENTRY_TLS.struct
                if callbacks:
                    result.indicators.append(Indicator(
                        category=ThreatCategory.DEFENSE_EVASION,
                        name="TLS Callbacks Present",
                        description=(
                            "TLS callbacks execute before the main entry point and are "
                            "commonly used for anti-debugging and anti-analysis."
                        ),
                        evidence=["TLS directory present with callbacks"],
                        severity=0.5,
                    ))
                    result.format_info["tls_callbacks"] = True
            except Exception:
                pass

    def _check_anomalies(self, pe, result: AnalysisResult) -> None:
        """Check for structural anomalies in the PE file."""
        # Check for no imports (unusual for legitimate executables)
        if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT") or not pe.DIRECTORY_ENTRY_IMPORT:
            result.indicators.append(Indicator(
                category=ThreatCategory.DEFENSE_EVASION,
                name="No Import Table",
                description=(
                    "PE file has no import table. This is unusual for legitimate executables "
                    "and may indicate that imports are resolved dynamically to evade detection."
                ),
                evidence=["Empty or missing import directory"],
                severity=0.5,
            ))

        # Check for very few sections
        num_sections = pe.FILE_HEADER.NumberOfSections
        if num_sections <= 1:
            result.indicators.append(Indicator(
                category=ThreatCategory.DEFENSE_EVASION,
                name="Minimal Sections",
                description=(
                    f"PE file has only {num_sections} section(s). "
                    "Legitimate executables typically have 3+ sections."
                ),
                evidence=[f"Section count: {num_sections}"],
                severity=0.3,
            ))

    def _check_resources(self, pe, result: AnalysisResult) -> None:
        """Check PE resources for embedded executables or suspicious content."""
        if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            return

        resource_types = []
        embedded_pe = False

        def _walk_resources(entries, depth=0):
            nonlocal embedded_pe
            for entry in entries:
                if hasattr(entry, "directory"):
                    _walk_resources(entry.directory.entries, depth + 1)
                elif hasattr(entry, "data"):
                    try:
                        rva = entry.data.struct.OffsetToData
                        size = entry.data.struct.Size
                        data = pe.get_data(rva, min(size, 1024))
                        if data[:2] == b"MZ":
                            embedded_pe = True
                    except Exception:
                        pass

        try:
            _walk_resources(pe.DIRECTORY_ENTRY_RESOURCE.entries)
        except Exception:
            pass

        if embedded_pe:
            result.indicators.append(Indicator(
                category=ThreatCategory.DEFENSE_EVASION,
                name="Embedded PE in Resources",
                description=(
                    "A PE executable was found embedded in the file's resources. "
                    "This is a common dropper technique."
                ),
                evidence=["MZ header found in resource data"],
                severity=0.8,
            ))
