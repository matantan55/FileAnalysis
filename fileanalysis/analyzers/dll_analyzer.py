"""Dedicated DLL analyzer — extends PE analysis with DLL-specific threat detection."""

from __future__ import annotations

import os

import pefile

from fileanalysis.analyzers.base import (
    AnalysisResult,
    BaseAnalyzer,
    Indicator,
    ThreatCategory,
)


# Known DLL names commonly targeted for DLL hijacking / search order abuse.
# These are legitimate Windows DLLs that are frequently impersonated.
HIJACKABLE_DLLS = {
    # Common side-loading targets
    "version.dll", "dbghelp.dll", "dbgcore.dll", "winmm.dll",
    "wintrust.dll", "msvcp140.dll", "vcruntime140.dll",
    "msvcr100.dll", "msvcr120.dll",
    "dwmapi.dll", "uxtheme.dll", "propsys.dll",
    "profapi.dll", "cryptbase.dll", "cryptsp.dll",
    "dpapi.dll", "dwrite.dll", "iphlpapi.dll",
    "netapi32.dll", "samcli.dll", "srvcli.dll",
    "userenv.dll", "winnsi.dll", "wtsapi32.dll",
    "shfolder.dll", "linkinfo.dll", "ntshrui.dll",
    "cscapi.dll", "netutils.dll",
    "WINSTA.dll", "slc.dll",
    # Frequently used in search-order hijacking
    "amsi.dll", "clr.dll", "comsvcs.dll",
    "diasymreader.dll", "faultrep.dll",
    "msfte.dll", "mshtml.dll", "mstscax.dll",
    "oleacc.dll", "pcwum.dll", "secur32.dll",
    "sxs.dll", "wbemcomn.dll", "windowscodecs.dll",
    "wkscli.dll", "wow64log.dll",
}

# Windows Known DLLs — these are loaded from System32 exclusively.
# A DLL claiming to be one of these from a non-system path is suspicious.
KNOWN_DLLS = {
    "advapi32.dll", "clbcatq.dll", "combase.dll", "comdlg32.dll",
    "coml2.dll", "difxapi.dll", "gdi32.dll", "gdiplus.dll",
    "imagehlp.dll", "imm32.dll", "kernel32.dll", "lz32.dll",
    "msctf.dll", "msi.dll", "msvcrt.dll", "normaliz.dll",
    "nsi.dll", "ntdll.dll", "ole32.dll", "oleaut32.dll",
    "psapi.dll", "rpcrt4.dll", "sechost.dll", "setupapi.dll",
    "shell32.dll", "shlwapi.dll", "sspicli.dll", "user32.dll",
    "ws2_32.dll", "wldap32.dll",
}

# Suspicious export function names
SUSPICIOUS_EXPORTS = {
    # Reflective DLL injection
    "ReflectiveLoader": (0.9, "Reflective DLL injection loader — loads the DLL from memory without touching disk"),
    "reflectiveloader": (0.9, "Reflective DLL injection loader"),
    "_ReflectiveLoader@4": (0.9, "Reflective DLL injection loader (stdcall)"),
    # COM registration (persistence vector)
    "DllRegisterServer": (0.4, "COM server registration — can be used for persistence via regsvr32"),
    "DllUnregisterServer": (0.3, "COM server unregistration"),
    "DllGetClassObject": (0.3, "COM class factory — indicates COM object implementation"),
    "DllCanUnloadNow": (0.2, "COM lifecycle management"),
    # Service DLL
    "ServiceMain": (0.5, "Windows service entry point — may install as a persistent service"),
    "SvchostPushServiceGlobals": (0.7, "Svchost service registration — often used by malware for stealthy persistence"),
    # Rundll32 compatible
    "Control_RunDLL": (0.4, "Control Panel applet entry — can be invoked via rundll32"),
    "DllInstall": (0.4, "DLL installation entry — can be invoked via regsvr32 /i"),
    # Shellcode / exploit
    "DllMain": (0.1, "Standard DLL entry point"),
    "StartW": (0.3, "Alternative entry point — sometimes used with rundll32"),
    "Start": (0.3, "Alternative entry point"),
    "_Start@16": (0.3, "Alternative entry point (stdcall)"),
}


class DLLAnalyzer(BaseAnalyzer):
    """Analyzes DLL files for DLL-specific threat vectors beyond standard PE analysis."""

    @property
    def name(self) -> str:
        return "DLL Analyzer"

    def analyze(self, file_path: str, file_bytes: bytes, result: AnalysisResult) -> None:
        """Run DLL-specific analysis."""

        try:
            pe = pefile.PE(file_path, fast_load=False)
        except Exception as e:
            result.errors.append(f"DLL parsing error: {e}")
            return

        # Confirm this is actually a DLL
        is_dll = bool(pe.FILE_HEADER.Characteristics & 0x2000)
        if not is_dll:
            pe.close()
            return

        try:
            self._check_hijacking_risk(file_path, result)
            self._analyze_exports_for_threats(pe, result)
            self._detect_proxy_dll(pe, result)
            self._check_forwarded_exports(pe, result)
            self._check_rundll32_compatibility(pe, result)
            self._check_known_dll_impersonation(file_path, result)
            self._analyze_dependency_chain(pe, result)
            self._check_dllmain_indicators(pe, file_bytes, result)
        finally:
            pe.close()

    def _check_hijacking_risk(self, file_path: str, result: AnalysisResult) -> None:
        """Check if the DLL name matches known hijackable DLL names."""
        dll_name = os.path.basename(file_path).lower()

        if dll_name in HIJACKABLE_DLLS:
            result.indicators.append(Indicator(
                category=ThreatCategory.PERSISTENCE,
                name="DLL Hijacking Target Name",
                description=(
                    f"The DLL is named '{dll_name}', which is a known target for DLL "
                    "search-order hijacking. Attackers place a malicious DLL with this name "
                    "in a directory searched before the legitimate system directory."
                ),
                evidence=[
                    f"DLL name: {dll_name}",
                    "This name appears in the known hijackable DLL list",
                ],
                severity=0.7,
            ))
            result.format_info["dll_hijacking_risk"] = True
            result.format_info["dll_hijackable_name"] = dll_name

    def _analyze_exports_for_threats(self, pe, result: AnalysisResult) -> None:
        """Analyze export table for suspicious export functions."""
        if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            # DLL with no exports is itself suspicious
            result.indicators.append(Indicator(
                category=ThreatCategory.DEFENSE_EVASION,
                name="DLL Has No Exports",
                description=(
                    "This DLL has no export table. Legitimate DLLs almost always export "
                    "functions. A DLL with no exports likely executes all its logic in "
                    "DllMain on load — a common malware technique."
                ),
                evidence=["No DIRECTORY_ENTRY_EXPORT found"],
                severity=0.6,
            ))
            return

        exports = []
        suspicious_found = []

        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            name = ""
            if exp.name:
                try:
                    name = exp.name.decode("utf-8", errors="replace")
                except Exception:
                    name = f"ordinal_{exp.ordinal}"
            else:
                name = f"ordinal_{exp.ordinal}"

            exports.append(name)

            if name in SUSPICIOUS_EXPORTS:
                severity, description = SUSPICIOUS_EXPORTS[name]
                suspicious_found.append((name, severity, description))

        result.format_info["dll_exports"] = exports
        result.format_info["dll_export_count"] = len(exports)

        for func_name, severity, description in suspicious_found:
            result.indicators.append(Indicator(
                category=ThreatCategory.EXECUTION,
                name=f"Suspicious DLL Export: {func_name}",
                description=description,
                evidence=[f"Exported function: {func_name}"],
                severity=severity,
            ))

    def _detect_proxy_dll(self, pe, result: AnalysisResult) -> None:
        """Detect proxy DLL patterns — a DLL that forwards all exports to the real DLL."""
        if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            return

        total_exports = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
        forwarded_count = 0

        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            # A forwarded export has its address pointing into the export directory
            if exp.forwarder:
                forwarded_count += 1

        if total_exports > 0 and forwarded_count > 0:
            forward_ratio = forwarded_count / total_exports

            if forward_ratio > 0.8:
                result.indicators.append(Indicator(
                    category=ThreatCategory.DEFENSE_EVASION,
                    name="Proxy DLL Detected",
                    description=(
                        f"This DLL forwards {forwarded_count}/{total_exports} "
                        f"({forward_ratio:.0%}) of its exports to another DLL. "
                        "This is a strong indicator of a proxy/shim DLL used for "
                        "DLL hijacking — it intercepts calls while forwarding them "
                        "to the legitimate DLL."
                    ),
                    evidence=[
                        f"Forwarded exports: {forwarded_count}/{total_exports}",
                        f"Forward ratio: {forward_ratio:.0%}",
                    ],
                    severity=0.85,
                ))
                result.format_info["is_proxy_dll"] = True
            elif forward_ratio > 0.3:
                result.indicators.append(Indicator(
                    category=ThreatCategory.DEFENSE_EVASION,
                    name="Partial Export Forwarding",
                    description=(
                        f"This DLL forwards {forwarded_count}/{total_exports} exports. "
                        "This may indicate selective function interception."
                    ),
                    evidence=[f"Forwarded: {forwarded_count}/{total_exports}"],
                    severity=0.5,
                ))

    def _check_forwarded_exports(self, pe, result: AnalysisResult) -> None:
        """Parse and report forwarded export details."""
        if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            return

        forwarded = []
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.forwarder:
                try:
                    forwarder_name = exp.forwarder.decode("utf-8", errors="replace")
                    export_name = (
                        exp.name.decode("utf-8", errors="replace")
                        if exp.name else f"ordinal_{exp.ordinal}"
                    )
                    forwarded.append(f"{export_name} -> {forwarder_name}")
                except Exception:
                    continue

        if forwarded:
            result.format_info["forwarded_exports"] = forwarded[:50]

    def _check_rundll32_compatibility(self, pe, result: AnalysisResult) -> None:
        """Check if the DLL has exports compatible with rundll32 execution."""
        if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            return

        rundll32_exports = []
        rundll32_patterns = [
            "Control_RunDLL", "DllInstall", "DllRegisterServer",
            "StartW", "Start", "EntryPoint", "RunDLL",
            "Execute", "Run", "Main", "Init",
        ]

        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                try:
                    name = exp.name.decode("utf-8", errors="replace")
                    for pattern in rundll32_patterns:
                        if pattern.lower() in name.lower():
                            rundll32_exports.append(name)
                            break
                except Exception:
                    continue

        if rundll32_exports:
            result.format_info["rundll32_exports"] = rundll32_exports
            result.indicators.append(Indicator(
                category=ThreatCategory.EXECUTION,
                name="Rundll32-Compatible Exports",
                description=(
                    f"Found {len(rundll32_exports)} export(s) that can be invoked via "
                    "rundll32.exe, a common malware execution technique that uses a "
                    "legitimate Windows utility to run DLL code."
                ),
                evidence=[f"rundll32.exe {pe.DIRECTORY_ENTRY_EXPORT.struct.Name},func"
                          for func in rundll32_exports[:5]],
                severity=0.4,
            ))

    def _check_known_dll_impersonation(self, file_path: str, result: AnalysisResult) -> None:
        """Check if the DLL impersonates a Windows Known DLL."""
        dll_name = os.path.basename(file_path).lower()
        dll_dir = os.path.dirname(os.path.abspath(file_path)).lower()

        if dll_name in KNOWN_DLLS:
            # Known DLLs should only be in System32
            system_paths = [
                "\\windows\\system32",
                "\\windows\\syswow64",
                "/windows/system32",
            ]
            is_system_path = any(sp in dll_dir for sp in system_paths)

            if not is_system_path:
                result.indicators.append(Indicator(
                    category=ThreatCategory.DEFENSE_EVASION,
                    name="Known DLL Impersonation",
                    description=(
                        f"This DLL is named '{dll_name}', which is a Windows Known DLL "
                        "that should only be loaded from the System32 directory. "
                        f"This file is located in '{dll_dir}', which suggests it may be "
                        "attempting to impersonate the legitimate system DLL."
                    ),
                    evidence=[
                        f"DLL name: {dll_name}",
                        f"Location: {dll_dir}",
                        "Expected: Windows\\System32",
                    ],
                    severity=0.8,
                ))

    def _analyze_dependency_chain(self, pe, result: AnalysisResult) -> None:
        """Analyze the DLL's import chain for unusual dependencies."""
        if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            return

        imported_dlls = []
        suspicious_deps = []

        # DLLs that are unusual for a DLL to import (may indicate injection tools)
        unusual_imports = {
            "dbghelp.dll": "Debug helper — may indicate memory dumping capability",
            "psapi.dll": "Process status API — used for process enumeration",
            "tlhelp32.dll": "Tool Help — used for process/thread enumeration",
            "imagehlp.dll": "Image helper — can manipulate PE files at runtime",
            "winscard.dll": "Smart card API — uncommon for most DLLs",
            "taskschd.dll": "Task scheduler — may create scheduled tasks for persistence",
            "amsi.dll": "Antimalware Scan Interface — may attempt to disable AMSI",
        }

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            try:
                dll_name = entry.dll.decode("utf-8", errors="replace").lower()
            except Exception:
                continue

            imported_dlls.append(dll_name)

            if dll_name in unusual_imports:
                suspicious_deps.append((dll_name, unusual_imports[dll_name]))

        result.format_info["dll_dependencies"] = imported_dlls

        if suspicious_deps:
            result.indicators.append(Indicator(
                category=ThreatCategory.DISCOVERY,
                name="Unusual DLL Dependencies",
                description=(
                    f"This DLL imports {len(suspicious_deps)} unusual library/libraries "
                    "that may indicate suspicious capabilities."
                ),
                evidence=[f"{dll}: {reason}" for dll, reason in suspicious_deps],
                severity=0.4,
            ))

    def _check_dllmain_indicators(self, pe, file_bytes: bytes, result: AnalysisResult) -> None:
        """Check for suspicious patterns near DllMain / entry point."""
        try:
            ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            ep_offset = pe.get_offset_from_rva(ep_rva)

            if ep_offset is None or ep_offset >= len(file_bytes) - 64:
                return

            # Get bytes around entry point
            ep_bytes = file_bytes[ep_offset:ep_offset + 128]

            # Check for thread creation at DLL load
            # CreateThread signature bytes pattern (push args, call)
            suspicious_patterns = {
                b"\x6A\x00\x6A\x00": "Thread creation with NULL parameters at entry",
                b"\xFF\x15": "Indirect call through import table at entry",
            }

            for pattern, description in suspicious_patterns.items():
                if pattern in ep_bytes[:32]:
                    result.indicators.append(Indicator(
                        category=ThreatCategory.EXECUTION,
                        name="Suspicious DllMain Entry Pattern",
                        description=(
                            f"{description}. DLLs that create threads or make significant "
                            "API calls immediately on load are often malicious."
                        ),
                        evidence=[f"Pattern at EP offset +0x{ep_bytes.find(pattern):X}"],
                        severity=0.5,
                    ))
                    break
        except Exception:
            pass
