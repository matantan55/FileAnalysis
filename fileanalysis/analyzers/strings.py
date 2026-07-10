"""Intelligent string extraction and classification for malware analysis."""

from __future__ import annotations

import base64
import re

from fileanalysis.analyzers.base import (
    AnalysisResult,
    BaseAnalyzer,
    Indicator,
    StringCategory,
    ThreatCategory,
)


# Minimum string length to extract
MIN_STRING_LEN = 4
MAX_STRINGS_PER_CATEGORY = 50

# Regex patterns for categorizing strings
PATTERNS = {
    "urls": re.compile(
        r'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]{4,}',
        re.ASCII
    ),
    "ips": re.compile(
        r'\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b'
    ),
    "email_addresses": re.compile(
        r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    ),
    "file_paths_win": re.compile(
        r'[A-Z]:\\(?:[^\\\/:*?"<>|\r\n]+\\)*[^\\\/:*?"<>|\r\n]*'
    ),
    "file_paths_unix": re.compile(
        r'(?:/(?:usr|etc|var|tmp|home|opt|bin|sbin|dev|proc|sys|root|mnt|boot|lib)'
        r'(?:/[a-zA-Z0-9._-]+)+)'
    ),
    "registry_keys": re.compile(
        r'(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU|HKCC)'
        r'(?:\\[a-zA-Z0-9 _.-]+)+'
    ),
    "crypto_wallets": re.compile(
        r'\b(?:bc1[a-zA-HJ-NP-Z0-9]{39,59}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|'
        r'0x[a-fA-F0-9]{40})\b'
    ),
    "base64_blobs": re.compile(
        r'(?:[A-Za-z0-9+/]{40,}={0,2})'
    ),
}

# Suspicious shell commands and indicators
SUSPICIOUS_COMMANDS = [
    "cmd.exe", "cmd /c", "cmd /k",
    "powershell", "pwsh", "Invoke-Expression", "iex(",
    "Invoke-WebRequest", "Invoke-RestMethod",
    "System.Net.WebClient", "DownloadString", "DownloadFile",
    "Start-Process", "New-Object",
    "/bin/sh", "/bin/bash", "bash -c", "sh -c",
    "wget ", "curl ", "nc ", "ncat ",
    "chmod +x", "chmod 777",
    "/etc/shadow", "/etc/passwd",
    "eval(", "exec(",
    "base64 --decode", "base64 -d",
    "certutil -decode", "certutil -urlcache",
    "bitsadmin",
    "reg add", "reg delete",
    "schtasks", "at ",
    "net user", "net localgroup",
    "wmic ", "wscript", "cscript",
    "mshta ", "rundll32",
    "regsvr32", "InstallUtil",
    "crontab", "launchctl",
    "iptables", "ufw ",
    "rm -rf", "del /f",
    "mkfifo", "mknod",
    "nohup ", "disown",
]

# Suspicious API function names (Windows)
SUSPICIOUS_APIS = [
    "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory",
    "NtUnmapViewOfSection", "NtCreateSection",
    "CreateProcess", "ShellExecute", "WinExec",
    "OpenProcess", "ReadProcessMemory",
    "VirtualProtect", "VirtualAlloc",
    "LoadLibrary", "GetProcAddress",
    "CreateFile", "WriteFile", "DeleteFile",
    "RegSetValue", "RegCreateKey",
    "InternetOpen", "HttpSendRequest", "URLDownloadToFile",
    "WSAStartup", "connect", "send", "recv",
    "socket", "bind", "listen", "accept",
    "CreateService", "StartService",
    "SetWindowsHookEx", "GetAsyncKeyState", "GetKeyState",
    "CryptEncrypt", "CryptDecrypt", "CryptGenKey",
    "AdjustTokenPrivileges", "LookupPrivilegeValue",
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess", "NtSetInformationThread",
    "MiniDumpWriteDump",
    "LsaRetrievePrivateData",
    "CredEnumerate",
    "FindFirstFile", "FindNextFile",
    "GetSystemInfo", "GetComputerName", "GetUserName",
    "EnumProcesses", "EnumProcessModules",
    "CreateToolhelp32Snapshot", "Process32First",
]


class StringAnalyzer(BaseAnalyzer):
    """Extracts and classifies strings from files to find suspicious content."""

    @property
    def name(self) -> str:
        return "String Extractor"

    def analyze(self, file_path: str, file_bytes: bytes, result: AnalysisResult) -> None:
        """Extract and classify strings."""
        # Extract ASCII and Unicode strings
        ascii_strings = self._extract_ascii_strings(file_bytes)
        unicode_strings = self._extract_unicode_strings(file_bytes)
        all_strings = list(set(ascii_strings + unicode_strings))

        # Classify strings
        categorized = self._classify_strings(all_strings)
        result.strings = categorized

        # Check for suspicious commands
        shell_cmds = self._find_suspicious_commands(all_strings)
        result.strings.shell_commands = shell_cmds[:MAX_STRINGS_PER_CATEGORY]

        # Check for suspicious API calls
        apis = self._find_suspicious_apis(all_strings)
        result.strings.api_calls = apis[:MAX_STRINGS_PER_CATEGORY]

        # Generate indicators from findings
        self._generate_indicators(result)

    def _extract_ascii_strings(self, data: bytes) -> list[str]:
        """Extract printable ASCII strings of minimum length."""
        pattern = rb'[\x20-\x7E]{' + str(MIN_STRING_LEN).encode() + rb',}'
        matches = re.findall(pattern, data)
        return [m.decode("ascii", errors="replace") for m in matches[:5000]]

    def _extract_unicode_strings(self, data: bytes) -> list[str]:
        """Extract UTF-16LE encoded strings (common in Windows binaries)."""
        pattern = rb'(?:[\x20-\x7E]\x00){' + str(MIN_STRING_LEN).encode() + rb',}'
        matches = re.findall(pattern, data)
        results = []
        for m in matches[:2000]:
            try:
                decoded = m.decode("utf-16-le").strip("\x00")
                if len(decoded) >= MIN_STRING_LEN:
                    results.append(decoded)
            except Exception:
                continue
        return results

    def _classify_strings(self, strings: list[str]) -> StringCategory:
        """Classify strings into categories using regex patterns."""
        cat = StringCategory()
        full_text = "\n".join(strings)

        cat.urls = list(set(PATTERNS["urls"].findall(full_text)))[:MAX_STRINGS_PER_CATEGORY]
        cat.ips = self._filter_valid_ips(PATTERNS["ips"].findall(full_text))
        cat.email_addresses = list(set(
            PATTERNS["email_addresses"].findall(full_text)
        ))[:MAX_STRINGS_PER_CATEGORY]

        win_paths = PATTERNS["file_paths_win"].findall(full_text)
        unix_paths = PATTERNS["file_paths_unix"].findall(full_text)
        cat.file_paths = list(set(win_paths + unix_paths))[:MAX_STRINGS_PER_CATEGORY]

        cat.registry_keys = list(set(
            PATTERNS["registry_keys"].findall(full_text)
        ))[:MAX_STRINGS_PER_CATEGORY]
        cat.crypto_wallets = list(set(
            PATTERNS["crypto_wallets"].findall(full_text)
        ))[:MAX_STRINGS_PER_CATEGORY]

        # Validate base64 blobs — only keep those that decode to something meaningful
        b64_candidates = PATTERNS["base64_blobs"].findall(full_text)
        valid_b64 = []
        for b in b64_candidates[:100]:
            try:
                decoded = base64.b64decode(b)
                # Check if decoded content has some printable chars
                printable_ratio = sum(1 for c in decoded if 32 <= c <= 126) / max(len(decoded), 1)
                if printable_ratio > 0.4:
                    valid_b64.append(b[:80] + ("..." if len(b) > 80 else ""))
            except Exception:
                continue
        cat.base64_blobs = valid_b64[:MAX_STRINGS_PER_CATEGORY]

        return cat

    def _filter_valid_ips(self, ips: list[str]) -> list[str]:
        """Filter out invalid and common/benign IP addresses."""
        valid = set()
        benign_prefixes = ("0.", "127.", "255.", "224.", "239.")
        for ip_str in ips:
            ip_part = ip_str.split(":")[0]
            if ip_part.startswith(benign_prefixes):
                continue
            octets = ip_part.split(".")
            try:
                if all(0 <= int(o) <= 255 for o in octets):
                    valid.add(ip_str)
            except ValueError:
                continue
        return list(valid)[:MAX_STRINGS_PER_CATEGORY]

    def _find_suspicious_commands(self, strings: list[str]) -> list[str]:
        """Find strings matching known suspicious commands."""
        found = []
        for s in strings:
            s_lower = s.lower()
            for cmd in SUSPICIOUS_COMMANDS:
                if cmd.lower() in s_lower:
                    found.append(s.strip()[:200])
                    break
        return list(set(found))

    def _find_suspicious_apis(self, strings: list[str]) -> list[str]:
        """Find strings matching suspicious API function names."""
        found = []
        for s in strings:
            for api in SUSPICIOUS_APIS:
                if api in s:
                    found.append(api)
                    break
        return list(set(found))

    def _generate_indicators(self, result: AnalysisResult) -> None:
        """Generate threat indicators from string findings."""
        s = result.strings

        if s.urls:
            result.indicators.append(Indicator(
                category=ThreatCategory.COMMAND_AND_CONTROL,
                name="URLs Detected",
                description=f"Found {len(s.urls)} URL(s) embedded in the file.",
                evidence=s.urls[:5],
                severity=0.4,
            ))

        if s.ips:
            result.indicators.append(Indicator(
                category=ThreatCategory.COMMAND_AND_CONTROL,
                name="IP Addresses Detected",
                description=f"Found {len(s.ips)} IP address(es) embedded in the file.",
                evidence=s.ips[:5],
                severity=0.5,
            ))

        if s.registry_keys:
            result.indicators.append(Indicator(
                category=ThreatCategory.PERSISTENCE,
                name="Registry Key References",
                description=f"Found {len(s.registry_keys)} registry key reference(s).",
                evidence=s.registry_keys[:5],
                severity=0.5,
            ))

        if s.crypto_wallets:
            result.indicators.append(Indicator(
                category=ThreatCategory.IMPACT,
                name="Cryptocurrency Wallet Addresses",
                description=(
                    f"Found {len(s.crypto_wallets)} cryptocurrency wallet address(es). "
                    "This may indicate ransomware or crypto-miner activity."
                ),
                evidence=s.crypto_wallets[:3],
                severity=0.8,
            ))

        if s.shell_commands:
            result.indicators.append(Indicator(
                category=ThreatCategory.EXECUTION,
                name="Suspicious Shell Commands",
                description=f"Found {len(s.shell_commands)} suspicious command reference(s).",
                evidence=s.shell_commands[:5],
                severity=0.6,
            ))

        if s.api_calls:
            result.indicators.append(Indicator(
                category=ThreatCategory.EXECUTION,
                name="Suspicious API Calls",
                description=f"Found {len(s.api_calls)} suspicious API function reference(s).",
                evidence=s.api_calls[:10],
                severity=0.5,
            ))

        if s.base64_blobs:
            result.indicators.append(Indicator(
                category=ThreatCategory.DEFENSE_EVASION,
                name="Base64 Encoded Data",
                description=(
                    f"Found {len(s.base64_blobs)} base64-encoded blob(s) that decode "
                    "to meaningful content. May hide malicious payloads."
                ),
                evidence=s.base64_blobs[:3],
                severity=0.4,
            ))
