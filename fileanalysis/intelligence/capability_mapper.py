"""Maps detected indicators and APIs to higher-level threat capabilities (MITRE ATT&CK-aligned)."""

from __future__ import annotations

from fileanalysis.analyzers.base import (
    AnalysisResult,
    Capability,
    ThreatCategory,
)


# Mapping of indicators/APIs to capabilities
CAPABILITY_RULES = [
    {
        "name": "Process Injection",
        "category": ThreatCategory.DEFENSE_EVASION,
        "technique_id": "T1055",
        "description": "Injects malicious code into legitimate running processes to bypass detection.",
        "apis": ["CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory", "NtUnmapViewOfSection", "QueueUserAPC", "mach_vm_write", "task_for_pid"],
        "indicators": ["Suspicious Section", "Embedded PE in Resources"],
    },
    {
        "name": "Persistence",
        "category": ThreatCategory.PERSISTENCE,
        "technique_id": "T1547.001",
        "description": "Establishes mechanism to survive reboot/logoff.",
        "apis": ["RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "CreateServiceA", "CreateServiceW", "DllRegisterServer"],
        "indicators": ["Registry Key References", "crontab", "LaunchAgents", "launchctl"],
    },
    {
        "name": "Credential Access",
        "category": ThreatCategory.CREDENTIAL_ACCESS,
        "technique_id": "T1003",
        "description": "Extracts usernames, passwords, or hashes from the operating system memory or registry.",
        "apis": ["MiniDumpWriteDump", "CredEnumerateA", "LsaRetrievePrivateData"],
        "indicators": ["Cryptocurrency Wallet Addresses"],
    },
    {
        "name": "Command & Control",
        "category": ThreatCategory.COMMAND_AND_CONTROL,
        "technique_id": "T1071",
        "description": "Establishes outbound communication channels to receive instructions or send heartbeats.",
        "apis": ["InternetOpenA", "InternetOpenW", "HttpSendRequestA", "connect", "socket"],
        "indicators": ["URLs Detected", "IP Addresses Detected"],
    },
    {
        "name": "Exfiltration",
        "category": ThreatCategory.EXFILTRATION,
        "technique_id": "T1048",
        "description": "Sends stolen information over alternative protocols or channels.",
        "apis": ["send", "HttpSendRequestA"],
        "indicators": ["Base64 Encoded Data"],
    },
    {
        "name": "Defense Evasion",
        "category": ThreatCategory.DEFENSE_EVASION,
        "technique_id": "T1027",
        "description": "Obfuscates binary contents, disables security software, or detects analysis environments.",
        "apis": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "ptrace", "sysctl"],
        "indicators": ["High Entropy Detected", "Packer/Protector Detected", "Proxy DLL Detected", "Known DLL Impersonation"],
    },
    {
        "name": "Wiper / Ransomware Impact",
        "category": ThreatCategory.IMPACT,
        "technique_id": "T1486",
        "description": "Encrypts files or destroys system data to disrupt operations.",
        "apis": ["CryptEncrypt", "CryptGenKey"],
        "indicators": ["Cryptocurrency Wallet Addresses"],
    },
    {
        "name": "Exploitation",
        "category": ThreatCategory.EXPLOIT,
        "technique_id": "T1068",
        "description": "Exploits known software vulnerabilities for initial access or privilege escalation.",
        "apis": [],
        "indicators": ["Vulnerability/CVE References Detected"],
    },
]


class CapabilityMapper:
    """Matches APIs and indicators to compile threat capabilities and plain-English impact reports."""

    def map_capabilities(self, result: AnalysisResult) -> None:
        """Analyze indicators and APIs to construct capabilities and environment impact statement."""
        # Collate all detected APIs from strings and format info
        detected_apis = set(result.strings.api_calls)
        if "imports" in result.format_info:
            for imp in result.format_info["imports"]:
                if ":" in imp:
                    func = imp.split(":")[1]
                    detected_apis.add(func)

        # Collate indicator names
        detected_indicators = {ind.name for ind in result.indicators}

        # Check mapping rules
        mapped_caps = []
        for rule in CAPABILITY_RULES:
            matched_apis = [api for api in rule["apis"] if api in detected_apis]
            matched_indicators = [ind for ind in rule["indicators"] if any(ind in di for di in detected_indicators)]

            if matched_apis or matched_indicators:
                evidence = []
                risk_contrib = 0.0

                if matched_apis:
                    evidence.append(f"APIs: {', '.join(matched_apis)}")
                    risk_contrib += min(0.4 + len(matched_apis) * 0.1, 0.7)
                if matched_indicators:
                    evidence.append(f"Indicators: {', '.join(matched_indicators)}")
                    risk_contrib += 0.3

                mapped_caps.append(Capability(
                    category=rule["category"],
                    name=rule["name"],
                    description=rule["description"],
                    technique_id=rule["technique_id"],
                    evidence=evidence,
                    risk_contribution=min(risk_contrib, 1.0),
                ))

        result.capabilities = mapped_caps
        self._generate_environment_impact(result)

    def _generate_environment_impact(self, result: AnalysisResult) -> None:
        """Create plain-English environment impact statement based on capabilities."""
        impacts = []
        caps = {cap.name: cap for cap in result.capabilities}

        if "Defense Evasion" in caps:
            impacts.append("The file may actively evade antivirus scanners, virtual environments, or debugger utilities.")

        if "Process Injection" in caps:
            impacts.append("It can inject payloads into other running processes (like explorer.exe) to hijack system actions.")

        if "Persistence" in caps:
            impacts.append("It establishes persistence (automatic restart) by writing run keys, creating background services, or installing startup jobs.")

        if "Credential Access" in caps:
            impacts.append("It attempts to dump passwords, login credentials, or security tokens from system databases/memory.")

        if "Command & Control" in caps:
            impacts.append("It initiates remote connections to server infrastructures (C2), meaning it could receive orders or download extra packages.")

        if "Wiper / Ransomware Impact" in caps:
            impacts.append("It is capable of performing bulk file encryption (ransomware behavior) or data destruction.")

        if "Exploitation" in caps:
            impacts.append("It targets specific software vulnerabilities (CVEs) to exploit the system for access or privileges.")

        if not impacts:
            if result.indicators:
                impacts.append("The file has minor suspicious features but no explicit dangerous behavior detected.")
            else:
                impacts.append("No threat capabilities detected. The file appears standard and benign.")

        result.environment_impact = impacts
