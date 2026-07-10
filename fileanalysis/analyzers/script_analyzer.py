"""Script file analyzer for common programming/scripting languages."""

from __future__ import annotations
import re
from fileanalysis.analyzers.base import (
    AnalysisResult,
    BaseAnalyzer,
    Indicator,
    ThreatCategory,
)


# Language signatures and indicators
DANGEROUS_PATTERNS = {
    "obfuscation": [
        (re.compile(r"base64\s*\.\s*b64decode|\[System\.Convert\]::FromBase64String|atob\s*\("), "Base64 decoding routine"),
        (re.compile(r"eval\s*\(\s*([\'\"`]|String\.fromCharCode)"), "Dynamic code evaluation (eval)"),
        (re.compile(r"iex\s+|\bInvoke-Expression\b"), "PowerShell Invoke-Expression (iex) execution"),
        (re.compile(r"String\.fromCharCode|chr\s*\(|\[char\]\s*\d+"), "Character code decoding tricks"),
    ],
    "execution": [
        (re.compile(r"subprocess\s*\.\s*(?:Popen|run|call|getoutput)|os\s*\.\s*(?:system|popen)"), "Python subprocess execution"),
        (re.compile(r"WScript\s*\.\s*Shell|CreateObject\s*\(\s*[\'\"]WScript\.Shell[\'\"]\s*\)"), "ActiveX WScript.Shell execution"),
        (re.compile(r"Start-Process|New-Object\s+.*Diagnostics\.ProcessStartInfo"), "PowerShell process start"),
        (re.compile(r"shell\s*\.\s*exec|child_process\s*\.\s*(?:exec|spawn|fork)"), "NodeJS process execution"),
    ],
    "network": [
        (re.compile(r"urllib\s*\.\s*request|requests\s*\.\s*(?:get|post|request)"), "Python HTTP network client"),
        (re.compile(r"Invoke-WebRequest|Invoke-RestMethod|System\.Net\.WebClient|New-Object\s+System\.Net"), "PowerShell network request"),
        (re.compile(r"XMLHTTPRequest|fetch\s*\(|require\s*\(\s*[\'\"](?:http|https)[\'\"]\s*\)"), "JS/NodeJS network client"),
        (re.compile(r"wget\s+|curl\s+|nc\s+-e"), "Shell download/networking commands"),
    ],
    "persistence": [
        (re.compile(r"reg\s+(?:add|delete)|Set-ItemProperty\s+-Path\s+.*Run"), "Windows registry run key persistence"),
        (re.compile(r"schtasks\s*/create|New-ScheduledTaskTrigger"), "Scheduled task creation"),
        (re.compile(r"crontab\s+|/etc/cron"), "Cron job setup"),
        (re.compile(r"LaunchAgents|LaunchDaemons"), "macOS LaunchAgent/Daemon persistence"),
    ],
}


class ScriptAnalyzer(BaseAnalyzer):
    """Analyzes scripts (Python, PowerShell, Bash, JS) for malicious patterns."""

    @property
    def name(self) -> str:
        return "Script Analyzer"

    def analyze(self, file_path: str, file_bytes: bytes, result: AnalysisResult) -> None:
        """Analyze script contents."""
        try:
            content = file_bytes.decode("utf-8", errors="replace")
        except Exception:
            result.errors.append("Failed to decode script content as UTF-8 text")
            return

        detected_indicators = []

        # Run regex checks against the script content
        for category_name, patterns in DANGEROUS_PATTERNS.items():
            category_indicators = []
            for pattern, description in patterns:
                matches = pattern.findall(content)
                if matches:
                    category_indicators.append((description, len(matches), matches[:3]))

            if category_indicators:
                threat_cat = self._get_threat_category(category_name)
                evidence = []
                for desc, count, samples in category_indicators:
                    evidence.append(f"{desc} (found {count} times)")

                result.indicators.append(Indicator(
                    category=threat_cat,
                    name=f"Script Indicators: {category_name.capitalize()}",
                    description=f"Detected script patterns associated with {category_name}.",
                    evidence=evidence,
                    severity=self._get_category_severity(category_name),
                ))

    def _get_threat_category(self, category_name: str) -> ThreatCategory:
        """Map local category to ThreatCategory enum."""
        mapping = {
            "obfuscation": ThreatCategory.DEFENSE_EVASION,
            "execution": ThreatCategory.EXECUTION,
            "network": ThreatCategory.COMMAND_AND_CONTROL,
            "persistence": ThreatCategory.PERSISTENCE,
        }
        return mapping.get(category_name, ThreatCategory.EXECUTION)

    def _get_category_severity(self, category_name: str) -> float:
        """Get relative severity for category."""
        mapping = {
            "obfuscation": 0.6,
            "execution": 0.5,
            "network": 0.4,
            "persistence": 0.7,
        }
        return mapping.get(category_name, 0.5)
