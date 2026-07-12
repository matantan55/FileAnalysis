"""Abstract base class for all file analyzers and shared data structures."""

from __future__ import annotations
import abc
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class RiskLevel(Enum):
    """Threat risk levels."""
    CLEAN = "clean"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatCategory(Enum):
    """MITRE ATT&CK-aligned threat categories."""
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DEFENSE_EVASION = "Defense Evasion"
    CREDENTIAL_ACCESS = "Credential Access"
    DISCOVERY = "Discovery"
    LATERAL_MOVEMENT = "Lateral Movement"
    COLLECTION = "Collection"
    COMMAND_AND_CONTROL = "Command & Control"
    EXFILTRATION = "Exfiltration"
    IMPACT = "Impact"
    EXECUTION = "Execution"
    INITIAL_ACCESS = "Initial Access"
    EXPLOIT = "Exploitation"


@dataclass
class Indicator:
    """A single suspicious indicator found during analysis."""
    category: ThreatCategory
    name: str
    description: str
    evidence: list[str] = field(default_factory=list)
    severity: float = 0.0  # 0.0 - 1.0


@dataclass
class HashResult:
    """Cryptographic hash results."""
    md5: str = ""
    sha1: str = ""
    sha256: str = ""
    ssdeep: str = ""
    imphash: str = ""


@dataclass
class EntropyResult:
    """Entropy analysis results."""
    overall: float = 0.0
    sections: dict[str, float] = field(default_factory=dict)
    is_packed: bool = False


@dataclass
class StringCategory:
    """Categorized strings found in a file."""
    urls: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    file_paths: list[str] = field(default_factory=list)
    registry_keys: list[str] = field(default_factory=list)
    api_calls: list[str] = field(default_factory=list)
    email_addresses: list[str] = field(default_factory=list)
    crypto_wallets: list[str] = field(default_factory=list)
    base64_blobs: list[str] = field(default_factory=list)
    shell_commands: list[str] = field(default_factory=list)
    suspicious: list[str] = field(default_factory=list)
    cve_references: list[str] = field(default_factory=list)


@dataclass
class SectionInfo:
    """Binary section information."""
    name: str
    virtual_size: int = 0
    raw_size: int = 0
    entropy: float = 0.0
    permissions: str = ""
    suspicious: bool = False
    reason: str = ""


@dataclass
class YaraMatch:
    """A YARA rule match result."""
    rule_name: str
    description: str = ""
    tags: list[str] = field(default_factory=list)
    severity: str = "medium"
    matched_strings: list[str] = field(default_factory=list)


@dataclass
class Capability:
    """A mapped threat capability."""
    category: ThreatCategory
    name: str
    description: str
    technique_id: str = ""  # MITRE ATT&CK technique ID
    evidence: list[str] = field(default_factory=list)
    risk_contribution: float = 0.0


@dataclass
class FileMetadata:
    """Basic file metadata."""
    name: str = ""
    path: str = ""
    size: int = 0
    size_human: str = ""
    mime_type: str = ""
    file_type: str = ""
    magic_description: str = ""
    creation_time: str = ""
    modification_time: str = ""
    permissions: str = ""


@dataclass
class AnalysisResult:
    """Aggregated result from all analysis stages."""
    metadata: FileMetadata = field(default_factory=FileMetadata)
    hashes: HashResult = field(default_factory=HashResult)
    entropy: EntropyResult = field(default_factory=EntropyResult)
    strings: StringCategory = field(default_factory=StringCategory)
    sections: list[SectionInfo] = field(default_factory=list)
    indicators: list[Indicator] = field(default_factory=list)
    capabilities: list[Capability] = field(default_factory=list)
    yara_matches: list[YaraMatch] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: RiskLevel = RiskLevel.CLEAN
    format_info: dict[str, Any] = field(default_factory=dict)
    scoring_method: str = "heuristic"
    nn_score: float = 0.0
    nn_risk_level: RiskLevel = RiskLevel.CLEAN
    nn_confidence: float = 0.0
    ml_score: float = 0.0
    ml_risk_level: RiskLevel = RiskLevel.CLEAN
    ml_confidence: float = 0.0
    ensemble_score: float = 0.0
    ensemble_risk_level: RiskLevel = RiskLevel.CLEAN
    environment_impact: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    ai_summary: Optional[str] = None


class BaseAnalyzer(abc.ABC):
    """Abstract base class for all file analyzers."""

    @abc.abstractmethod
    def analyze(self, file_path: str, file_bytes: bytes, result: AnalysisResult) -> None:
        """Run analysis on the given file and populate the result.

        Args:
            file_path: Path to the file being analyzed.
            file_bytes: Raw bytes of the file.
            result: The AnalysisResult to populate with findings.
        """
        ...

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Human-readable name of this analyzer."""
        ...
