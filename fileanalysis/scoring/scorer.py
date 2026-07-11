"""Risk scoring engine."""

from __future__ import annotations

from fileanalysis.analyzers.base import AnalysisResult, RiskLevel


class ThreatScorer:
    """Calculates weighted threat score and determines risk level."""

    def calculate_score(self, result: AnalysisResult) -> None:
        """Calculate score 0-100 and set RiskLevel."""
        score = 0.0

        # 1. Entropy component (Max 15)
        if result.entropy.is_packed:
            score += 15.0
        elif result.entropy.overall > 6.5:
            score += 10.0

        # 2. Suspicious string patterns (Max 20)
        str_points = 0.0
        if result.strings.urls:
            str_points += 5.0
        if result.strings.ips:
            str_points += 7.0
        if result.strings.crypto_wallets:
            str_points += 15.0
        if result.strings.shell_commands:
            str_points += min(len(result.strings.shell_commands) * 3, 10.0)
        score += min(str_points, 20.0)

        # 3. Capabilities / ATT&CK Mapping (Max 35)
        cap_points = sum(cap.risk_contribution * 15 for cap in result.capabilities)
        score += min(cap_points, 35.0)

        # 4. YARA Matches (Max 30)
        yara_points = 0.0
        for match in result.yara_matches:
            sev = match.severity.lower()
            if sev == "critical":
                yara_points += 30.0
            elif sev == "high":
                yara_points += 20.0
            elif sev == "medium":
                yara_points += 10.0
            else:
                yara_points += 5.0
        score += min(yara_points, 30.0)

        # Bound score 0-100
        final_score = min(max(round(score, 1), 0.0), 100.0)
        result.risk_score = final_score

        # Determine level
        if final_score <= 20.0:
            result.risk_level = RiskLevel.CLEAN
        elif final_score <= 40.0:
            result.risk_level = RiskLevel.LOW
        elif final_score <= 60.0:
            result.risk_level = RiskLevel.MODERATE
        elif final_score <= 80.0:
            result.risk_level = RiskLevel.HIGH
        else:
            result.risk_level = RiskLevel.CRITICAL
