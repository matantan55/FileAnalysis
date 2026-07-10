"""VirusTotal API client for reputation checks."""

from __future__ import annotations

import os

import requests

from fileanalysis.analyzers.base import AnalysisResult, VirusTotalResult


class VirusTotalClient:
    """Performs VirusTotal database checks using file hash."""

    def __init__(self, api_key: str | None = None):
        self.api_key = api_key or os.environ.get("VT_API_KEY")
        self.enabled = bool(self.api_key)

    def lookup_hash(self, sha256_hash: str, result: AnalysisResult) -> None:
        """Lookup a file SHA-256 hash in VirusTotal."""
        if not self.enabled:
            # Silent skip if not configured
            return

        headers = {
            "x-apikey": self.api_key
        }
        url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"

        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json().get("data", {})
                attributes = data.get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})

                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                undetected = stats.get("undetected", 0)
                harmless = stats.get("harmless", 0)
                total = malicious + suspicious + undetected + harmless

                detection_ratio = f"{malicious}/{total}" if total > 0 else "0/0"
                detected = malicious > 2  # Standard consensus threshold

                # Extract top engines results
                results = attributes.get("last_analysis_results", {})
                detections = {}
                for engine, details in results.items():
                    if details.get("category") == "malicious":
                        detections[engine] = details.get("result") or "Generic"

                family = attributes.get("popular_threat_classification", {}).get("suggested_threat_label", "")

                result.virustotal = VirusTotalResult(
                    detected=detected,
                    detection_ratio=detection_ratio,
                    detections=detections,
                    malware_family=family,
                    permalink=f"https://www.virustotal.com/gui/file/{sha256_hash}",
                )
            elif response.status_code == 404:
                result.virustotal = VirusTotalResult(
                    detected=False,
                    detection_ratio="0/0 (Not Found)",
                    permalink="",
                )
            else:
                result.errors.append(f"VirusTotal API error: Status code {response.status_code}")
        except Exception as e:
            result.errors.append(f"VirusTotal lookup failed: {e}")
