"""YARA signature matching engine."""

from __future__ import annotations

import os
from pathlib import Path

import yara

from fileanalysis.analyzers.base import AnalysisResult, YaraMatch


class YaraScanner:
    """Compiles and scans files using YARA rules."""

    def __init__(self, custom_rules_dir: str | None = None):
        self.rules = None

        # Determine rules path
        # Look for default rules in current directory/rules
        rules_dir = Path(__file__).resolve().parent.parent.parent / "rules"
        if custom_rules_dir:
            rules_dir = Path(custom_rules_dir)

        self.rules = self._compile_rules(rules_dir)

    def _compile_rules(self, rules_dir: Path):
        """Compile all .yar/.yara rules found in the directory."""
        if not rules_dir.exists() or not rules_dir.is_dir():
            return None

        rule_files = {}
        for p in rules_dir.glob("**/*"):
            if p.suffix.lower() in (".yar", ".yara"):
                rule_files[str(p.relative_to(rules_dir))] = str(p)

        if not rule_files:
            return None

        try:
            return yara.compile(filepaths=rule_files)
        except Exception as e:
            # Return None or partially compiled rules if some fail
            # We can log/add errors to results at scan time
            return None

    def scan(self, file_path: str, result: AnalysisResult) -> None:
        """Scan a file using compiled rules."""
        if not self.rules:
            # Check if default empty rule can be compiled or skipped
            return

        try:
            matches = self.rules.match(filepath=file_path)
            for m in matches:
                # Extract description and severity metadata if present
                desc = m.meta.get("description", "No description provided")
                severity = m.meta.get("severity", "medium")

                # Extract matched strings
                matched_strings = []
                for s_match in m.strings:
                    if hasattr(s_match, "instances"):
                        identifier = getattr(s_match, "identifier", "$?")
                        for inst in getattr(s_match, "instances", []):
                            offset = getattr(inst, "offset", 0)
                            data = getattr(inst, "matched_data", b"")
                            try:
                                printable = data.decode("utf-8", errors="replace")
                            except Exception:
                                printable = data.hex()
                            matched_strings.append(f"{identifier} at 0x{offset:X}: {printable[:60]}")
                    else:
                        try:
                            offset, identifier, data = s_match
                            try:
                                printable = data.decode("utf-8", errors="replace")
                            except Exception:
                                printable = data.hex()
                            matched_strings.append(f"{identifier} at 0x{offset:X}: {printable[:60]}")
                        except Exception:
                            pass

                result.yara_matches.append(YaraMatch(
                    rule_name=m.rule,
                    description=desc,
                    tags=list(m.tags),
                    severity=severity,
                    matched_strings=matched_strings[:10],  # Limit to top 10
                ))
        except Exception as e:
            result.errors.append(f"YARA scan error: {e}")
