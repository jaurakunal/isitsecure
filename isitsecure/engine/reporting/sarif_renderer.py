"""Renders scan report as SARIF 2.1.0 for GitHub Code Scanning.

SARIF (Static Analysis Results Interchange Format) is understood by
GitHub, GitLab, and VS Code. Upload via:

    - uses: github/codeql-action/upload-sarif@v3
      with:
        sarif_file: results.sarif

SRP: This class converts DeepScanReport findings into SARIF JSON.
     It does not run scans or generate other report formats.
"""

from __future__ import annotations

import json
from typing import Any

from isitsecure import __version__
from isitsecure.engine.models import DeepScanReport, DeepFinding


class SARIFRenderer:
    """Converts DeepScanReport to SARIF 2.1.0 JSON."""

    SARIF_SCHEMA = (
        "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/"
        "sarif-2.1/schema/sarif-schema-2.1.0.json"
    )
    SARIF_VERSION = "2.1.0"

    # Map isitsecure severity → SARIF level
    _SEVERITY_TO_LEVEL = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }

    # Map isitsecure severity → SARIF security-severity score (0-10)
    _SEVERITY_TO_SCORE = {
        "critical": "9.5",
        "high": "8.0",
        "medium": "5.5",
        "low": "3.0",
        "info": "1.0",
    }

    def render(self, report: DeepScanReport) -> str:
        """Render a DeepScanReport as a SARIF 2.1.0 JSON string.

        Args:
            report: The completed scan report.

        Returns:
            SARIF JSON string (pretty-printed).
        """
        rules, rule_index = self._build_rules(report.findings)

        results = [
            self._build_result(finding, rule_index)
            for finding in report.findings
        ]

        sarif: dict[str, Any] = {
            "$schema": self.SARIF_SCHEMA,
            "version": self.SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "isitsecure",
                            "version": __version__,
                            "semanticVersion": __version__,
                            "informationUri": "https://isitsecure.ai",
                            "rules": rules,
                        }
                    },
                    "results": results,
                    "columnKind": "utf16CodeUnits",
                }
            ],
        }

        return json.dumps(sarif, indent=2, default=str)

    def _build_rules(
        self, findings: list[DeepFinding]
    ) -> tuple[list[dict], dict[str, int]]:
        """Build SARIF rule definitions and a rule_id → index mapping.

        Each unique (scanner_name, category) pair becomes one rule.
        """
        rules: list[dict] = []
        rule_index: dict[str, int] = {}

        for finding in findings:
            rule_id = self._rule_id(finding)
            if rule_id in rule_index:
                continue

            severity = self._severity_value(finding)
            rule_index[rule_id] = len(rules)
            rules.append({
                "id": rule_id,
                "name": self._rule_name(finding),
                "shortDescription": {
                    "text": f"{finding.scanner_name}: {finding.category.value}",
                },
                "defaultConfiguration": {
                    "level": self._SEVERITY_TO_LEVEL.get(severity, "warning"),
                },
                "properties": {
                    "tags": ["security"],
                    "security-severity": self._SEVERITY_TO_SCORE.get(severity, "5.0"),
                },
                "helpUri": f"https://github.com/jaurakunal/isitsecure/tree/main/docs/scanners",
            })

        return rules, rule_index

    def _build_result(
        self, finding: DeepFinding, rule_index: dict[str, int]
    ) -> dict:
        """Build a single SARIF result from a DeepFinding."""
        rule_id = self._rule_id(finding)
        severity = self._severity_value(finding)

        result: dict[str, Any] = {
            "ruleId": rule_id,
            "ruleIndex": rule_index.get(rule_id, 0),
            "level": self._SEVERITY_TO_LEVEL.get(severity, "warning"),
            "message": {
                "text": self._build_message(finding),
            },
        }

        # Location
        locations = self._build_locations(finding)
        if locations:
            result["locations"] = locations

        # Fingerprint for dedup across runs
        result["fingerprints"] = {
            "isitsecure/v1": finding.id,
        }

        # Properties
        result["properties"] = {
            "scanner": finding.scanner_name,
            "source": finding.source.value if hasattr(finding.source, "value") else str(finding.source),
            "confidence": finding.confidence,
        }

        if finding.priority:
            result["properties"]["priority"] = finding.priority
        if finding.impact:
            result["properties"]["impact"] = finding.impact

        return result

    def _build_locations(self, finding: DeepFinding) -> list[dict]:
        """Build SARIF location objects from a finding."""
        locations: list[dict] = []

        # Code location (SAST findings)
        if finding.code_location and finding.code_location.file_path:
            loc: dict[str, Any] = {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": finding.code_location.file_path,
                        "uriBaseId": "%SRCROOT%",
                    },
                }
            }

            if finding.code_location.line_number:
                region: dict[str, Any] = {
                    "startLine": finding.code_location.line_number,
                }
                if finding.code_location.line_end:
                    region["endLine"] = finding.code_location.line_end
                loc["physicalLocation"]["region"] = region

            if finding.code_location.code_snippet:
                loc["physicalLocation"]["region"] = loc["physicalLocation"].get("region", {})
                loc["physicalLocation"]["region"]["snippet"] = {
                    "text": finding.code_location.code_snippet[:1000],
                }

            locations.append(loc)

        # Endpoint URL (DAST findings)
        elif finding.endpoint_url:
            locations.append({
                "logicalLocations": [{
                    "fullyQualifiedName": f"{finding.http_method or 'GET'} {finding.endpoint_url}",
                    "kind": "endpoint",
                }]
            })

        return locations

    def _build_message(self, finding: DeepFinding) -> str:
        """Build a human-readable message from a finding."""
        parts = [finding.title]
        if finding.description:
            parts.append(finding.description)
        if finding.remediation_guidance:
            parts.append(f"**Remediation:** {finding.remediation_guidance}")
        return "\n\n".join(parts)

    @staticmethod
    def _rule_id(finding: DeepFinding) -> str:
        """Generate a stable rule ID from scanner name and category."""
        category = finding.category.value if hasattr(finding.category, "value") else str(finding.category)
        return f"{finding.scanner_name}/{category}"

    @staticmethod
    def _rule_name(finding: DeepFinding) -> str:
        """Generate a PascalCase rule name from the category."""
        category = finding.category.value if hasattr(finding.category, "value") else str(finding.category)
        return "".join(word.capitalize() for word in category.replace("_", " ").split())

    @staticmethod
    def _severity_value(finding: DeepFinding) -> str:
        """Extract severity as a lowercase string."""
        return finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
