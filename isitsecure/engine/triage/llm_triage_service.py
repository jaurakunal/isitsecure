"""LLM-powered triage service for finding deduplication and enrichment.

SRP: This service is responsible ONLY for triaging findings — deduplication,
     enrichment with impact/likelihood/priority, generating remediation
     guidance, and producing the owner summary.  It does not detect
     vulnerabilities (that's the scanners' job).

DIP: Depends on ``LLMClientProtocol`` for LLM access, not on any
     concrete LLM implementation.

Architecture:
    1. **Rule-based pre-filter** — deduplicates identical findings across
       files, auto-triages SAST findings (no LLM needed), and removes
       LOW severity noise.  This runs instantly and is the primary
       scaling mechanism.
    2. **Batched LLM dev triage** — sends remaining LLM-review findings
       in parallel batches of ~20 for enrichment.
    3. **LLM owner summary** — produces the executive summary from the
       triaged results.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from collections import defaultdict
from dataclasses import dataclass, field

from isitsecure.engine.constants import (
    ReportConfig,
    TriageConfig,
)
from isitsecure.engine.enums import (
    ImpactCategory,
    LikelihoodLevel,
    ScanMode,
)
from isitsecure.engine.models import (
    DeepFinding,
    OwnerSummary,
    RemediationPhase,
    SecurityTheme,
)
from isitsecure.engine.triage.priority_calculator import (
    calculate_priority,
)
from isitsecure.llm.protocol import LLMClientProtocol
from isitsecure.engine.enums import SeverityLevel

logger = logging.getLogger(__name__)


@dataclass
class TriageResult:
    """Result of the triage process."""

    triaged_findings: list[DeepFinding] = field(default_factory=list)
    owner_summary: OwnerSummary = field(default_factory=OwnerSummary)
    themes: list[SecurityTheme] = field(default_factory=list)


class LLMTriageService:
    """Triages scan findings using rule-based pre-filtering and LLM enrichment.

    Pipeline:
    1. Rule-based dedup + SAST auto-triage (instant, no LLM)
    2. Batched LLM enrichment (parallel, bounded)
    3. LLM owner summary (single small call)

    Falls back to rule-based triage if any LLM call fails.
    """

    SEVERITY_MAP = {
        "CRITICAL": SeverityLevel.CRITICAL,
        "HIGH": SeverityLevel.HIGH,
        "MEDIUM": SeverityLevel.MEDIUM,
        "LOW": SeverityLevel.LOW,
    }

    IMPACT_MAP = {
        "financial": ImpactCategory.FINANCIAL,
        "data_breach": ImpactCategory.DATA_BREACH,
        "legal": ImpactCategory.LEGAL,
        "operational": ImpactCategory.OPERATIONAL,
        "reputational": ImpactCategory.REPUTATIONAL,
    }

    LIKELIHOOD_MAP = {
        "actively_exploitable": LikelihoodLevel.ACTIVELY_EXPLOITABLE,
        "requires_auth": LikelihoodLevel.REQUIRES_AUTH,
        "requires_admin": LikelihoodLevel.REQUIRES_ADMIN,
        "theoretical": LikelihoodLevel.THEORETICAL,
    }

    # SAST scanners whose findings don't need LLM enrichment
    SAST_ONLY_SCANNERS = frozenset({
        "route_auth_analyzer",
        "express_middleware_analyzer",
        "drizzle_schema_analyzer",
        "iac_scanner",
        "docker_scanner",
        "shell_script_scanner",
        "dependency_scanner",
        "firebase_rules_analyzer",
        "secret_scanner",
        "static_injection_analyzer",
    })

    # Rule-based impact mapping by category
    CATEGORY_IMPACT = {
        "exposed_secrets": ImpactCategory.DATA_BREACH,
        "dependency_vuln": ImpactCategory.OPERATIONAL,
        "unencrypted_pii": ImpactCategory.LEGAL,
        "info_disclosure": ImpactCategory.REPUTATIONAL,
        "injection_risk": ImpactCategory.DATA_BREACH,
        "auth_weakness": ImpactCategory.DATA_BREACH,
        "exposed_api_endpoint": ImpactCategory.OPERATIONAL,
    }

    # Rule-based likelihood by severity
    SEVERITY_LIKELIHOOD = {
        SeverityLevel.CRITICAL: LikelihoodLevel.ACTIVELY_EXPLOITABLE,
        SeverityLevel.HIGH: LikelihoodLevel.REQUIRES_AUTH,
        SeverityLevel.MEDIUM: LikelihoodLevel.REQUIRES_AUTH,
        SeverityLevel.LOW: LikelihoodLevel.THEORETICAL,
    }

    BATCH_SIZE = 20
    MAX_CONCURRENT_BATCHES = 3

    def __init__(self, llm_client: LLMClientProtocol) -> None:
        self._llm = llm_client

    async def triage(
        self,
        findings: list[DeepFinding],
        scan_mode: ScanMode,
        target_url: str | None = None,
        repo_url: str | None = None,
    ) -> TriageResult:
        """Triage all findings: deduplicate, enrich, prioritize, summarize."""
        if not findings:
            return TriageResult(
                triaged_findings=[],
                owner_summary=self._generate_fallback_summary(
                    [], scan_mode
                ),
            )

        target = target_url or repo_url or "unknown"

        # ---- Phase 0: Rule-based pre-filter (instant, no LLM) ----
        deduped, removed_count = self._rule_based_dedup(findings)
        sast_findings, llm_findings = self._split_by_scanner(deduped)
        self._auto_triage_sast(sast_findings)

        logger.info(
            "Pre-filter: %d → %d findings (%d deduped), "
            "%d SAST (auto-triaged), %d for LLM triage",
            len(findings),
            len(deduped),
            removed_count,
            len(sast_findings),
            len(llm_findings),
        )

        try:
            # ---- Phase 1: Batched LLM enrichment ----
            if llm_findings:
                await self._run_batched_dev_triage(
                    llm_findings, scan_mode, target
                )

            # ---- Phase 1.5: Fallback for unenriched findings ----
            # Any LLM findings that the batch didn't enrich get rule-based
            # defaults so nothing leaves triage with null impact/priority.
            self._apply_fallback_enrichment(llm_findings)
            # Also fill empty narrative fields on SAST findings
            self._apply_fallback_enrichment(sast_findings)

            all_triaged = sast_findings + llm_findings

            # ---- Phase 1.6: Severity calibration ----
            # Auto-escalate to CRITICAL if both impact and likelihood
            # indicate an actively exploitable, high-impact issue.
            self._calibrate_severity(all_triaged)

            # ---- Phase 1.7: Theme detection (non-blocking) ----
            try:
                themes = await self._detect_themes(all_triaged)
            except Exception as theme_err:
                logger.warning("Theme detection failed (non-blocking): %s", theme_err)
                themes = []

            # ---- Phase 2: Owner summary ----
            owner_summary = await self._run_owner_summary(
                all_triaged, scan_mode, target
            )

            logger.info(
                "Triage complete: %d → %d findings, %d themes",
                len(findings),
                len(all_triaged),
                len(themes),
            )
            return TriageResult(
                triaged_findings=all_triaged,
                owner_summary=owner_summary,
                themes=themes,
            )

        except Exception as e:
            logger.warning(
                TriageConfig.ERROR_TRIAGE_FAILED.format(
                    error=f"{type(e).__name__}: {str(e)}"
                )
            )
            logger.warning("Triage error details:", exc_info=True)
            # SAST findings are already triaged — return them + raw LLM findings
            all_findings = sast_findings + llm_findings
            return TriageResult(
                triaged_findings=all_findings,
                owner_summary=self._generate_fallback_summary(
                    all_findings, scan_mode
                ),
            )

    # ------------------------------------------------------------------
    # Phase 0: Rule-based pre-filter
    # ------------------------------------------------------------------

    # Stop words excluded from fuzzy title matching
    _STOP_WORDS = frozenset({
        "a", "an", "the", "in", "on", "at", "to", "for", "of", "and",
        "or", "is", "are", "not", "via", "from", "with", "without",
        "by", "any", "all", "but", "can", "may", "could", "when",
        "this", "that", "which", "after", "before",
    })

    @classmethod
    def _rule_based_dedup(
        cls,
        findings: list[DeepFinding],
    ) -> tuple[list[DeepFinding], int]:
        """Multi-pass deduplication of findings.

        Pass 1: Exact title match
        Pass 2: Same file + same line number
        Pass 3: Same scanner + same category + same file (merges
                 e.g. 6 Stripe ID findings into 1 grouped finding)
        Pass 4: Fuzzy title match across files (merges e.g.
                 "in-memory rate limiter" appearing in 3 files)

        Returns (deduped list, count of removed duplicates).
        """
        severity_rank = {
            SeverityLevel.CRITICAL: 0,
            SeverityLevel.HIGH: 1,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.LOW: 3,
        }

        def _pick_best(group: list[DeepFinding]) -> DeepFinding:
            group.sort(
                key=lambda f: (
                    severity_rank.get(f.severity, 4),
                    0 if f.scanner_name == "llm_code_reviewer" else 1,
                    -len(f.description),
                )
            )
            return group[0]

        def _merge_group(group: list[DeepFinding]) -> DeepFinding:
            """Keep the best finding and append affected items from others."""
            best = _pick_best(group)
            if len(group) > 1:
                others = [f for f in group if f.id != best.id]
                extra_items = [f.title for f in others]
                if extra_items:
                    best.description += (
                        "\n\nAlso affects: " + "; ".join(extra_items)
                    )
            return best

        removed = 0

        # Pass 1: Exact title match
        title_groups: dict[str, list[DeepFinding]] = defaultdict(list)
        for f in findings:
            title_groups[f.title.lower().strip()].append(f)

        after_p1: list[DeepFinding] = []
        for group in title_groups.values():
            after_p1.append(_pick_best(group))
            removed += len(group) - 1

        # Pass 2: Same file + same line number
        loc_groups: dict[str, list[DeepFinding]] = defaultdict(list)
        for f in after_p1:
            if f.code_location and f.code_location.line_number:
                key = f"{f.code_location.file_path}:{f.code_location.line_number}"
            else:
                key = f"__no_loc_{f.id}"
            loc_groups[key].append(f)

        after_p2: list[DeepFinding] = []
        for group in loc_groups.values():
            after_p2.append(_pick_best(group))
            removed += len(group) - 1

        # Pass 3: Same SAST scanner + same category + same file → merge
        # (collapses e.g. 6 "stripe_xxx in plaintext" into 1 finding)
        # Only applies to SAST scanners — LLM findings in the same
        # file/category are usually genuinely different issues.
        pattern_groups: dict[str, list[DeepFinding]] = defaultdict(list)
        after_p3: list[DeepFinding] = []
        for f in after_p2:
            if f.scanner_name in cls.SAST_ONLY_SCANNERS:
                file_path = f.code_location.file_path if f.code_location else "__none"
                key = f"{f.scanner_name}|{f.category.value}|{file_path}"
                pattern_groups[key].append(f)
            else:
                after_p3.append(f)

        for group in pattern_groups.values():
            if len(group) <= 2:
                after_p3.extend(group)
                continue
            # 3+ SAST findings with same scanner+category+file → merge
            after_p3.append(_merge_group(group))
            removed += len(group) - 1

        # Pass 4: Fuzzy title match across files (word overlap ≥ 60%)
        def _title_words(title: str) -> set[str]:
            words = set(re.findall(r'[a-z]{3,}', title.lower()))
            return words - cls._STOP_WORDS

        fuzzy_groups: dict[int, list[DeepFinding]] = {}
        assigned: set[str] = set()
        group_id = 0

        for i, f1 in enumerate(after_p3):
            if f1.id in assigned:
                continue
            current_group = [f1]
            assigned.add(f1.id)
            w1 = _title_words(f1.title)
            if len(w1) < 3:
                fuzzy_groups[group_id] = current_group
                group_id += 1
                continue

            for f2 in after_p3[i + 1:]:
                if f2.id in assigned:
                    continue
                w2 = _title_words(f2.title)
                if len(w2) < 3:
                    continue
                overlap = len(w1 & w2) / max(len(w1), len(w2))
                if overlap >= 0.6:
                    current_group.append(f2)
                    assigned.add(f2.id)

            fuzzy_groups[group_id] = current_group
            group_id += 1

        deduped: list[DeepFinding] = []
        for group in fuzzy_groups.values():
            if len(group) == 1:
                deduped.append(group[0])
            else:
                deduped.append(_merge_group(group))
                removed += len(group) - 1

        return deduped, removed

    def _split_by_scanner(
        self, findings: list[DeepFinding]
    ) -> tuple[list[DeepFinding], list[DeepFinding]]:
        """Split findings into SAST (auto-triageable) and LLM (needs enrichment)."""
        sast: list[DeepFinding] = []
        llm: list[DeepFinding] = []
        for f in findings:
            if f.scanner_name in self.SAST_ONLY_SCANNERS:
                sast.append(f)
            else:
                llm.append(f)
        return sast, llm

    def _auto_triage_sast(self, findings: list[DeepFinding]) -> None:
        """Apply rule-based impact/likelihood to SAST findings (no LLM)."""
        for f in findings:
            cat_str = f.category.value if hasattr(f.category, "value") else str(f.category)
            f.impact = self.CATEGORY_IMPACT.get(
                cat_str, ImpactCategory.OPERATIONAL
            )
            f.likelihood = self.SEVERITY_LIKELIHOOD.get(
                f.severity, LikelihoodLevel.THEORETICAL
            )
            f.priority = calculate_priority(f.impact, f.likelihood)

    def _apply_fallback_enrichment(
        self, findings: list[DeepFinding]
    ) -> None:
        """Apply rule-based defaults to any findings the LLM batch skipped.

        After batched triage, some findings may still have null impact
        (the LLM didn't include them in its response, or the batch
        timed out). These get the same rule-based treatment as SAST
        findings so nothing leaves triage with null priority.

        Also fills empty narrative fields (technical_detail, evidence,
        remediation_guidance) from the finding's own description so
        no field is blank in the final report.
        """
        unenriched = [f for f in findings if f.impact is None]
        if unenriched:
            logger.info(
                "Fallback enrichment: %d findings not enriched by LLM",
                len(unenriched),
            )
            self._auto_triage_sast(unenriched)

        # Fill empty narrative fields for ALL findings (SAST + LLM)
        for f in findings:
            if not f.technical_detail:
                f.technical_detail = f.description
            if not f.evidence and f.code_location and f.code_location.code_snippet:
                f.evidence = f.code_location.code_snippet
            if not f.remediation_guidance:
                f.remediation_guidance = self._category_remediation(f)

    @staticmethod
    def _calibrate_severity(findings: list[DeepFinding]) -> None:
        """Auto-escalate HIGH → CRITICAL based on impact × likelihood.

        Only escalates findings already rated HIGH by the scanner/LLM.
        MEDIUM findings are never jumped to CRITICAL — the LLM's own
        assessment that the finding is not HIGH is respected.
        """
        critical_combos = {
            (ImpactCategory.FINANCIAL, LikelihoodLevel.ACTIVELY_EXPLOITABLE),
            (ImpactCategory.DATA_BREACH, LikelihoodLevel.ACTIVELY_EXPLOITABLE),
        }
        for f in findings:
            if (
                f.severity == SeverityLevel.HIGH
                and f.impact
                and f.likelihood
                and (f.impact, f.likelihood) in critical_combos
            ):
                f.severity = SeverityLevel.CRITICAL
                f.priority = 1

    # Category-specific remediation templates
    _REMEDIATION_BY_CATEGORY = {
        "auth_weakness": (
            "Implement authorization checks to verify the requesting user "
            "has permission to perform this action on this resource. Use "
            "database-level constraints as the authoritative guard."
        ),
        "exposed_secrets": (
            "Encrypt secrets at rest using application-level encryption "
            "(e.g., AES-256-GCM) or a managed KMS. Never store raw secret "
            "values in database columns."
        ),
        "info_disclosure": (
            "Apply explicit field projection to API responses — return "
            "only the fields the client needs. Remove internal identifiers "
            "and metadata from public-facing outputs."
        ),
        "injection_risk": (
            "Validate and sanitize all user-supplied inputs before passing "
            "them to interpreters, queries, or system commands. Use "
            "parameterized queries for database access."
        ),
        "unencrypted_pii": (
            "Encrypt PII columns at rest using application-level encryption. "
            "Consider field-level encryption with a managed KMS to comply "
            "with GDPR/CCPA requirements."
        ),
        "dependency_vuln": (
            "Update the affected dependency to the latest patched version. "
            "Run `npm audit fix` or manually update the version in "
            "package.json and verify no breaking changes."
        ),
        "exposed_api_endpoint": (
            "Restrict access to this endpoint using network-level controls "
            "(firewall, security groups) or add authentication. Ensure "
            "the endpoint is not accessible from untrusted networks."
        ),
    }

    @classmethod
    def _category_remediation(cls, finding: DeepFinding) -> str:
        """Generate category-specific remediation guidance."""
        cat = finding.category.value if hasattr(finding.category, "value") else str(finding.category)
        return cls._REMEDIATION_BY_CATEGORY.get(
            cat,
            f"Review the {finding.severity.value}-severity finding and "
            f"apply the appropriate security control for this issue type.",
        )

    # ------------------------------------------------------------------
    # Phase 1.7: Theme detection
    # ------------------------------------------------------------------

    async def _detect_themes(
        self, findings: list[DeepFinding],
    ) -> list[SecurityTheme]:
        """Group findings into thematic clusters via LLM.

        Falls back to an empty list if the LLM call fails — themes
        are additive, not blocking.
        """
        if not findings or not self._llm:
            return []

        # Build a compact summary for the LLM (no full code snippets)
        findings_for_llm = []
        for f in findings:
            entry = {
                "id": f.id,
                "title": f.title,
                "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                "category": f.category.value if hasattr(f.category, "value") else str(f.category),
                "file": (f.code_location.file_path if f.code_location else ""),
            }
            if f.description:
                entry["description"] = f.description[:200]
            findings_for_llm.append(entry)

        try:
            response = await self._llm.generate_with_system(
                system_prompt=TriageConfig.THEME_DETECTION_SYSTEM_PROMPT,
                user_prompt=TriageConfig.THEME_DETECTION_USER_PROMPT.format(
                    count=len(findings_for_llm),
                    findings_json=json.dumps(findings_for_llm, indent=2),
                ),
                max_tokens=TriageConfig.MAX_TOKENS_THEME_DETECTION,
            )
        except Exception as e:
            logger.warning("Theme detection LLM call failed: %s", e)
            return []

        # Parse response
        themes = self._parse_themes(response, findings)
        logger.info("Detected %d themes across %d findings", len(themes), len(findings))
        return themes

    def _parse_themes(
        self, response: str, findings: list[DeepFinding],
    ) -> list[SecurityTheme]:
        """Parse theme detection LLM response and stamp theme_id on findings."""
        # Extract JSON from response
        json_match = re.search(r"\{[\s\S]*\}", response)
        if not json_match:
            logger.warning("No JSON found in theme detection response")
            return []

        try:
            data = json.loads(json_match.group())
        except json.JSONDecodeError as e:
            logger.warning("Failed to parse theme JSON: %s", e)
            return []

        raw_themes = data.get("themes", [])
        if not raw_themes:
            return []

        # Build a lookup for fast finding access
        finding_by_id = {f.id: f for f in findings}
        themes: list[SecurityTheme] = []

        for t in raw_themes:
            theme_id = t.get("theme_id", "")
            if not theme_id:
                continue
            fids = t.get("finding_ids", [])
            # Validate finding IDs exist
            valid_fids = [fid for fid in fids if fid in finding_by_id]

            theme = SecurityTheme(
                theme_id=theme_id,
                title=t.get("title", theme_id),
                description=t.get("description", ""),
                severity=t.get("severity", "medium"),
                finding_count=len(valid_fids),
                finding_ids=valid_fids,
            )
            themes.append(theme)

            # Stamp theme_id on each finding
            for fid in valid_fids:
                finding_by_id[fid].theme_id = theme_id

        return themes

    # ------------------------------------------------------------------
    # Phase 1: Batched LLM dev triage
    # ------------------------------------------------------------------

    async def _run_batched_dev_triage(
        self,
        findings: list[DeepFinding],
        scan_mode: ScanMode,
        target: str,
    ) -> None:
        """Enrich LLM-review findings in parallel batches.

        Modifies findings in-place with impact/likelihood/evidence.
        Removes duplicates/false positives identified by the LLM.
        """
        # Filter out LOW — not worth LLM tokens
        triageable = [
            f for f in findings if f.severity != SeverityLevel.LOW
        ]
        severity_order = {
            SeverityLevel.CRITICAL: 0,
            SeverityLevel.HIGH: 1,
            SeverityLevel.MEDIUM: 2,
        }
        triageable.sort(key=lambda f: severity_order.get(f.severity, 3))

        # Cap total findings sent to LLM
        capped = triageable[: TriageConfig.MAX_FINDINGS_PER_TRIAGE]

        if not capped:
            return

        # Split into batches
        batches: list[list[DeepFinding]] = []
        for i in range(0, len(capped), self.BATCH_SIZE):
            batches.append(capped[i : i + self.BATCH_SIZE])

        logger.info(
            "LLM triage: %d findings in %d batches (max %d concurrent)",
            len(capped),
            len(batches),
            self.MAX_CONCURRENT_BATCHES,
        )

        # Collect duplicate IDs across all batches (thread-safe via asyncio)
        all_duplicate_ids: set[str] = set()

        # Process batches with bounded concurrency
        sem = asyncio.Semaphore(self.MAX_CONCURRENT_BATCHES)

        async def _triage_batch(batch: list[DeepFinding]) -> None:
            async with sem:
                batch_dupes = await self._run_single_batch_triage(
                    batch, scan_mode, target
                )
                all_duplicate_ids.update(batch_dupes)

        await asyncio.gather(
            *[_triage_batch(b) for b in batches],
            return_exceptions=True,
        )

        # Remove LLM-identified duplicates from the parent findings list
        if all_duplicate_ids:
            before_count = len(findings)
            findings[:] = [f for f in findings if f.id not in all_duplicate_ids]
            removed = before_count - len(findings)
            if removed:
                logger.info(
                    "LLM dedup removed %d findings from %d total",
                    removed,
                    before_count,
                )

    async def _run_single_batch_triage(
        self,
        batch: list[DeepFinding],
        scan_mode: ScanMode,
        target: str,
    ) -> set[str]:
        """Run dev triage on a single batch of findings. Modifies in-place.

        Processes the LLM response:
        1. ``triaged_findings`` — enriches each finding with impact/likelihood
        2. ``duplicate_ids`` — returned to caller for batch-level removal
        3. ``merged_ids`` in each triaged finding — links related findings

        Returns:
            Set of finding IDs the LLM flagged as duplicates/false positives.
        """
        findings_json = self._serialize_findings(batch)

        user_prompt = TriageConfig.DEV_TRIAGE_USER_PROMPT.format(
            scan_mode=scan_mode.value,
            target=target,
            count=len(batch),
            findings_json=findings_json,
        )

        try:
            response = await self._llm.generate_with_system(
                system_prompt=TriageConfig.DEV_TRIAGE_SYSTEM_PROMPT,
                user_prompt=user_prompt,
                max_tokens=TriageConfig.MAX_TOKENS_PER_TRIAGE,
            )

            data = self._extract_json(response)
            if data is None:
                return set()

            findings_by_id = {f.id: f for f in batch}

            # Apply enrichment to triaged findings
            for enrichment in data.get("triaged_findings", []):
                finding_id = enrichment.get("id")
                if finding_id and finding_id in findings_by_id:
                    self._apply_enrichment(
                        findings_by_id[finding_id], enrichment
                    )
                    # Link merged findings via related_finding_ids
                    merged = enrichment.get("merged_ids", [])
                    if merged:
                        findings_by_id[finding_id].related_finding_ids.extend(
                            mid for mid in merged
                            if mid not in findings_by_id[finding_id].related_finding_ids
                        )

            # Return duplicate IDs for removal by the caller
            return set(data.get("duplicate_ids", []))

        except Exception as e:
            logger.warning("Batch triage failed (%d findings): %s", len(batch), e)
            return set()

    # ------------------------------------------------------------------
    # Phase 2: Owner summary
    # ------------------------------------------------------------------

    async def _run_owner_summary(
        self,
        triaged_findings: list[DeepFinding],
        scan_mode: ScanMode,
        target: str,
    ) -> OwnerSummary:
        """Generate plain-language executive summary via LLM."""
        summary_json = self._serialize_for_owner(triaged_findings)

        critical = sum(
            1 for f in triaged_findings
            if f.severity == SeverityLevel.CRITICAL
        )
        high = sum(
            1 for f in triaged_findings
            if f.severity == SeverityLevel.HIGH
        )
        medium = sum(
            1 for f in triaged_findings
            if f.severity == SeverityLevel.MEDIUM
        )

        user_prompt = TriageConfig.OWNER_SUMMARY_USER_PROMPT.format(
            scan_mode=scan_mode.value,
            target=target,
            total=len(triaged_findings),
            critical=critical,
            high=high,
            medium=medium,
            summary_json=summary_json,
        )

        try:
            response = await self._llm.generate_with_system(
                system_prompt=TriageConfig.OWNER_SUMMARY_SYSTEM_PROMPT,
                user_prompt=user_prompt,
                max_tokens=TriageConfig.MAX_TOKENS_OWNER_SUMMARY,
            )
            return self._parse_owner_summary_response(
                response, scan_mode, triaged_findings
            )
        except Exception as e:
            logger.warning("Owner summary LLM failed: %s", e)
            return self._generate_fallback_summary(
                triaged_findings, scan_mode
            )

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    @staticmethod
    def _serialize_findings(findings: list[DeepFinding]) -> str:
        """Serialize findings into compact JSON for the triage prompt."""
        compact = []
        for f in findings:
            entry: dict = {
                "id": f.id,
                "severity": f.severity.value,
                "category": f.category.value,
                "title": f.title,
                "description": f.description[:500],
                "scanner": f.scanner_name,
            }
            if f.code_location:
                entry["file"] = f.code_location.file_path
                entry["line"] = f.code_location.line_number
                # Shorter snippets for batched triage — save tokens
                if f.code_location.code_snippet:
                    entry["code_snippet"] = f.code_location.code_snippet[:400]
            if f.endpoint_url:
                entry["endpoint"] = f.endpoint_url
            compact.append(entry)

        return json.dumps(compact, indent=1)

    @staticmethod
    def _serialize_for_owner(findings: list[DeepFinding]) -> str:
        """Serialize triaged findings for the owner summary prompt."""
        compact = []
        for f in findings[: TriageConfig.MAX_FINDINGS_PER_TRIAGE]:
            entry: dict = {
                "severity": f.severity.value,
                "title": f.title,
            }
            if f.impact:
                entry["impact"] = f.impact.value
            if f.likelihood:
                entry["likelihood"] = f.likelihood.value
            if f.code_location:
                entry["file"] = f.code_location.file_path
            compact.append(entry)
        return json.dumps(compact, indent=1)

    # ------------------------------------------------------------------
    # Response parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_json(response: str) -> dict | None:
        """Extract JSON object from an LLM response.

        Handles invalid escape sequences that LLMs sometimes produce
        (e.g., backtick-escaped regex patterns in description fields).
        """
        json_match = re.search(r"\{.*\}", response, re.DOTALL)
        if not json_match:
            logger.warning("Triage response did not contain valid JSON")
            return None
        raw = json_match.group(0)
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            # LLMs sometimes produce invalid escapes (e.g., \` or \')
            # Replace invalid escape sequences and retry
            sanitized = re.sub(
                r'\\(?!["\\/bfnrtu])', r'\\\\', raw,
            )
            try:
                return json.loads(sanitized)
            except json.JSONDecodeError as e:
                logger.warning("Failed to parse triage JSON: %s", e)
                return None

    def _apply_enrichment(
        self, finding: DeepFinding, enrichment: dict
    ) -> None:
        """Apply LLM enrichment data to a finding."""
        impact_str = enrichment.get("impact", "")
        likelihood_str = enrichment.get("likelihood", "")

        if impact_str in self.IMPACT_MAP:
            finding.impact = self.IMPACT_MAP[impact_str]
        if likelihood_str in self.LIKELIHOOD_MAP:
            finding.likelihood = self.LIKELIHOOD_MAP[likelihood_str]

        if finding.impact and finding.likelihood:
            finding.priority = calculate_priority(
                finding.impact, finding.likelihood
            )

        if enrichment.get("technical_detail"):
            finding.technical_detail = enrichment["technical_detail"]
        if enrichment.get("evidence"):
            finding.evidence = enrichment["evidence"]
        if enrichment.get("remediation_guidance"):
            finding.remediation_guidance = enrichment["remediation_guidance"]

        severity_adj = enrichment.get("severity_adjustment")
        if severity_adj and severity_adj.upper() in self.SEVERITY_MAP:
            finding.severity = self.SEVERITY_MAP[severity_adj.upper()]

    def _parse_owner_summary_response(
        self,
        response: str,
        scan_mode: ScanMode,
        triaged_findings: list[DeepFinding] | None = None,
    ) -> OwnerSummary:
        """Parse the owner summary LLM response."""
        data = self._extract_json(response)
        if data is None:
            return self._generate_fallback_summary([], scan_mode)
        return self._parse_owner_summary(data, scan_mode, triaged_findings)

    def _parse_owner_summary(
        self,
        data: dict,
        scan_mode: ScanMode,
        triaged_findings: list[DeepFinding] | None = None,
    ) -> OwnerSummary:
        """Parse the owner summary from LLM response."""
        phases = []
        for phase_data in data.get("remediation_phases", []):
            phases.append(
                RemediationPhase(
                    phase_number=phase_data.get("phase_number", 1),
                    title=phase_data.get("title", ""),
                    description=phase_data.get("description", ""),
                )
            )

        # Wire up finding_count per phase from actual triaged findings
        if triaged_findings and phases:
            self._populate_phase_counts(phases, triaged_findings)

        mode_key = scan_mode.value if scan_mode else "code_only"

        return OwnerSummary(
            grade=data.get("grade", ""),
            grade_label=ReportConfig.GRADE_LABELS.get(
                data.get("grade", ""), ""
            ),
            risk_summary=data.get(
                "risk_summary", TriageConfig.FALLBACK_RISK_SUMMARY
            ),
            key_risks=data.get("key_risks", [])[:5],  # Cap at 5
            remediation_phases=phases,
            scope_disclaimer=TriageConfig.SCOPE_DISCLAIMERS.get(
                mode_key, ""
            ),
            what_this_report_is_not=TriageConfig.REPORT_IS_NOT.get(
                mode_key, ""
            ),
        )

    @staticmethod
    def _populate_phase_counts(
        phases: list[RemediationPhase],
        findings: list[DeepFinding],
    ) -> None:
        """Assign finding counts to remediation phases by severity.

        Each finding belongs to exactly one phase (no overlap):
        Phase 1 (Immediate): CRITICAL + HIGH severity
        Phase 2 (Short-term): MEDIUM severity
        Phase 3 (Ongoing):    LOW severity
        """
        severity_to_phase = {
            SeverityLevel.CRITICAL: 1,
            SeverityLevel.HIGH: 1,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.LOW: 3,
        }
        counts: dict[int, int] = defaultdict(int)
        for f in findings:
            phase_num = severity_to_phase.get(f.severity, 3)
            counts[phase_num] += 1

        for phase in phases:
            phase.finding_count = counts.get(phase.phase_number, 0)

    # ------------------------------------------------------------------
    # Fallback (when LLM fails)
    # ------------------------------------------------------------------

    def _generate_fallback_summary(
        self,
        findings: list[DeepFinding],
        scan_mode: ScanMode,
    ) -> OwnerSummary:
        """Generate a rule-based owner summary when LLM is unavailable."""
        critical = sum(
            1 for f in findings if f.severity == SeverityLevel.CRITICAL
        )
        high = sum(
            1 for f in findings if f.severity == SeverityLevel.HIGH
        )

        if critical == 0 and high == 0:
            grade = "A"
        elif critical == 0 and high <= ReportConfig.GRADE_B:
            grade = "B"
        elif critical == 0 and high <= ReportConfig.GRADE_C:
            grade = "C"
        elif critical <= 1 and high <= ReportConfig.GRADE_D:
            grade = "D"
        else:
            grade = "F"

        mode_key = scan_mode.value if scan_mode else "code_only"

        return OwnerSummary(
            grade=grade,
            grade_label=ReportConfig.GRADE_LABELS.get(grade, ""),
            risk_summary=(
                f"Automated analysis identified {len(findings)} issues: "
                f"{critical} critical, {high} high severity. "
                f"Review recommended."
            ),
            key_risks=[],
            remediation_phases=[],
            scope_disclaimer=TriageConfig.SCOPE_DISCLAIMERS.get(
                mode_key, ""
            ),
            what_this_report_is_not=TriageConfig.REPORT_IS_NOT.get(
                mode_key, ""
            ),
        )
