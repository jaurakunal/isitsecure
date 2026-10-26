"""Cross-references DAST and SAST findings to produce combined insights."""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlparse

from isitsecure.engine.constants import CrossRefConfig
from isitsecure.engine.models import CodeLocation, DeepFinding, FindingSource
from isitsecure.engine.enums import FindingCategory, SeverityLevel


class _SeverityOrder:
    """Maps SeverityLevel to numeric rank for comparison."""

    _ORDER: list[SeverityLevel] = [
        SeverityLevel.INFO,
        SeverityLevel.LOW,
        SeverityLevel.MEDIUM,
        SeverityLevel.HIGH,
        SeverityLevel.CRITICAL,
    ]
    _MAX_INDEX = len(_ORDER) - 1

    @classmethod
    def rank(cls, severity: SeverityLevel) -> int:
        """Return numeric rank (0 = INFO, 4 = CRITICAL)."""
        try:
            return cls._ORDER.index(severity)
        except ValueError:
            return 0

    @classmethod
    def from_rank(cls, rank: int) -> SeverityLevel:
        """Return severity for a clamped rank."""
        clamped = max(0, min(rank, cls._MAX_INDEX))
        return cls._ORDER[clamped]

    @classmethod
    def boosted(cls, sev_a: SeverityLevel, sev_b: SeverityLevel) -> SeverityLevel:
        """Return the higher of two severities, boosted by one level.

        INFO stays INFO: agreement between two informational findings is
        not a reason to turn them into a LOW finding.
        """
        higher = max(cls.rank(sev_a), cls.rank(sev_b))
        if higher == 0:
            return cls.from_rank(0)
        return cls.from_rank(higher + 1)


_WORD = re.compile(r"[a-z0-9]+")
_MIN_TOKEN = 3
_SECRET_TOKEN_MIN = 10
# Path/file words shared by almost every app; matching on them proves nothing.
_GENERIC_WORDS = frozenset({
    "api", "rest", "graphql", "www", "http", "https", "com", "app", "main",
    "index", "static", "assets", "public", "src", "lib", "routes", "route",
    "controllers", "controller", "handlers", "handler", "views", "pages",
    "server", "client", "js", "ts", "py", "json", "html", "get", "post",
    "put", "delete", "patch", "the", "and", "for", "with", "this", "that",
    "from", "not", "has", "code", "file", "line", "path", "user", "data",
})
_CAMEL_BOUNDARY = re.compile(r"([a-z0-9])([A-Z])")
_ACRONYM_BOUNDARY = re.compile(r"([A-Z]+)([A-Z][a-z])")
_ID_SEGMENT = re.compile(r"^(?:v\d+|\d+|[0-9a-f]{8,}(?:-[0-9a-f]{4,})*)$")


def _tokens(text: str) -> set[str]:
    """Lower-case identifier words, with a trailing plural 's' folded away."""
    out: set[str] = set()
    # AccountController / orderItems -> "Account Controller" / "order Items"
    text = _ACRONYM_BOUNDARY.sub(r"\1 \2", _CAMEL_BOUNDARY.sub(r"\1 \2", text))
    for word in _WORD.findall(text.lower()):
        if len(word) < _MIN_TOKEN or word in _GENERIC_WORDS:
            continue
        out.add(word[:-1] if word.endswith("s") and len(word) > _MIN_TOKEN else word)
    return out


def _endpoint_keys(url: str | None) -> set[str]:
    """Distinctive path segments and query parameter names of a live URL."""
    if not url:
        return set()
    parsed = urlparse(url)
    keys: set[str] = set()
    for seg in parsed.path.split("/"):
        if seg and not _ID_SEGMENT.match(seg.lower()):
            keys |= _tokens(seg.rsplit(".", 1)[0])
    for name, _ in parse_qsl(parsed.query):
        keys |= _tokens(name)
    return keys


def _long_tokens(text: str) -> set[str]:
    """Long opaque tokens (key material / secret fragments) in free text."""
    return {
        w for w in re.findall(r"[A-Za-z0-9_\-]{%d,}" % _SECRET_TOKEN_MIN, text)
        if not w.isalpha()
    }


def _finding_text(f: DeepFinding) -> str:
    snippet = f.code_location.code_snippet if f.code_location else ""
    return " ".join(
        part for part in (f.title, f.description, f.evidence, f.technical_detail, snippet)
        if part
    )


def findings_related(dast: DeepFinding, sast: DeepFinding) -> bool:
    """True when the SAST finding plausibly describes the DAST finding's target.

    A category match alone says nothing about whether two findings concern
    the same code, so a pair must also share either a distinctive endpoint
    word (path segment or parameter name) with the SAST finding's file
    path/description, or a long opaque token (a leaked secret) in both.
    """
    sast_words = _tokens(
        (sast.code_location.file_path if sast.code_location else "")
        + " " + _finding_text(sast)
    )
    if _endpoint_keys(dast.endpoint_url) & sast_words:
        return True
    shared = _long_tokens(_finding_text(dast)) & _long_tokens(_finding_text(sast))
    return bool(shared)


class FindingCrossReferencer:
    """Combines DAST and SAST findings for high-confidence insights.

    Cross-reference rules:
    1. Same category found by both DAST and SAST -> confirmed (boost severity)
    2. DAST: endpoint exposed + SAST: no auth on that route -> confirmed IDOR
    3. DAST: anon key works + SAST: no RLS policy -> confirmed RLS gap
    4. DAST: secret in JS + SAST: secret in git history -> confirmed leak
    """

    # Category pairs that produce cross-referenced findings.
    # Each tuple: (dast_category, sast_category, combined_title)
    CROSS_REF_PAIRS: list[tuple[FindingCategory, FindingCategory, str]] = [
        (
            FindingCategory.IDOR,
            FindingCategory.IDOR,
            CrossRefConfig.TITLE_IDOR_CONFIRMED,
        ),
        (
            FindingCategory.IDOR,
            FindingCategory.AUTH_WEAKNESS,
            CrossRefConfig.TITLE_IDOR_AUTH_MISSING,
        ),
        (
            FindingCategory.RLS_MISCONFIGURATION,
            FindingCategory.RLS_MISCONFIGURATION,
            CrossRefConfig.TITLE_RLS_GAP_CONFIRMED,
        ),
        (
            FindingCategory.EXPOSED_SECRETS,
            FindingCategory.EXPOSED_SECRETS,
            CrossRefConfig.TITLE_SECRET_EXPOSURE_CONFIRMED,
        ),
        (
            FindingCategory.EXPOSED_API_ENDPOINT,
            FindingCategory.AUTH_WEAKNESS,
            CrossRefConfig.TITLE_EXPOSED_ENDPOINT_CONFIRMED,
        ),
        (
            FindingCategory.INJECTION_RISK,
            FindingCategory.INJECTION_RISK,
            CrossRefConfig.TITLE_INJECTION_CONFIRMED,
        ),
    ]

    def cross_reference(
        self,
        dast_findings: list[DeepFinding],
        sast_findings: list[DeepFinding],
    ) -> list[DeepFinding]:
        """Match DAST and SAST findings and produce cross-ref insights.

        A pair needs a matching category AND evidence that both concern the
        same endpoint/file (``findings_related``); unrelated findings of the
        same category stay separate, unboosted findings. Each SAST finding is
        consumed at most once (first related match wins).
        """
        cross_ref_findings: list[DeepFinding] = []
        used_sast_ids: set[str] = set()

        for dast in dast_findings:
            for sast in sast_findings:
                if sast.id in used_sast_ids:
                    continue

                matched_title = self._match_pair(dast.category, sast.category)
                if matched_title is None or not findings_related(dast, sast):
                    continue

                cross_finding = self._build_cross_finding(dast, sast, matched_title)
                cross_ref_findings.append(cross_finding)
                used_sast_ids.add(sast.id)
                break  # move to next DAST finding

        return cross_ref_findings

    def _match_pair(
        self, dast_category: FindingCategory, sast_category: FindingCategory
    ) -> str | None:
        """Return combined title if the categories form a cross-ref pair, else None."""
        for dast_cat, sast_cat, title in self.CROSS_REF_PAIRS:
            if dast_category == dast_cat and sast_category == sast_cat:
                return title
        return None

    def _build_cross_finding(
        self,
        dast: DeepFinding,
        sast: DeepFinding,
        title: str,
    ) -> DeepFinding:
        """Build a unified cross-referenced finding from a DAST + SAST pair."""
        sast_detail = (
            sast.code_location.file_path
            if sast.code_location
            else sast.description[:CrossRefConfig.SAST_FALLBACK_DESCRIPTION_LIMIT]
        )
        technical_detail = (
            CrossRefConfig.TECHNICAL_DAST_PREFIX
            + (dast.evidence or dast.title)
            + CrossRefConfig.TECHNICAL_DETAIL_SEPARATOR
            + CrossRefConfig.TECHNICAL_SAST_PREFIX
            + sast_detail
        )

        return DeepFinding(
            source=FindingSource.CROSS_REFERENCED,
            category=dast.category,
            severity=_SeverityOrder.boosted(dast.severity, sast.severity),
            title=title,
            description=CrossRefConfig.DESC_DAST_SAST_CONFIRMED.format(
                dast_title=dast.title, sast_title=sast.title,
            ),
            technical_detail=technical_detail,
            evidence=CrossRefConfig.EVIDENCE_TEMPLATE.format(
                dast_scanner=dast.scanner_name, sast_scanner=sast.scanner_name,
            ),
            confidence=CrossRefConfig.CONFIDENCE_CROSS_REF,
            scanner_name=CrossRefConfig.SCANNER_NAME,
            endpoint_url=dast.endpoint_url,
            code_location=sast.code_location,
            related_finding_ids=[dast.id, sast.id],
        )
