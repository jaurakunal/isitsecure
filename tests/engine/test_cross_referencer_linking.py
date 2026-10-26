"""Cross-referencer must pair findings only when they concern the same target."""

from __future__ import annotations

from isitsecure.engine.cross_referencer import FindingCrossReferencer, _SeverityOrder
from isitsecure.engine.enums import FindingCategory, SeverityLevel
from isitsecure.engine.models import CodeLocation, DeepFinding, FindingSource


def _f(title: str, cat: FindingCategory, sev: SeverityLevel, *, src: FindingSource,
       file: str | None = None, url: str | None = None, desc: str = "d",
       evidence: str = "", snippet: str = "") -> DeepFinding:
    return DeepFinding(
        source=src, category=cat, severity=sev, title=title, description=desc,
        evidence=evidence, confidence=0.9, scanner_name="x", endpoint_url=url,
        code_location=(
            CodeLocation(file_path=file, line_number=4, code_snippet=snippet) if file else None
        ),
    )


DAST = FindingSource.DAST_URL
SAST = FindingSource.SAST_CODE


def test_unrelated_same_category_findings_are_not_paired_or_boosted() -> None:
    dast = _f("IDOR on /api/orders/1", FindingCategory.IDOR, SeverityLevel.LOW,
              src=DAST, url="http://t/api/orders/1")
    sast = _f("IDOR in admin/reports.py", FindingCategory.IDOR, SeverityLevel.CRITICAL,
              src=SAST, file="admin/reports.py")
    assert FindingCrossReferencer().cross_reference([dast], [sast]) == []


def test_related_endpoint_and_file_are_paired_and_boosted() -> None:
    dast = _f("IDOR on /api/orders/1", FindingCategory.IDOR, SeverityLevel.MEDIUM,
              src=DAST, url="http://t/api/orders/1")
    sast = _f("IDOR in orders handler", FindingCategory.IDOR, SeverityLevel.HIGH,
              src=SAST, file="src/routes/orders.py")
    out = FindingCrossReferencer().cross_reference([dast], [sast])
    assert len(out) == 1
    assert out[0].severity == SeverityLevel.CRITICAL
    assert out[0].related_finding_ids == [dast.id, sast.id]


def test_pairing_does_not_depend_on_input_order() -> None:
    d1 = _f("a", FindingCategory.IDOR, SeverityLevel.HIGH, src=DAST, url="http://t/alpha")
    d2 = _f("b", FindingCategory.IDOR, SeverityLevel.HIGH, src=DAST, url="http://t/beta")
    s1 = _f("s", FindingCategory.IDOR, SeverityLevel.HIGH, src=SAST, file="alpha.py")
    out = FindingCrossReferencer().cross_reference([d2, d1], [s1])
    assert [o.endpoint_url for o in out] == ["http://t/alpha"]


def test_generic_api_path_words_do_not_link() -> None:
    dast = _f("Exposed", FindingCategory.EXPOSED_API_ENDPOINT, SeverityLevel.MEDIUM,
              src=DAST, url="http://t/api/v1/things")
    sast = _f("Missing auth", FindingCategory.AUTH_WEAKNESS, SeverityLevel.HIGH,
              src=SAST, file="src/api/routes/other.ts")
    assert FindingCrossReferencer().cross_reference([dast], [sast]) == []


def test_secret_pair_linked_by_shared_long_token() -> None:
    token = "sk_live_51HxAbCdEfGhIjKl"
    dast = _f("Secret in JS", FindingCategory.EXPOSED_SECRETS, SeverityLevel.HIGH,
              src=DAST, url="http://t/static/main.js", evidence=f"found {token}")
    sast = _f("Stripe key in history", FindingCategory.EXPOSED_SECRETS, SeverityLevel.HIGH,
              src=FindingSource.SAST_GIT_HISTORY, file="config.py", snippet=f"KEY='{token}'")
    assert len(FindingCrossReferencer().cross_reference([dast], [sast])) == 1


def test_different_secrets_are_not_paired() -> None:
    dast = _f("Secret in JS", FindingCategory.EXPOSED_SECRETS, SeverityLevel.HIGH,
              src=DAST, url="http://t/static/main.js", evidence="sk_live_51HxAbCdEfGhIjKl")
    sast = _f("AWS key", FindingCategory.EXPOSED_SECRETS, SeverityLevel.HIGH,
              src=SAST, file="config.py", snippet="AKIAIOSFODNN7EXAMPLE")
    assert FindingCrossReferencer().cross_reference([dast], [sast]) == []


def test_info_plus_info_is_not_boosted() -> None:
    assert _SeverityOrder.boosted(SeverityLevel.INFO, SeverityLevel.INFO) == SeverityLevel.INFO
    assert _SeverityOrder.boosted(SeverityLevel.LOW, SeverityLevel.INFO) == SeverityLevel.MEDIUM
