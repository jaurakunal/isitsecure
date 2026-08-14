"""Tests for stable cross-scan finding identity (#38)."""

from __future__ import annotations

from isitsecure.engine.enums import FindingCategory, SeverityLevel
from isitsecure.engine.identity import compute_fingerprint, finding_fingerprint
from isitsecure.engine.models import CodeLocation, DeepFinding, FindingSource


def _dast(title="SQL injection", url="http://localhost:3000/createdb", method="GET",
          scanner="active_injection_scanner", category=FindingCategory.INJECTION_RISK):
    return DeepFinding(
        source=FindingSource.DAST_URL, category=category, severity=SeverityLevel.HIGH,
        title=title, description="d", confidence=0.8, scanner_name=scanner,
        endpoint_url=url, http_method=method,
    )


def _sast(file_path="app/db.py", line=42, title="SQLi", scanner="semgrep_taint",
          category=FindingCategory.INJECTION_RISK):
    return DeepFinding(
        source=FindingSource.SAST_CODE, category=category, severity=SeverityLevel.HIGH,
        title=title, description="d", confidence=0.9, scanner_name=scanner,
        code_location=CodeLocation(file_path=file_path, line_number=line),
    )


class TestDASTFingerprint:
    def test_stable_across_host_port_and_query(self):
        a = _dast(url="http://localhost:3000/createdb")
        b = _dast(url="https://prod.example.com:8443/createdb?x=1&y=2")
        assert a.fingerprint == b.fingerprint

    def test_different_path_differs(self):
        assert _dast(url="http://x/createdb").fingerprint != _dast(url="http://x/login").fingerprint

    def test_different_method_differs(self):
        assert _dast(method="GET").fingerprint != _dast(method="POST").fingerprint

    def test_different_category_differs(self):
        a = _dast(category=FindingCategory.INJECTION_RISK)
        b = _dast(category=FindingCategory.AUTH_WEAKNESS)
        assert a.fingerprint != b.fingerprint


class TestSASTFingerprint:
    def test_line_agnostic(self):
        assert _sast(line=42).fingerprint == _sast(line=999).fingerprint

    def test_different_file_differs(self):
        assert _sast(file_path="a.py").fingerprint != _sast(file_path="b.py").fingerprint

    def test_sast_and_dast_never_collide(self):
        assert _sast().fingerprint != _dast().fingerprint


class TestProperties:
    def test_stable_across_instances_despite_random_id(self):
        a, b = _dast(), _dast()
        assert a.id != b.id  # per-scan random
        assert a.fingerprint == b.fingerprint  # but stable identity

    def test_serialized_in_model_dump(self):
        d = _dast().model_dump(mode="json")
        assert d.get("fingerprint") == _dast().fingerprint
        assert len(d["fingerprint"]) == 16

    def test_finding_without_locus_is_deterministic(self):
        f = DeepFinding(
            source=FindingSource.DAST_URL, category=FindingCategory.MISSING_HEADERS,
            severity=SeverityLevel.LOW, title="Missing header", description="d",
            confidence=0.5, scanner_name="security_headers_scanner",
        )
        assert f.fingerprint == f.fingerprint
        assert len(f.fingerprint) == 16


def test_compute_fingerprint_matches_finding_helper():
    f = _dast()
    assert finding_fingerprint(f) == compute_fingerprint(
        scanner_name=f.scanner_name, category=f.category, title=f.title,
        endpoint_url=f.endpoint_url, http_method=f.http_method,
    )


class TestVolatileTitleStability:
    """Regression for #38-C1: titles that interpolate the full URL or a run-to-run
    count must NOT destabilise the fingerprint across environments/runs."""

    def test_title_with_full_url_is_environment_stable(self):
        from isitsecure.engine.constants import TemplateInjectionConfig as SSTI
        t_local = SSTI.TITLE_SSTI.format(engine="jinja2", param="name",
                                         url="http://localhost:3000/render?x=1")
        t_prod = SSTI.TITLE_SSTI.format(engine="jinja2", param="name",
                                        url="https://prod.example.com:8443/render?x=99")
        fp = lambda title, url: compute_fingerprint(  # noqa: E731
            scanner_name="active_injection_scanner", category=FindingCategory.INJECTION_RISK,
            title=title, endpoint_url=url, http_method="POST")
        assert fp(t_local, "http://localhost:3000/render?x=1") == \
               fp(t_prod, "https://prod.example.com:8443/render?x=99")

    def test_verbose_error_title_is_environment_stable(self):
        from isitsecure.engine.constants import HTTPProbeConfig
        a = HTTPProbeConfig.TITLE_VERBOSE_ERROR.format(url="http://localhost:3000/api")
        b = HTTPProbeConfig.TITLE_VERBOSE_ERROR.format(url="http://prod:80/api")
        assert compute_fingerprint(scanner_name="http_probe_scanner",
                                   category=FindingCategory.INFO_DISCLOSURE, title=a,
                                   endpoint_url="http://localhost:3000/api", http_method="GET") == \
               compute_fingerprint(scanner_name="http_probe_scanner",
                                   category=FindingCategory.INFO_DISCLOSURE, title=b,
                                   endpoint_url="http://prod:80/api", http_method="GET")

    def test_race_title_has_no_volatile_count(self):
        from isitsecure.engine.constants import RaceConditionConfig
        title = RaceConditionConfig.TITLE_RACE_CONDITION.format(method="POST", path="/buy")
        assert "{count}" not in title and "succeeds concurrently" in title

    def test_different_paths_still_distinct_after_normalization(self):
        a = compute_fingerprint(scanner_name="s", category="c", title="Verbose error page at http://x/a")
        b = compute_fingerprint(scanner_name="s", category="c", title="Verbose error page at http://x/b")
        assert a != b


def test_fingerprint_survives_model_dump_roundtrip():
    """The server layers reload findings via model_validate; the extra computed
    field must be ignored and the fingerprint recompute unchanged."""
    f = _dast()
    reloaded = DeepFinding.model_validate(f.model_dump(mode="json"))
    assert reloaded.fingerprint == f.fingerprint
