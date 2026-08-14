"""Tests for persisted finding suppression — .isitsecureignore (#51)."""

from __future__ import annotations

from isitsecure.engine import suppression as S
from isitsecure.engine.enums import FindingCategory, SeverityLevel
from isitsecure.engine.models import DeepFinding, FindingSource


def _f(title, url):
    return DeepFinding(
        source=FindingSource.DAST_URL, category=FindingCategory.INJECTION_RISK,
        severity=SeverityLevel.HIGH, title=title, description="d", confidence=0.8,
        scanner_name="active_injection_scanner", endpoint_url=url, http_method="GET",
    )


class TestLoad:
    def test_missing_file_is_empty(self, tmp_path):
        assert S.load_suppressed_fingerprints(tmp_path / ".isitsecureignore") == set()

    def test_parses_fingerprints_and_ignores_comments(self, tmp_path):
        p = tmp_path / ".isitsecureignore"
        p.write_text(
            "# a comment\n"
            "\n"
            "abc123def4567890   # [injection_risk] GET /x — reason\n"
            "   deadbeefcafebabe\n"  # leading whitespace, no comment
            "# another comment\n"
        )
        assert S.load_suppressed_fingerprints(p) == {"abc123def4567890", "deadbeefcafebabe"}

    def test_only_first_token_is_read(self, tmp_path):
        p = tmp_path / ".isitsecureignore"
        p.write_text("abc123 extra words here\n")
        assert S.load_suppressed_fingerprints(p) == {"abc123"}


class TestPartition:
    def test_splits_by_fingerprint(self):
        f1, f2 = _f("SQLi", "http://x/a"), _f("SQLi", "http://x/b")
        active, hidden = S.partition([f1, f2], {f1.fingerprint})
        assert [f.fingerprint for f in active] == [f2.fingerprint]
        assert [f.fingerprint for f in hidden] == [f1.fingerprint]

    def test_empty_suppression_keeps_all(self):
        fs = [_f("SQLi", "http://x/a"), _f("SQLi", "http://x/b")]
        active, hidden = S.partition(fs, set())
        assert len(active) == 2 and hidden == []


class TestAddSuppressions:
    def test_creates_file_with_header_and_entry(self, tmp_path):
        p = tmp_path / ".isitsecureignore"
        f = _f("SQL injection", "http://x/createdb")
        newly = S.add_suppressions(p, [f], [f.fingerprint], reason="benign")
        assert [x.fingerprint for x in newly] == [f.fingerprint]
        text = p.read_text()
        assert text.startswith("# isitsecure suppressions")
        assert f.fingerprint in text
        assert "benign" in text and "createdb" in text
        # round-trips
        assert S.load_suppressed_fingerprints(p) == {f.fingerprint}

    def test_idempotent(self, tmp_path):
        p = tmp_path / ".isitsecureignore"
        f = _f("SQLi", "http://x/a")
        S.add_suppressions(p, [f], [f.fingerprint])
        before = p.read_text()
        assert S.add_suppressions(p, [f], [f.fingerprint]) == []
        assert p.read_text() == before  # nothing appended

    def test_unknown_fingerprint_skipped(self, tmp_path):
        p = tmp_path / ".isitsecureignore"
        f = _f("SQLi", "http://x/a")
        assert S.add_suppressions(p, [f], ["notinthisscan00"]) == []
        assert not p.exists()  # nothing to write

    def test_appends_to_existing_file(self, tmp_path):
        p = tmp_path / ".isitsecureignore"
        f1, f2 = _f("SQLi", "http://x/a"), _f("SQLi", "http://x/b")
        S.add_suppressions(p, [f1, f2], [f1.fingerprint])
        S.add_suppressions(p, [f1, f2], [f2.fingerprint])
        assert S.load_suppressed_fingerprints(p) == {f1.fingerprint, f2.fingerprint}

    def test_appends_cleanly_to_hand_edited_file_without_header_or_newline(self, tmp_path):
        """A user may hand-write the file with no header and no trailing newline —
        appending must not merge two entries onto one line."""
        p = tmp_path / ".isitsecureignore"
        existing_fp = "aaaabbbbccccdddd"
        p.write_text(f"{existing_fp}   # hand-written, no trailing newline")  # no \n
        f = _f("SQLi", "http://x/new")
        S.add_suppressions(p, [f], [f.fingerprint])
        fps = S.load_suppressed_fingerprints(p)
        assert fps == {existing_fp, f.fingerprint}  # both parsed = not merged


def test_default_ignore_path_uses_cwd_by_default(tmp_path):
    assert S.default_ignore_path().name == ".isitsecureignore"
    assert S.default_ignore_path(tmp_path) == tmp_path / ".isitsecureignore"
