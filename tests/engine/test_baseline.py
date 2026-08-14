"""Tests for baseline mode — surface only new findings (#52)."""

from __future__ import annotations

from isitsecure.engine import baseline as B
from isitsecure.engine.enums import FindingCategory, SeverityLevel
from isitsecure.engine.models import DeepFinding, FindingSource


def _f(title, url):
    return DeepFinding(
        source=FindingSource.DAST_URL, category=FindingCategory.INJECTION_RISK,
        severity=SeverityLevel.HIGH, title=title, description="d", confidence=0.8,
        scanner_name="active_injection_scanner", endpoint_url=url, http_method="GET",
    )


class TestProjectKey:
    def test_repo_key_stable_across_target_environments(self):
        a = B.project_key("http://localhost:3000", "github.com/me/app")
        b = B.project_key("https://prod.example.com:8443", "github.com/me/app")
        assert a == b

    def test_distinct_repos_get_distinct_keys(self):
        assert B.project_key(None, "github.com/me/a") != B.project_key(None, "github.com/me/b")

    def test_key_is_filesystem_safe_and_readable(self):
        k = B.project_key("http://localhost:3000/app", None)
        assert "/" not in k and k.startswith("localhost-3000")

    def test_slug_collision_disambiguated_by_hash(self):
        # Two identifiers that slugify identically must still differ (hash suffix).
        a = B.project_key(None, "github.com/me/app")
        b = B.project_key(None, "github.com/me/app/")  # trailing slash → same slug
        assert a != b


class TestSaveLoad:
    def test_missing_baseline_returns_none(self, tmp_path):
        # None (absent) is distinct from an empty set (a validly-empty baseline).
        assert B.load_baseline(tmp_path / "none.json") is None

    def test_save_then_load_roundtrips_fingerprints(self, tmp_path):
        p = tmp_path / "proj.json"
        fs = [_f("SQLi", "http://x/a"), _f("SQLi", "http://x/b")]
        n = B.save_baseline(p, fs, target_url="http://x", repo_url=None)
        assert n == 2
        assert B.load_baseline(p) == {fs[0].fingerprint, fs[1].fingerprint}

    def test_validly_empty_baseline_is_empty_set_not_none(self, tmp_path):
        p = tmp_path / "clean.json"
        B.save_baseline(p, [])  # a clean app: 0 findings baselined
        assert B.load_baseline(p) == set()

    def test_save_dedups_fingerprints(self, tmp_path):
        p = tmp_path / "proj.json"
        dupe = _f("SQLi", "http://x/a")
        same = _f("SQLi", "http://x/a")  # identical → same fingerprint
        assert dupe.fingerprint == same.fingerprint
        assert B.save_baseline(p, [dupe, same]) == 1

    def test_corrupt_baseline_returns_none(self, tmp_path):
        p = tmp_path / "proj.json"
        p.write_text("not valid json {{{")
        assert B.load_baseline(p) is None

    def test_valid_json_wrong_shape_returns_none_not_crash(self, tmp_path):
        # A JSON array, or a non-list `fingerprints`, must degrade to None — never
        # crash (M1) and never mis-read a string as a set of chars.
        for bad in ('[1, 2, 3]', '{"fingerprints": "abcd"}', '"just a string"', '42'):
            p = tmp_path / "bad.json"
            p.write_text(bad)
            assert B.load_baseline(p) is None

    def test_creates_parent_directory(self, tmp_path):
        p = tmp_path / "nested" / "dir" / "proj.json"
        B.save_baseline(p, [_f("SQLi", "http://x/a")])
        assert p.exists()


class TestPartitionNew:
    def test_splits_new_vs_known(self):
        old = [_f("SQLi", "http://x/a"), _f("SQLi", "http://x/b")]
        baseline = {old[0].fingerprint, old[1].fingerprint}
        current = [_f("SQLi", "http://x/a"), _f("SQLi", "http://x/c")]  # b fixed, c new
        new, known = B.partition_new(current, baseline)
        assert [f.endpoint_url for f in new] == ["http://x/c"]
        assert [f.endpoint_url for f in known] == ["http://x/a"]

    def test_empty_baseline_makes_everything_new(self):
        fs = [_f("SQLi", "http://x/a"), _f("SQLi", "http://x/b")]
        new, known = B.partition_new(fs, set())
        assert len(new) == 2 and known == []


def test_baseline_path_uses_baselines_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(B, "CONFIG_DIR", tmp_path)
    p = B.baseline_path("http://x", None)
    assert p.parent == tmp_path / "baselines"
    assert p.suffix == ".json"


class TestIntegration:
    """Mirror the CLI flow: accept a baseline, then a later scan surfaces only new."""

    def test_accept_then_diff_surfaces_only_new(self, tmp_path):
        p = tmp_path / "proj.json"
        scan1 = [_f("SQLi", "http://x/a"), _f("SQLi", "http://x/b")]
        B.save_baseline(p, scan1)
        scan2 = [_f("SQLi", "http://x/a"), _f("SQLi", "http://x/d")]  # b fixed, d new
        new, known = B.partition_new(scan2, B.load_baseline(p))
        assert [f.endpoint_url for f in new] == ["http://x/d"]
        assert [f.endpoint_url for f in known] == ["http://x/a"]

    def test_composes_with_suppression(self, tmp_path):
        """The CLI baselines the post-suppression set, so a suppressed finding is
        neither recorded nor surfaced as new later."""
        from isitsecure.engine import suppression as Sup
        ignore = tmp_path / ".isitsecureignore"
        p = tmp_path / "proj.json"
        scan1 = [_f("SQLi", "http://x/a"), _f("SQLi", "http://x/b"), _f("SQLi", "http://x/c")]
        Sup.add_suppressions(ignore, scan1, [scan1[1].fingerprint], "fp")  # suppress b
        active1, _ = Sup.partition(scan1, Sup.load_suppressed_fingerprints(ignore))
        B.save_baseline(p, active1)  # baseline = {a, c}

        scan2 = [_f("SQLi", "http://x/a"), _f("SQLi", "http://x/c"), _f("SQLi", "http://x/d")]
        active2, _ = Sup.partition(scan2, Sup.load_suppressed_fingerprints(ignore))
        new, _ = B.partition_new(active2, B.load_baseline(p))
        assert [f.endpoint_url for f in new] == ["http://x/d"]  # only the genuinely new one
