"""Tests for Wave 1 onboarding/UX helpers in isitsecure.cli.

Covers:
  * #56 smart first-run mode auto-selection
  * #54 pre-flight prerequisite detection (which warnings fire per mode)
"""

from __future__ import annotations

import pytest

from isitsecure import cli


# ---------------------------------------------------------------------------
# #56 — mode auto-selection
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "url, repo, has_auth, expected",
    [
        ("https://app.com", "github.com/a/b", False, "full"),
        ("https://app.com", "github.com/a/b", True, "full"),   # both wins over auth
        ("https://app.com", None, False, "url-only"),
        ("https://app.com", None, True, "authenticated"),
        (None, "github.com/a/b", False, "code-only"),
        (None, "github.com/a/b", True, "code-only"),            # no url -> auth irrelevant
    ],
)
def test_auto_select_mode(url, repo, has_auth, expected):
    assert cli._auto_select_mode(url, repo, has_auth) == expected


def test_every_selectable_mode_has_an_explanation():
    # Every mode the auto-selector can return must have a plain-English line.
    for mode in ("url-only", "authenticated", "code-only", "full"):
        assert mode in cli._MODE_EXPLANATIONS
        assert cli._MODE_EXPLANATIONS[mode]


# ---------------------------------------------------------------------------
# #54 — pre-flight checks (which warnings fire, per mode / prerequisites)
# ---------------------------------------------------------------------------

def _run_preflight(monkeypatch, *, mode, chromium, missing_lsp, provider, has_key):
    """Run _preflight_checks with fully stubbed detection, return captured text."""
    monkeypatch.setattr(cli, "_chromium_installed", lambda: chromium)
    # Force LSP detection: _first_which returns None (missing) or a fake path.
    monkeypatch.setattr(cli, "_first_which", lambda bins: None if missing_lsp else "found")
    # shutil.which is used for runtime checks — treat runtimes as present so the
    # only variable is _first_which above.
    import shutil
    monkeypatch.setattr(shutil, "which", lambda *_: "found")

    printed: list[str] = []
    monkeypatch.setattr(
        cli.err_console, "print", lambda *a, **k: printed.append(" ".join(str(x) for x in a))
    )
    cli._preflight_checks(mode, provider, has_key)
    return "\n".join(printed)


def test_url_only_missing_chromium_warns(monkeypatch):
    out = _run_preflight(
        monkeypatch, mode="url-only", chromium=False,
        missing_lsp=False, provider="none", has_key=False,
    )
    assert "browser" in out.lower()
    assert "isitsecure setup" in out


def test_url_only_does_not_warn_about_lsp(monkeypatch):
    # A live-site-only scan needs no language servers, so missing LSPs must be
    # silent even if they're absent.
    out = _run_preflight(
        monkeypatch, mode="url-only", chromium=True,
        missing_lsp=True, provider="none", has_key=False,
    )
    assert out.strip() == ""  # nothing missing that this mode needs


def test_code_only_does_not_warn_about_browser(monkeypatch):
    # Code scan needs no browser — a missing Chromium must not fire.
    out = _run_preflight(
        monkeypatch, mode="code-only", chromium=False,
        missing_lsp=False, provider="none", has_key=False,
    )
    assert "browser" not in out.lower()


def test_code_only_warns_about_missing_lsp(monkeypatch):
    out = _run_preflight(
        monkeypatch, mode="code-only", chromium=False,
        missing_lsp=True, provider="none", has_key=False,
    )
    assert "isitsecure setup --lsp" in out


def test_llm_key_warning_only_when_provider_selected_and_missing(monkeypatch):
    # provider chosen but no key -> warn
    out = _run_preflight(
        monkeypatch, mode="url-only", chromium=True,
        missing_lsp=False, provider="anthropic", has_key=False,
    )
    assert "api key" in out.lower()
    assert "ANTHROPIC_API_KEY" in out


def test_no_llm_key_warning_when_key_present(monkeypatch):
    out = _run_preflight(
        monkeypatch, mode="url-only", chromium=True,
        missing_lsp=False, provider="anthropic", has_key=True,
    )
    assert "api key" not in out.lower()


def test_no_llm_key_warning_when_provider_none(monkeypatch):
    out = _run_preflight(
        monkeypatch, mode="url-only", chromium=True,
        missing_lsp=False, provider="none", has_key=False,
    )
    assert "api key" not in out.lower()


def test_full_mode_reports_all_three_when_all_missing(monkeypatch):
    out = _run_preflight(
        monkeypatch, mode="full", chromium=False,
        missing_lsp=True, provider="anthropic", has_key=False,
    )
    assert "browser" in out.lower()
    assert "isitsecure setup --lsp" in out
    assert "api key" in out.lower()


def test_all_ready_prints_nothing(monkeypatch):
    out = _run_preflight(
        monkeypatch, mode="full", chromium=True,
        missing_lsp=False, provider="anthropic", has_key=True,
    )
    assert out.strip() == ""


# ---------------------------------------------------------------------------
# #55 — humanized error for the "gave neither url nor repo" case (end-to-end)
# ---------------------------------------------------------------------------

def test_scan_with_no_target_shows_human_error(monkeypatch):
    from typer.testing import CliRunner

    # Silence the welcome banner so it can't interfere with output capture.
    monkeypatch.setattr(cli, "_print_welcome", lambda: None)
    # err_console writes to stderr; capture it as a plain string.
    import io
    from rich.console import Console
    buf = io.StringIO()
    monkeypatch.setattr(cli, "err_console", Console(file=buf, force_terminal=False))

    runner = CliRunner()
    result = runner.invoke(cli.app, ["scan"])
    assert result.exit_code == 1
    out = buf.getvalue()
    # Plain-language, not the old terse "provide a target URL, a --repo".
    assert "I need either your website" in out
    assert "isitsecure scan https://" in out
