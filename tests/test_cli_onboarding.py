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

def _run_preflight(
    monkeypatch, *, mode, chromium, missing_lsp, provider, has_key,
    ts_runtime="/fake/typescript/lib/tsserver.js",
):
    """Run _preflight_checks with fully stubbed detection, return captured text."""
    monkeypatch.setattr(cli, "_chromium_installed", lambda: chromium)
    # Force LSP detection: _first_which returns None (missing) or a fake path.
    monkeypatch.setattr(cli, "_first_which", lambda bins: None if missing_lsp else "found")
    # shutil.which is used for runtime checks — treat runtimes as present so the
    # only variable is _first_which above.
    import shutil
    monkeypatch.setattr(shutil, "which", lambda *_: "found")
    # The TypeScript runtime lookup hits the real filesystem otherwise, which
    # would make these tests depend on the host's npm install (#145).
    from isitsecure.engine.code_analysis.lsp import tsserver_locator
    monkeypatch.setattr(
        tsserver_locator, "find_tsserver_js", lambda *_a, **_k: ts_runtime
    )

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


def test_code_only_warns_when_ts_server_has_no_typescript_runtime(monkeypatch):
    # The language server being installed isn't enough — without a TypeScript
    # 5.x runtime it refuses to start, and the scan silently degrades (#145).
    out = _run_preflight(
        monkeypatch, mode="code-only", chromium=True,
        missing_lsp=False, provider="none", has_key=False,
        ts_runtime=None,
    )
    assert "TypeScript runtime" in out
    assert "isitsecure setup --lsp" in out


def test_no_runtime_warning_when_the_ts_server_itself_is_missing(monkeypatch):
    # One warning, not two: "install the language server" already covers it.
    out = _run_preflight(
        monkeypatch, mode="code-only", chromium=True,
        missing_lsp=True, provider="none", has_key=False,
        ts_runtime=None,
    )
    assert "TypeScript runtime" not in out


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


# ---------------------------------------------------------------------------
# #145 — `setup --lsp` provisions a TypeScript runtime for the TS language server
# ---------------------------------------------------------------------------

def _run_ensure_runtime(
    monkeypatch, tmp_path, *, server_installed=True, runtime=None,
    npm=True, install_result=(0, ""), installs_runtime=True,
):
    """Run _ensure_tsserver_runtime with npm and the locator stubbed out."""
    import shutil
    import subprocess

    from isitsecure.engine.code_analysis.lsp import tsserver_locator

    monkeypatch.setattr(
        cli, "_first_which", lambda bins: "found" if server_installed else None
    )
    monkeypatch.setattr(
        shutil, "which", lambda name: "/usr/bin/npm" if (npm and name == "npm") else None
    )
    monkeypatch.setattr(tsserver_locator, "PROVISIONED_ROOT", tmp_path / "lsp")

    calls: list[list[str]] = []
    found = {"path": runtime}

    def fake_run(cmd, **_kwargs):
        calls.append(list(cmd))
        code, output = install_result
        if code == 0 and installs_runtime:
            found["path"] = tmp_path / "lsp/node_modules/typescript/lib/tsserver.js"
        return subprocess.CompletedProcess(cmd, code, stdout=output, stderr=output)

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(
        tsserver_locator, "find_tsserver_js", lambda *_a, **_k: found["path"]
    )

    printed: list[str] = []
    monkeypatch.setattr(
        cli.console, "print", lambda *a, **k: printed.append(" ".join(str(x) for x in a))
    )
    cli._ensure_tsserver_runtime()
    return "\n".join(printed), calls


def test_runtime_provisioning_skipped_without_the_language_server(monkeypatch, tmp_path):
    # Nothing to feed a runtime to — stay quiet rather than install for nobody.
    out, calls = _run_ensure_runtime(monkeypatch, tmp_path, server_installed=False)
    assert out == ""
    assert calls == []


def test_existing_runtime_is_reported_and_not_reinstalled(monkeypatch, tmp_path):
    out, calls = _run_ensure_runtime(
        monkeypatch, tmp_path, runtime="/usr/lib/typescript/lib/tsserver.js"
    )
    assert "/usr/lib/typescript/lib/tsserver.js" in out
    assert calls == []


def test_missing_runtime_is_installed_privately_and_pinned_to_5(monkeypatch, tmp_path):
    from isitsecure.engine.code_analysis.lsp.tsserver_locator import (
        TYPESCRIPT_PACKAGE_SPEC,
    )

    out, calls = _run_ensure_runtime(monkeypatch, tmp_path, runtime=None)

    assert len(calls) == 1
    cmd = calls[0]
    assert "install" in cmd and TYPESCRIPT_PACKAGE_SPEC in cmd
    # Private prefix: never touch the user's global TypeScript.
    assert "--prefix" in cmd
    assert str(tmp_path / "lsp") in cmd
    assert "-g" not in cmd
    assert "installed" in out


def test_install_failure_is_reported_not_claimed_as_success(monkeypatch, tmp_path):
    out, _calls = _run_ensure_runtime(
        monkeypatch, tmp_path, runtime=None,
        install_result=(1, "npm ERR! network timeout"), installs_runtime=False,
    )
    assert "installed" not in out
    assert "network timeout" in out


def test_install_that_exits_clean_but_provisions_nothing_is_not_success(
    monkeypatch, tmp_path
):
    out, _calls = _run_ensure_runtime(
        monkeypatch, tmp_path, runtime=None,
        install_result=(0, "up to date"), installs_runtime=False,
    )
    assert "installed" not in out


def test_missing_npm_gives_guidance_instead_of_installing(monkeypatch, tmp_path):
    out, calls = _run_ensure_runtime(monkeypatch, tmp_path, runtime=None, npm=False)
    assert calls == []
    assert "ISITSECURE_TSSERVER_PATH" in out


# ---------------------------------------------------------------------------
# #147 — a scan that couldn't read the code must not exit clean
# ---------------------------------------------------------------------------

def _run_scan_cli(monkeypatch, report, argv):
    """Invoke `scan` with the engine stubbed out; return (exit_code, stderr)."""
    import io

    from rich.console import Console
    from typer.testing import CliRunner

    monkeypatch.setattr(cli, "_print_welcome", lambda: None)
    monkeypatch.setattr(cli, "_preflight_checks", lambda *a, **k: None)
    buf = io.StringIO()
    monkeypatch.setattr(cli, "err_console", Console(file=buf, force_terminal=False))
    monkeypatch.setattr(cli, "console", Console(file=buf, force_terminal=False))

    import isitsecure.engine.factory as factory
    monkeypatch.setattr(factory, "create_repo_ingestion_service", lambda *a, **k: None)
    monkeypatch.setattr(
        factory, "create_deep_security_scan_agent", lambda *a, **k: object()
    )

    async def fake_run_scan(agent, **kwargs):
        return report

    monkeypatch.setattr(cli, "_run_scan", fake_run_scan)

    result = CliRunner().invoke(cli.app, argv)
    return result.exit_code, buf.getvalue()


def _empty_report(**kwargs):
    from isitsecure.engine.models import DeepScanReport
    return DeepScanReport(scan_mode="full", **kwargs)


def test_scan_exits_nonzero_when_the_repo_could_not_be_read(monkeypatch, tmp_path):
    # A partial scan that reports zero code findings reads as "your code is
    # fine" in CI. It has to say the code was never scanned, and exit non-zero.
    report = _empty_report(
        ingestion_errors=["Repository not found (or not accessible): git@x/y"],
    )
    code, out = _run_scan_cli(
        monkeypatch, report,
        ["scan", "https://example.com", "--repo", "git@x/y", "--llm", "none",
         "--output", "json", "--output-file", str(tmp_path / "r.json")],
    )
    assert code == 1
    assert "Repository not found" in out
    assert "not scanned" in out


def test_failed_ingestion_is_recorded_in_the_report_itself(monkeypatch, tmp_path):
    """Not just on the terminal — a saved report has to carry the caveat."""
    import json

    out_file = tmp_path / "r.json"
    _run_scan_cli(
        monkeypatch,
        _empty_report(ingestion_errors=["Repository not found"]),
        ["scan", "https://example.com", "--repo", "git@x/y", "--llm", "none",
         "--output", "json", "--output-file", str(out_file)],
    )
    assert json.loads(out_file.read_text())["ingestion_errors"] == [
        "Repository not found"
    ]


def test_scan_exits_clean_when_nothing_failed(monkeypatch, tmp_path):
    code, out = _run_scan_cli(
        monkeypatch, _empty_report(),
        ["scan", "https://example.com", "--llm", "none",
         "--output", "json", "--output-file", str(tmp_path / "r.json")],
    )
    assert code == 0
    assert "not scanned" not in out
