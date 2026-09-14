"""GoLSPClient — gopls discovery and language id."""

from __future__ import annotations

from isitsecure.engine.code_analysis.lsp import go_client as go_mod
from isitsecure.engine.code_analysis.lsp.go_client import GoLSPClient
from isitsecure.engine.code_analysis.lsp.language_router import (
    default_language_support,
    detect_project_language,
)


def test_language_id_is_go():
    assert GoLSPClient()._get_language_id("main.go") == "go"


def test_runtime_requires_go_toolchain(monkeypatch):
    """gopls needs `go` on PATH to resolve anything, so runtime availability
    tracks the go toolchain — not unconditionally true."""
    monkeypatch.setattr(go_mod.shutil, "which",
                        lambda n: "/usr/bin/go" if n == "go" else None)
    assert GoLSPClient.is_runtime_available() is True
    monkeypatch.setattr(go_mod.shutil, "which", lambda n: None)
    assert GoLSPClient.is_runtime_available() is False


def test_router_skips_go_without_toolchain(monkeypatch):
    """No `go` on PATH → the router must not route to gopls (avoids the
    confident-silence of a server that resolves nothing)."""
    from isitsecure.engine.code_analysis.lsp.language_router import (
        default_language_support,
    )
    monkeypatch.setattr(go_mod.shutil, "which",
                        lambda n: "/usr/bin/gopls" if n == "gopls" else None)
    avail, _ = default_language_support()["go"]
    assert avail() is False  # gopls present but go toolchain absent


def test_server_available_follows_path(monkeypatch):
    monkeypatch.setattr(go_mod.shutil, "which",
                        lambda n: "/usr/bin/gopls" if n == "gopls" else None)
    assert GoLSPClient.is_server_available() is True
    monkeypatch.setattr(go_mod.shutil, "which", lambda n: None)
    assert GoLSPClient.is_server_available() is False


def test_router_registers_go():
    assert "go" in default_language_support()


def test_go_project_detected(tmp_path):
    (tmp_path / "main.go").write_text("package main\n")
    assert detect_project_language(str(tmp_path)) == "go"
