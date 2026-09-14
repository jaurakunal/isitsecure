"""Server-selection policy for the Python and Java/Kotlin LSP clients.

Two precision fixes are pinned here:

- Python prefers ``pyright``/``basedpyright`` over ``pylsp`` — their cross-file
  definition/reference resolution is what auth-flow tracing depends on.
- The Java/Kotlin client prefers ``kotlin-language-server`` for a Kotlin-dominant
  project (jdtls resolves Kotlin poorly), while a Java-dominant project keeps
  jdtls. Without this, an installed Kotlin server would sit idle whenever jdtls
  was present.
"""

from __future__ import annotations

import pytest

from isitsecure.engine.code_analysis.lsp import java_client as java_mod
from isitsecure.engine.code_analysis.lsp import python_client as py_mod
from isitsecure.engine.code_analysis.lsp.java_client import JavaLSPClient
from isitsecure.engine.code_analysis.lsp.python_client import PythonLSPClient

# --------------------------------------------------------------------------
# Python: pyright before pylsp
# --------------------------------------------------------------------------

def test_python_server_options_prefer_pyright_over_pylsp() -> None:
    binaries = [b for b, _ in PythonLSPClient.SERVER_OPTIONS]
    assert binaries.index("pyright-langserver") < binaries.index("pylsp")
    assert binaries.index("basedpyright-langserver") < binaries.index("pylsp")


@pytest.mark.asyncio
async def test_python_picks_pyright_when_both_installed(monkeypatch) -> None:
    """With pyright and pylsp both on PATH, pyright is chosen."""
    monkeypatch.setattr(
        py_mod.shutil, "which", lambda name: f"/usr/bin/{name}"
    )  # everything "installed"
    cmd = await PythonLSPClient()._find_server_command()
    assert cmd == ("pyright-langserver", "--stdio")


@pytest.mark.asyncio
async def test_python_falls_back_to_pylsp(monkeypatch) -> None:
    """Only pylsp installed → pylsp is used."""
    monkeypatch.setattr(
        py_mod.shutil, "which",
        lambda name: "/usr/bin/pylsp" if name == "pylsp" else None,
    )
    cmd = await PythonLSPClient()._find_server_command()
    assert cmd == ("pylsp",)


# --------------------------------------------------------------------------
# Java/Kotlin: project-aware server selection
# --------------------------------------------------------------------------

def _write(tmp_path, name: str) -> None:
    (tmp_path / name).write_text("// x\n")


def test_kotlin_dominance_detection(tmp_path) -> None:
    _write(tmp_path, "A.kt")
    _write(tmp_path, "B.kt")
    _write(tmp_path, "C.java")
    client = JavaLSPClient()
    client._project_path = str(tmp_path)
    assert client._project_is_kotlin_dominant() is True


def test_java_dominance_and_ties_favour_java(tmp_path) -> None:
    _write(tmp_path, "A.kt")
    _write(tmp_path, "B.java")  # tie -> not Kotlin-dominant
    client = JavaLSPClient()
    client._project_path = str(tmp_path)
    assert client._project_is_kotlin_dominant() is False


def test_empty_project_is_not_kotlin_dominant() -> None:
    client = JavaLSPClient()
    client._project_path = ""
    assert client._project_is_kotlin_dominant() is False


@pytest.mark.asyncio
async def test_kotlin_project_prefers_kotlin_server_over_jdtls(
    tmp_path, monkeypatch
) -> None:
    """A Kotlin-dominant project uses kotlin-language-server even when jdtls
    is installed."""
    _write(tmp_path, "A.kt")
    _write(tmp_path, "B.kt")
    monkeypatch.setattr(
        java_mod.shutil, "which", lambda name: f"/usr/bin/{name}"
    )  # both jdtls and kotlin-language-server "installed"
    client = JavaLSPClient()
    client._project_path = str(tmp_path)
    cmd = await client._find_server_command()
    assert cmd == ("kotlin-language-server",)


@pytest.mark.asyncio
async def test_java_project_uses_jdtls(tmp_path, monkeypatch) -> None:
    """A Java-dominant project uses jdtls (with a workspace dir), not Kotlin."""
    _write(tmp_path, "A.java")
    _write(tmp_path, "B.java")
    monkeypatch.setattr(
        java_mod.shutil, "which", lambda name: f"/usr/bin/{name}"
    )
    client = JavaLSPClient()
    client._project_path = str(tmp_path)
    cmd = await client._find_server_command()
    assert cmd[0] == "jdtls"
    assert "-data" in cmd


@pytest.mark.asyncio
async def test_kotlin_project_falls_back_to_jdtls_when_no_kotlin_server(
    tmp_path, monkeypatch
) -> None:
    """A Kotlin project with only jdtls installed still gets a server (jdtls)."""
    _write(tmp_path, "A.kt")
    monkeypatch.setattr(
        java_mod.shutil, "which",
        lambda name: "/usr/bin/jdtls" if name == "jdtls" else None,
    )
    client = JavaLSPClient()
    client._project_path = str(tmp_path)
    cmd = await client._find_server_command()
    assert cmd[0] == "jdtls"
