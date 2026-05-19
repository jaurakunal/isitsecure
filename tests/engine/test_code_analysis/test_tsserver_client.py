"""Tests for TypeScriptLSPClient.

Tests static/class methods, instance state management, and response
parsing without spawning a real tsserver subprocess.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from isitsecure.engine.code_analysis.lsp.tsserver_client import (
    TypeScriptLSPClient,
)
from isitsecure.engine.constants import LSPConfig


# ------------------------------------------------------------------
# TestNodeAvailability
# ------------------------------------------------------------------


class TestNodeAvailability:
    """Tests for the static ``is_node_available`` check."""

    def test_is_node_available_returns_bool(self) -> None:
        """is_node_available must return a bool, regardless of environment."""
        result = TypeScriptLSPClient.is_node_available()
        assert isinstance(result, bool)

    def test_is_available_false_before_init(self) -> None:
        """A freshly-created client should report is_available=False."""
        client = TypeScriptLSPClient()
        assert client.is_available is False


# ------------------------------------------------------------------
# TestClientLifecycle
# ------------------------------------------------------------------


class TestClientLifecycle:
    """Tests for instance state immediately after construction."""

    def test_initial_state(self) -> None:
        """Verify all default values on a brand-new client."""
        client = TypeScriptLSPClient()
        assert client._process is None
        assert client._initialized is False
        assert client._opened_files == set()
        assert isinstance(client._opened_files, set)

    def test_is_available_requires_both_initialized_and_process(self) -> None:
        """is_available should be True only when BOTH _initialized and
        _process are truthy."""
        client = TypeScriptLSPClient()

        # Neither set
        assert client.is_available is False

        # Only _initialized
        client._initialized = True
        assert client.is_available is False

        # Only _process (reset _initialized)
        client._initialized = False
        client._process = object()  # type: ignore[assignment]
        assert client.is_available is False

        # Both set
        client._initialized = True
        assert client.is_available is True

    def test_opened_files_is_instance_variable(self) -> None:
        """Each client instance must have its own _opened_files set."""
        client_a = TypeScriptLSPClient()
        client_b = TypeScriptLSPClient()

        client_a._opened_files.add("/tmp/a.ts")

        assert "/tmp/a.ts" in client_a._opened_files
        assert "/tmp/a.ts" not in client_b._opened_files


# ------------------------------------------------------------------
# TestLanguageDetection
# ------------------------------------------------------------------


class TestLanguageDetection:
    """Tests for the static ``_detect_language`` helper."""

    @pytest.mark.parametrize(
        ("path", "expected"),
        [
            ("src/index.ts", "typescript"),
            ("src/App.tsx", "typescript"),
            ("lib/utils.js", "javascript"),
            ("lib/App.jsx", "javascript"),
            ("lib/helpers.mjs", "javascript"),
            ("data/config.py", "plaintext"),
        ],
        ids=[
            "dot_ts",
            "dot_tsx",
            "dot_js",
            "dot_jsx",
            "dot_mjs",
            "dot_py_unknown",
        ],
    )
    def test_detect_language(self, path: str, expected: str) -> None:
        result = TypeScriptLSPClient._detect_language(path)
        assert result == expected


# ------------------------------------------------------------------
# TestLocationParsing
# ------------------------------------------------------------------


class TestLocationParsing:
    """Tests for the static ``_parse_locations`` response parser."""

    def test_parse_locations_none_returns_none(self) -> None:
        assert TypeScriptLSPClient._parse_locations(None) is None

    def test_parse_locations_empty_list_returns_none(self) -> None:
        assert TypeScriptLSPClient._parse_locations([]) is None

    def test_parse_locations_single_location(self) -> None:
        raw = {
            "uri": "file:///tmp/test.ts",
            "range": {
                "start": {"line": 5, "character": 10},
                "end": {"line": 5, "character": 20},
            },
        }
        result = TypeScriptLSPClient._parse_locations(raw)

        assert result is not None
        assert len(result) == 1

        loc = result[0]
        assert loc.file_path == "/tmp/test.ts"
        assert loc.line == 5
        assert loc.character == 10
        assert loc.end_line == 5
        assert loc.end_character == 20

    def test_parse_locations_array_of_locations(self) -> None:
        raw = [
            {
                "uri": "file:///a.ts",
                "range": {
                    "start": {"line": 1, "character": 0},
                    "end": {"line": 1, "character": 5},
                },
            },
            {
                "uri": "file:///b.ts",
                "range": {
                    "start": {"line": 10, "character": 3},
                    "end": {"line": 12, "character": 0},
                },
            },
        ]
        result = TypeScriptLSPClient._parse_locations(raw)

        assert result is not None
        assert len(result) == 2
        assert result[0].file_path == "/a.ts"
        assert result[1].file_path == "/b.ts"
        assert result[1].line == 10
        assert result[1].end_line == 12

    def test_parse_locations_strips_file_prefix(self) -> None:
        raw = {
            "uri": "file:///home/user/project/src/auth.ts",
            "range": {
                "start": {"line": 0, "character": 0},
                "end": {"line": 0, "character": 0},
            },
        }
        result = TypeScriptLSPClient._parse_locations(raw)

        assert result is not None
        assert result[0].file_path == "/home/user/project/src/auth.ts"
        assert not result[0].file_path.startswith("file://")


# ------------------------------------------------------------------
# TestTsconfigManagement
# ------------------------------------------------------------------


class TestTsconfigManagement:
    """Tests for ``_ensure_tsconfig`` using the ``tmp_path`` fixture."""

    def test_ensure_tsconfig_creates_temp(self, tmp_path: Path) -> None:
        """When no tsconfig.json exists, a temporary one is created."""
        client = TypeScriptLSPClient()
        tsconfig_path = tmp_path / "tsconfig.json"
        assert not tsconfig_path.exists()

        client._ensure_tsconfig(str(tmp_path))

        assert tsconfig_path.exists()
        assert client._temp_tsconfig == tsconfig_path

        content = json.loads(tsconfig_path.read_text())
        assert content == LSPConfig.DEFAULT_TSCONFIG

    def test_ensure_tsconfig_skips_existing(self, tmp_path: Path) -> None:
        """When tsconfig.json already exists, it is not overwritten."""
        client = TypeScriptLSPClient()
        tsconfig_path = tmp_path / "tsconfig.json"
        original = {"compilerOptions": {"strict": False}}
        tsconfig_path.write_text(json.dumps(original))

        client._ensure_tsconfig(str(tmp_path))

        # Should not have been touched
        assert client._temp_tsconfig is None
        content = json.loads(tsconfig_path.read_text())
        assert content == original
