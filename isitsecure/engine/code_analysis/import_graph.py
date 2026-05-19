"""Import graph builder for import-graph centrality analysis.

SRP: ``ImportParser`` extracts import specifiers from source code.
     ``ImportGraphBuilder`` resolves paths and computes fan-in.

DIP: Both classes depend on configuration constants, not concrete
     implementations.  The builder accepts ``file_index`` (a plain dict)
     rather than coupling to ``RepoSnapshot``.
"""

from __future__ import annotations

import json
import logging
import posixpath
import re
from collections import defaultdict

from isitsecure.engine.constants import ImportGraphCentralityConfig

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Import parser — extracts raw import specifiers from source code
# ---------------------------------------------------------------------------


class ImportParser:
    """Extracts import specifiers from JS/TS/Python source files.

    Uses regex, not a full parser.  This is deliberate: we only need
    module paths (not imported names), and regex is fast enough to scan
    thousands of files in under a second.
    """

    # Compiled patterns (class-level for reuse)
    _JS_PATTERNS = [
        re.compile(ImportGraphCentralityConfig.ES6_IMPORT_PATTERN),
        re.compile(ImportGraphCentralityConfig.CJS_REQUIRE_PATTERN),
        re.compile(ImportGraphCentralityConfig.DYNAMIC_IMPORT_PATTERN),
    ]
    _PY_FROM_RE = re.compile(
        ImportGraphCentralityConfig.PYTHON_FROM_IMPORT_PATTERN, re.MULTILINE,
    )
    _PY_IMPORT_RE = re.compile(
        ImportGraphCentralityConfig.PYTHON_IMPORT_PATTERN, re.MULTILINE,
    )

    # Strip single-line and block comments before parsing (JS/TS)
    _JS_COMMENT_RE = re.compile(
        r"//[^\n]*|/\*[\s\S]*?\*/", re.MULTILINE,
    )
    # Strip Python comments
    _PY_COMMENT_RE = re.compile(r"#[^\n]*")

    @classmethod
    def parse_imports(cls, content: str, file_path: str) -> list[str]:
        """Extract raw import specifiers from source code.

        Returns a list of unresolved specifiers (e.g., ``'./utils'``,
        ``'@/lib/db'``, ``'express'``).
        """
        ext = cls._extension(file_path)
        if ext in (".py",):
            return cls._parse_python(content)
        if ext in ImportGraphCentralityConfig.PARSEABLE_EXTENSIONS:
            return cls._parse_js(content)
        return []

    # ------------------------------------------------------------------
    # JS / TS
    # ------------------------------------------------------------------

    @classmethod
    def _parse_js(cls, content: str) -> list[str]:
        """Extract import specifiers from JS/TS source."""
        # Strip comments to avoid false matches
        cleaned = cls._JS_COMMENT_RE.sub("", content)
        specifiers: list[str] = []
        for pattern in cls._JS_PATTERNS:
            for match in pattern.finditer(cleaned):
                spec = match.group(1)
                if spec:
                    specifiers.append(spec)
        return specifiers

    # ------------------------------------------------------------------
    # Python
    # ------------------------------------------------------------------

    @classmethod
    def _parse_python(cls, content: str) -> list[str]:
        """Extract import specifiers from Python source."""
        cleaned = cls._PY_COMMENT_RE.sub("", content)
        specifiers: list[str] = []
        for match in cls._PY_FROM_RE.finditer(cleaned):
            specifiers.append(match.group(1))
        for match in cls._PY_IMPORT_RE.finditer(cleaned):
            specifiers.append(match.group(1))
        return specifiers

    @staticmethod
    def _extension(file_path: str) -> str:
        dot = file_path.rfind(".")
        return file_path[dot:].lower() if dot != -1 else ""


# ---------------------------------------------------------------------------
# Import graph builder — resolves paths and computes fan-in
# ---------------------------------------------------------------------------


class ImportGraphBuilder:
    """Builds a fan-in map from a repository's file index.

    Fan-in = for each file, the set of other files that import it.
    High fan-in from security-sensitive routes indicates a shared module
    with high blast radius.
    """

    def __init__(
        self,
        alias_mappings: dict[str, str] | None = None,
    ) -> None:
        self._alias_mappings = (
            alias_mappings
            or dict(ImportGraphCentralityConfig.DEFAULT_ALIAS_MAPPINGS)
        )
        self._file_index_keys: set[str] = set()
        # Cache resolved paths to avoid repeated work
        self._resolve_cache: dict[tuple[str, str], str | None] = {}

    def build_fan_in_map(
        self, file_index: dict[str, str],
    ) -> dict[str, set[str]]:
        """Build fan-in map: ``{imported_file: {importer1, importer2, ...}}``.

        Only includes files that exist in ``file_index``.
        External packages are excluded.
        """
        self._file_index_keys = set(file_index.keys())
        self._resolve_cache.clear()

        # Try to load tsconfig.json alias mappings
        self._load_tsconfig_aliases(file_index)

        fan_in: dict[str, set[str]] = defaultdict(set)
        parsed_count = 0

        for source_path, content in file_index.items():
            # Skip non-parseable files
            if not self._is_parseable(source_path):
                continue

            specifiers = ImportParser.parse_imports(content, source_path)
            parsed_count += 1

            for spec in specifiers:
                resolved = self._resolve_import(spec, source_path)
                if resolved:
                    fan_in[resolved].add(source_path)

        logger.info(
            "Import graph: parsed %d files, found %d imported modules",
            parsed_count,
            len(fan_in),
        )
        return dict(fan_in)

    # ------------------------------------------------------------------
    # Path resolution
    # ------------------------------------------------------------------

    def _resolve_import(
        self, specifier: str, source_path: str,
    ) -> str | None:
        """Resolve an import specifier to a file_index key.

        Returns None if the specifier is an external package or
        cannot be resolved to a known file.
        """
        cache_key = (specifier, source_path)
        if cache_key in self._resolve_cache:
            return self._resolve_cache[cache_key]

        result = self._do_resolve(specifier, source_path)
        self._resolve_cache[cache_key] = result
        return result

    def _do_resolve(
        self, specifier: str, source_path: str,
    ) -> str | None:
        """Internal resolution logic."""
        # Skip external packages (no relative prefix and not aliased)
        if not self._is_local_import(specifier):
            return None

        # Resolve alias imports (@/lib/db → src/lib/db)
        resolved_spec = self._resolve_alias(specifier)

        if resolved_spec.startswith("."):
            # Relative import — resolve against source file's directory
            source_dir = posixpath.dirname(source_path)
            resolved_spec = posixpath.normpath(
                posixpath.join(source_dir, resolved_spec)
            )

        # Probe for the actual file
        return self._probe_file(resolved_spec)

    def _is_local_import(self, specifier: str) -> bool:
        """Check if an import specifier refers to a local file."""
        # Relative imports
        if specifier.startswith("."):
            return True
        # Aliased imports
        for alias in self._alias_mappings:
            if specifier.startswith(alias):
                return True
        return False

    def _resolve_alias(self, specifier: str) -> str:
        """Replace alias prefixes with their mapped paths."""
        for alias, replacement in self._alias_mappings.items():
            if specifier.startswith(alias):
                return replacement + specifier[len(alias):]
        return specifier

    def _probe_file(self, base_path: str) -> str | None:
        """Try to find the actual file in file_index.

        Probes with extensions and /index variants.
        """
        # Exact match
        if base_path in self._file_index_keys:
            return base_path

        # Try with extensions
        for ext in ImportGraphCentralityConfig.EXTENSION_PROBE_ORDER:
            candidate = base_path + ext
            if candidate in self._file_index_keys:
                return candidate

        # Try as directory with index file
        for index_file in ImportGraphCentralityConfig.INDEX_FILES:
            candidate = posixpath.join(base_path, index_file)
            if candidate in self._file_index_keys:
                return candidate

        return None

    # ------------------------------------------------------------------
    # tsconfig.json alias discovery
    # ------------------------------------------------------------------

    def _load_tsconfig_aliases(self, file_index: dict[str, str]) -> None:
        """Load path aliases from tsconfig.json if present."""
        for config_name in ("tsconfig.json", "jsconfig.json"):
            content = file_index.get(config_name)
            if not content:
                continue
            try:
                # Strip comments (tsconfig allows them)
                cleaned = re.sub(r"//[^\n]*|/\*[\s\S]*?\*/", "", content)
                config = json.loads(cleaned)
                paths = (
                    config.get("compilerOptions", {}).get("paths", {})
                )
                base_url = config.get("compilerOptions", {}).get(
                    "baseUrl", "."
                )
                for alias_pattern, targets in paths.items():
                    if not targets:
                        continue
                    # Convert TS path pattern to prefix mapping
                    # e.g., "@lib/*": ["src/lib/*"] → "@lib/": "src/lib/"
                    alias_prefix = alias_pattern.replace("*", "")
                    target_prefix = targets[0].replace("*", "")
                    if base_url and base_url != ".":
                        target_prefix = posixpath.join(
                            base_url, target_prefix,
                        )
                    self._alias_mappings[alias_prefix] = target_prefix
                logger.info(
                    "Loaded %d path aliases from %s",
                    len(paths),
                    config_name,
                )
            except (json.JSONDecodeError, KeyError, IndexError):
                pass

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_parseable(file_path: str) -> bool:
        """Check if a file should be parsed for imports."""
        # Check extension
        dot = file_path.rfind(".")
        if dot == -1:
            return False
        ext = file_path[dot:].lower()
        if ext not in ImportGraphCentralityConfig.PARSEABLE_EXTENSIONS:
            return False

        # Check skip directories
        parts = file_path.replace("\\", "/").split("/")
        return not any(
            part in ImportGraphCentralityConfig.SKIP_DIRECTORIES
            for part in parts
        )
