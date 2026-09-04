"""Pick the language server that matches the project being scanned.

Why this exists: the LSP client used to be chosen when the *agent* was built,
which is before anything has been ingested — so the only thing it could go on
was what happened to be installed on the machine. With Node present that was
always the TypeScript server, and a pure-Python repository would be handed
tsserver while a working pyright sat idle. The language server for a language
the project isn't written in finds nothing, so those scans silently fell back
to regex-only auth analysis.

``initialize(project_path)`` is the first moment the project actually exists,
so that is where the choice belongs. ``LanguageRoutingLSPClient`` implements
``LSPClientProtocol`` and delegates to whichever concrete client fits, which
keeps the decision out of the agent entirely.

If the project's language has no server installed we stop, rather than falling
back to a server for some other language: a mismatched server is not a partial
answer, it is a confident silence.
"""

from __future__ import annotations

import logging
import os
from collections import Counter
from collections.abc import Callable, Mapping

from isitsecure.engine.code_analysis.lsp.protocols import (
    LSPClientProtocol,
    LSPLocation,
)
from isitsecure.engine.constants import LSPConfig

logger = logging.getLogger(__name__)

# (is the server installed?, build a client for it)
LanguageSupport = tuple[Callable[[], bool], Callable[[], LSPClientProtocol]]


def detect_project_language(project_path: str) -> str | None:
    """Return the language most of the project is written in, or ``None``.

    Counts source files by extension.  Ties break toward the order languages
    are declared in ``LSPConfig.LANGUAGE_EXTENSIONS``, so a repo with equal
    amounts of two languages resolves the same way every scan.
    """
    by_extension: dict[str, str] = {
        ext: language
        for language, exts in LSPConfig.LANGUAGE_EXTENSIONS.items()
        for ext in exts
    }
    counts: Counter[str] = Counter()
    seen = 0

    for _root, dirnames, filenames in os.walk(project_path):
        dirnames[:] = [
            d for d in dirnames
            if d not in LSPConfig.LANGUAGE_SCAN_SKIP_DIRS and not d.startswith(".")
        ]
        for name in filenames:
            language = by_extension.get(os.path.splitext(name)[1].lower())
            if language:
                counts[language] += 1
            seen += 1
        if seen >= LSPConfig.LANGUAGE_SCAN_MAX_FILES:
            break

    if not counts:
        return None
    best = max(counts.values())
    # Declaration order is the tiebreak, so the answer is stable.
    for language in LSPConfig.LANGUAGE_EXTENSIONS:
        if counts.get(language) == best:
            logger.info(
                "Project language: %s (%s)",
                language,
                ", ".join(f"{lang} {n}" for lang, n in counts.most_common()),
            )
            return language
    return None


def default_language_support() -> Mapping[str, LanguageSupport]:
    """The languages we can serve, and how to tell whether we can serve them."""
    import shutil

    from isitsecure.engine.code_analysis.lsp.java_client import JavaLSPClient
    from isitsecure.engine.code_analysis.lsp.python_client import PythonLSPClient
    from isitsecure.engine.code_analysis.lsp.tsserver_client import (
        TypeScriptLSPClient,
    )

    def typescript_available() -> bool:
        return TypeScriptLSPClient.is_node_available() and any(
            shutil.which(binary)
            for binary in ("typescript-language-server", "npx")
        )

    return {
        "typescript": (typescript_available, TypeScriptLSPClient),
        "python": (PythonLSPClient.is_server_available, PythonLSPClient),
        "java": (
            lambda: JavaLSPClient.is_runtime_available()
            and JavaLSPClient.is_server_available(),
            JavaLSPClient,
        ),
    }


class LanguageRoutingLSPClient:
    """An ``LSPClientProtocol`` that picks its concrete client per project."""

    def __init__(
        self, support: Mapping[str, LanguageSupport] | None = None
    ) -> None:
        self._support = support
        self._delegate: LSPClientProtocol | None = None
        self._last_error: str | None = None

    @property
    def is_available(self) -> bool:
        return self._delegate is not None and self._delegate.is_available

    @property
    def last_error(self) -> str | None:
        if self._delegate is not None and self._delegate.last_error:
            return self._delegate.last_error
        return self._last_error

    async def initialize(self, project_path: str) -> bool:
        self._delegate = None
        self._last_error = None

        support = self._support
        if support is None:
            support = default_language_support()

        language = detect_project_language(project_path)
        if language is None:
            self._last_error = LSPConfig.MSG_LANGUAGE_UNRECOGNISED
            logger.info(LSPConfig.MSG_LANGUAGE_UNRECOGNISED)
            return False

        entry = support.get(language)
        if entry is None or not entry[0]():
            self._last_error = LSPConfig.MSG_NO_SERVER_FOR_LANGUAGE.format(
                language=language
            )
            logger.warning(self._last_error)
            return False

        delegate = entry[1]()
        logger.info(
            "LSP: using %s for this %s project",
            type(delegate).__name__,
            language,
        )
        initialized = await delegate.initialize(project_path)
        # Keep the delegate either way: a failed one still knows why.
        self._delegate = delegate
        return initialized

    async def get_definition(
        self, file_path: str, line: int, character: int
    ) -> list[LSPLocation] | None:
        if self._delegate is None:
            return None
        return await self._delegate.get_definition(file_path, line, character)

    async def get_references(
        self, file_path: str, line: int, character: int
    ) -> list[LSPLocation] | None:
        if self._delegate is None:
            return None
        return await self._delegate.get_references(file_path, line, character)

    async def get_hover(
        self, file_path: str, line: int, character: int
    ) -> str | None:
        if self._delegate is None:
            return None
        return await self._delegate.get_hover(file_path, line, character)

    async def shutdown(self) -> None:
        if self._delegate is not None:
            await self._delegate.shutdown()
            self._delegate = None
