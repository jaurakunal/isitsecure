"""Path-containment helper for writing files back into a scanned repo.

Fix targets come from untrusted sources (scanned-repo file names, LLM output),
so a raw ``open(os.path.join(repo, path))`` is a path-traversal / arbitrary-
file-write primitive: an absolute ``path`` discards the repo base, and ``..``
escapes it. Every write into the repo must go through :func:`resolve_within`.
"""

from __future__ import annotations

import os


def resolve_within(base: str, relative: str) -> str:
    """Resolve ``relative`` under ``base``; raise if it escapes ``base``.

    Returns the absolute, real path to write to. Rejects absolute paths and
    ``..`` traversal that would land outside the repository.
    """
    base_real = os.path.realpath(base)
    target = os.path.realpath(os.path.join(base_real, relative))
    if target != base_real and not target.startswith(base_real + os.sep):
        raise ValueError(
            f"Refusing to write outside the repository: {relative!r}"
        )
    return target
