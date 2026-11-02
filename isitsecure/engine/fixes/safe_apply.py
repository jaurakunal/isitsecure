"""Loss-free application of generated fixes to a working tree.

Both the CLI (``isitsecure fix``) and the web fix-all service write the model's
final per-file contents back to disk. Doing that naively can destroy user data:

* the files were read minutes (LLM calls) before they are written, so a user
  edit made in between would be silently overwritten;
* a plain ``open(..., "wb")`` truncates in place, so a crash mid-write leaves a
  half-written file, and a permission change is lost on re-creation;
* when one write fails after others succeeded the tree is left half-fixed.

:func:`apply_file_fixes` fixes all three: it refuses (and reports) any file that
changed on disk since it was read, writes atomically (temp file in the same
directory + ``os.replace``, mode preserved, bytes/line endings exactly as given),
and rolls every already-written file back if a later write fails.

Path safety (confinement to the repo, ``.git`` refusal, symlink escape) is
delegated to ``resolve_fix_target`` so there is exactly one definition of it.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from dataclasses import dataclass, field

from isitsecure.engine.fixes.fix_generator import resolve_fix_target

_BOM = b"\xef\xbb\xbf"


@dataclass
class ApplyOutcome:
    """What an :func:`apply_file_fixes` call actually did, file by file."""

    written: list[str] = field(default_factory=list)  # fixed content is on disk
    stale: list[str] = field(default_factory=list)  # changed on disk since read; untouched
    failed: dict[str, str] = field(default_factory=dict)  # path -> write error
    rolled_back: list[str] = field(default_factory=list)  # written, then restored
    rollback_failed: dict[str, str] = field(default_factory=dict)  # path -> why not restored
    # path -> (original bytes, bytes we wrote); the undo log.
    _undo: dict[str, tuple[bytes, bytes]] = field(default_factory=dict, repr=False)

    @property
    def ok(self) -> bool:
        """True only when every requested file was written and nothing was undone."""
        return not (self.stale or self.failed or self.rolled_back or self.rollback_failed)

    @property
    def unapplied(self) -> list[str]:
        """Every path whose fix is NOT on disk (stale, failed, or rolled back)."""
        return [*self.stale, *self.failed, *self.rolled_back]


def encode_for_write(target: str, content: str) -> bytes:
    """UTF-8 bytes for ``content``, keeping the file's own BOM if the model dropped it."""
    data = content.encode("utf-8")
    if not data.startswith(_BOM):
        try:
            with open(target, "rb") as fh:
                if fh.read(3) == _BOM:
                    data = _BOM + data
        except OSError:
            pass
    return data


def atomic_write_bytes(target: str, data: bytes) -> None:
    """Replace ``target`` with ``data`` atomically, preserving its permission bits."""
    directory = os.path.dirname(target)
    fd, tmp = tempfile.mkstemp(prefix=".isitsecure-tmp-", dir=directory)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        try:
            shutil.copymode(target, tmp)
        except OSError:
            pass  # new file: keep mkstemp's private default
        os.replace(tmp, target)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _read_bytes(target: str) -> bytes | None:
    try:
        with open(target, "rb") as fh:
            return fh.read()
    except OSError:
        return None


def apply_file_fixes(
    repo_path: str,
    contents: dict[str, str],
    originals: dict[str, str],
) -> ApplyOutcome:
    """Write ``contents`` (path -> fixed text) into the repo, all-or-nothing per run.

    ``originals`` maps each path to the text the fix was generated from. A file
    whose on-disk bytes no longer equal that text is left untouched and listed in
    ``stale``. If any remaining write fails, every file written earlier in this
    call is restored and listed in ``rolled_back`` (or ``rollback_failed`` when it
    cannot be restored without clobbering a newer edit).
    """
    outcome = ApplyOutcome()
    plan: list[tuple[str, str, bytes, bytes]] = []  # path, target, original bytes, new bytes

    for path, new_text in contents.items():
        try:
            target = resolve_fix_target(repo_path, path)
        except ValueError as exc:
            outcome.failed[path] = str(exc)
            continue
        current = _read_bytes(target)
        if current is None:
            outcome.failed[path] = "could not read the file before writing"
            continue
        expected = originals.get(path)
        if expected is not None and current != expected.encode("utf-8"):
            outcome.stale.append(path)
            continue
        plan.append((path, target, current, encode_for_write(target, new_text)))

    if outcome.failed:
        # A path we cannot even resolve: do not start a partial write at all.
        return outcome

    for path, target, before, after in plan:
        try:
            atomic_write_bytes(target, after)
        except Exception as exc:  # noqa: BLE001 - report every OS-level failure
            outcome.failed[path] = f"{type(exc).__name__}: {exc}"
            rollback_applied(repo_path, outcome)
            return outcome
        outcome.written.append(path)
        outcome._undo[path] = (before, after)
    return outcome


def rollback_applied(repo_path: str, outcome: ApplyOutcome) -> None:
    """Restore every file ``outcome`` wrote, unless the user has edited it since."""
    for path in list(outcome.written):
        before, after = outcome._undo[path]
        try:
            target = resolve_fix_target(repo_path, path)
            if _read_bytes(target) != after:
                outcome.rollback_failed[path] = "changed again after the fix was written; left as is"
                continue
            atomic_write_bytes(target, before)
        except Exception as exc:  # noqa: BLE001
            outcome.rollback_failed[path] = f"{type(exc).__name__}: {exc}"
            continue
        outcome.written.remove(path)
        outcome.rolled_back.append(path)
