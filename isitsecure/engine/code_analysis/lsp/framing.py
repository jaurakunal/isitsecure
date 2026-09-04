"""Reading LSP messages off a server's stdout.

The wire format is HTTP-like: a header block, a blank line, then exactly
``Content-Length`` bytes of JSON.

DRY: every client reads the same format, so the framing lives here rather than
once per client.

The header block is a *block* — that is the whole point of this module. Both
readers used to take ``Content-Length`` and then consume a single line as the
separator, which works only for a server that sends no other header. pylsp
sends the ``Content-Type`` the spec explicitly permits::

    Content-Length: 888
    Content-Type: application/vscode-jsonrpc; charset=utf8

so that lone ``readline()`` ate the Content-Type, the body read then started on
the real blank line, and every message came back truncated by two bytes —
killing the reader task and leaving initialization to time out 30s later with
"no response from the server".
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

logger = logging.getLogger(__name__)

_CONTENT_LENGTH = "content-length"
_CONTENT_TYPE = "content-type"


async def read_message(stream: asyncio.StreamReader) -> dict[str, Any] | None:
    """Read one framed LSP message, or ``None`` at end of stream.

    Raises ``asyncio.IncompleteReadError`` if the stream ends mid-body and
    ``json.JSONDecodeError`` if the body is not JSON — both of which the
    caller reports rather than swallowing.
    """
    content_length: int | None = None

    while True:
        line = await stream.readline()
        if not line:
            return None  # EOF — the server exited
        text = line.decode(errors="replace").strip()

        if not text:
            if content_length is None:
                # A blank line before any header is noise, not a separator.
                continue
            break  # end of the header block; the body follows

        name, _, value = text.partition(":")
        name = name.strip().lower()
        if name == _CONTENT_LENGTH:
            try:
                content_length = int(value.strip())
            except ValueError:
                logger.debug("LSP: unparseable Content-Length: %s", text[:200])
        elif name != _CONTENT_TYPE:
            # Not a header we know — usually npx/tooling chatter on stdout.
            logger.debug("LSP stdout (non-header): %s", text[:200])

    body = await stream.readexactly(content_length)
    return json.loads(body.decode())
