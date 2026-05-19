"""Shared JWT decoding utilities for deep security scanners."""

from __future__ import annotations

import base64
import json
import logging
from typing import Any

logger = logging.getLogger(__name__)

JWT_PARTS_COUNT = 3
JWT_HEADER_INDEX = 0
JWT_PAYLOAD_INDEX = 1


def decode_jwt_payload(token: str) -> dict[str, Any] | None:
    """Decode JWT payload without verification using base64.

    Args:
        token: The raw JWT string (header.payload.signature).

    Returns:
        The decoded payload as a dict, or None if decoding fails.
    """
    try:
        parts = token.split(".")
        if len(parts) != JWT_PARTS_COUNT:
            return None

        payload_b64 = parts[JWT_PAYLOAD_INDEX]
        # Add padding
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += "=" * padding

        payload_bytes = base64.urlsafe_b64decode(payload_b64)
        return json.loads(payload_bytes)
    except Exception as exc:
        logger.debug("Failed to decode JWT payload: %s", exc)
        return None


def decode_jwt_header(token: str) -> dict[str, Any] | None:
    """Decode JWT header without verification using base64.

    Args:
        token: The raw JWT string (header.payload.signature).

    Returns:
        The decoded header as a dict, or None if decoding fails.
    """
    try:
        parts = token.split(".")
        if len(parts) != JWT_PARTS_COUNT:
            return None

        header_b64 = parts[JWT_HEADER_INDEX]
        padding = 4 - len(header_b64) % 4
        if padding != 4:
            header_b64 += "=" * padding

        header_bytes = base64.urlsafe_b64decode(header_b64)
        return json.loads(header_bytes)
    except Exception:
        return None
