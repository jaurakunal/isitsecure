"""The mutation-IDOR probes must not mistake the SPA shell for a write.

A code-split front end serves index.html (200 text/html) for any path its
router doesn't know, so a PUT/PATCH/DELETE to a non-existent server route comes
back 2xx and read as a CRITICAL unauthorized change. 13 of 15 mutation-IDOR
findings on Juice Shop were exactly this.
"""

from __future__ import annotations

import httpx

from isitsecure.engine.scanners.idor_scanner import _is_spa_shell


def _resp(status=200, ctype="application/json", body="") -> httpx.Response:
    return httpx.Response(status_code=status,
                          headers={"content-type": ctype},
                          content=body.encode())


class TestIsSpaShell:
    def test_html_content_type_is_shell(self) -> None:
        assert _is_spa_shell(_resp(ctype="text/html; charset=utf-8",
                                   body="<!DOCTYPE html><html>...</html>"))

    def test_html_body_without_content_type_is_shell(self) -> None:
        # Some servers omit/mislabel the content-type; sniff the body too.
        assert _is_spa_shell(_resp(ctype="", body="<!-- Juice Shop -->\n<html>"))

    def test_json_write_response_is_not_shell(self) -> None:
        assert not _is_spa_shell(
            _resp(body='{"status":"success","data":{"id":1}}')
        )

    def test_empty_204_is_not_shell(self) -> None:
        # A real API accept with no body must still count as a write.
        assert not _is_spa_shell(_resp(status=204, ctype="", body=""))

    def test_plain_text_ok_is_not_shell(self) -> None:
        assert not _is_spa_shell(_resp(ctype="text/plain", body="OK"))
