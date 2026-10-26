"""CSRF forged-origin verdict regressions (batch D2)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from isitsecure.engine.constants import CSRFConfig
from isitsecure.engine.enums import EndpointMethod, SeverityLevel
from isitsecure.engine.ingestion.snapshot import CodebaseSnapshot, HTTPHeadersData
from isitsecure.engine.models import DiscoveredEndpoint
from isitsecure.engine.scanners.csrf_scanner import CSRFScanner


def _resp(status: int, text: str, ctype: str = "application/json") -> MagicMock:
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {"content-type": ctype}
    return r


async def _run_forged(responses, auth_headers=None):
    """Run the forged-origin phase with queued (forged, control) responses."""
    scanner = CSRFScanner()
    if auth_headers is not None:
        scanner._auth_headers = auth_headers
    ep = DiscoveredEndpoint(
        url="https://example.com/api/deals", method=EndpointMethod.POST
    )
    with patch(
        "isitsecure.engine.scanners.csrf_scanner.RateLimitedClient"
    ) as MockClient:
        client_instance = AsyncMock()
        client_instance.request = AsyncMock(side_effect=responses)
        MockClient.return_value.__aenter__ = AsyncMock(
            return_value=client_instance
        )
        MockClient.return_value.__aexit__ = AsyncMock(return_value=False)
        findings = await scanner.scan(endpoints=[ep])
    return [f for f in findings if f.title == CSRFConfig.TITLE_FORGED_ORIGIN]


class TestForgedOriginVerdicts:
    @pytest.mark.asyncio
    async def test_html_shell_not_reported(self) -> None:
        shell = "<!doctype html><html><body><div id=root></div></body></html>"
        out = await _run_forged(
            [_resp(200, shell, "text/html"), _resp(200, shell, "text/html")]
        )
        assert out == []

    @pytest.mark.asyncio
    async def test_json_success_false_not_reported(self) -> None:
        body = '{"success": false, "error": "bad input"}'
        assert await _run_forged([_resp(200, body), _resp(200, body)]) == []

    @pytest.mark.asyncio
    async def test_bearer_only_auth_skipped(self) -> None:
        out = await _run_forged(
            [_resp(200, '{"id": 1}')] * 2,
            auth_headers={"Authorization": "Bearer abc"},
        )
        assert out == []

    @pytest.mark.asyncio
    async def test_origin_validated_forged_rejected(self) -> None:
        out = await _run_forged([_resp(403, "forbidden")])
        assert out == []

    @pytest.mark.asyncio
    async def test_control_failing_not_reported(self) -> None:
        out = await _run_forged([_resp(200, '{"id": 1}'), _resp(400, "bad")])
        assert out == []

    @pytest.mark.asyncio
    async def test_positive_control_unvalidated_state_change_reported(self) -> None:
        out = await _run_forged([_resp(200, '{"id": 7}'), _resp(200, '{"id": 8}')])
        assert len(out) == 1
        assert out[0].severity == SeverityLevel.HIGH

    @pytest.mark.asyncio
    async def test_positive_control_cookie_auth_empty_204_reported(self) -> None:
        out = await _run_forged(
            [_resp(204, ""), _resp(204, "")],
            auth_headers={"Cookie": "sid=abc"},
        )
        assert len(out) == 1

    def test_hidden_input_name_before_type_seen(self) -> None:
        html = (
            '<form method="POST" action="/x">'
            '<input name="csrf_token" type="hidden" value="t"/></form>'
        )
        snap = CodebaseSnapshot(
            url="https://example.com",
            html_content=html,
            headers=HTTPHeadersData(raw_headers={}, status_code=200, cookies=[]),
        )
        assert CSRFScanner()._check_forms_for_csrf_tokens(snap) == []
