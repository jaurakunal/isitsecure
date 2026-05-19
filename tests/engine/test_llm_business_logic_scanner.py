"""Tests for the LLM business logic attack scanner."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from isitsecure.engine.auth.protocols import AuthSession
from isitsecure.engine.constants import LLMBusinessLogicConfig
from isitsecure.engine.enums import AuthProvider, EndpointMethod
from isitsecure.engine.models import DiscoveredEndpoint
from isitsecure.engine.scanners.llm_business_logic_scanner import (
    LLMBusinessLogicScanner,
)
from isitsecure.engine.enums import SeverityLevel


def _make_session(token: str = "test-token", user_id: str = "user-1") -> AuthSession:
    return AuthSession(
        user_id=user_id, access_token=token, provider=AuthProvider.SUPABASE,
    )


def _make_endpoint(url: str, method: str = "GET") -> DiscoveredEndpoint:
    return DiscoveredEndpoint(url=url, method=EndpointMethod(method))


class TestFileSelection:

    def test_selects_business_logic_files(self):
        scanner = LLMBusinessLogicScanner(llm_client=AsyncMock())
        files = {
            "src/server/routers/deal.ts": "export const deal = ...",
            "src/server/routers/payment.ts": "export const payment = ...",
            "src/components/Button.tsx": "export const Button = ...",
            "src/utils/format.ts": "export function format() {}",
        }
        selected = scanner._select_files(files)
        assert "src/server/routers/deal.ts" in selected
        assert "src/server/routers/payment.ts" in selected
        assert "src/components/Button.tsx" not in selected

    def test_skips_test_files(self):
        scanner = LLMBusinessLogicScanner(llm_client=AsyncMock())
        files = {
            "src/server/routers/deal.test.ts": "test code",
            "tests/payment.spec.ts": "test code",
            "src/server/routers/deal.ts": "real code",
        }
        selected = scanner._select_files(files)
        assert len(selected) == 1
        assert "src/server/routers/deal.ts" in selected

    def test_skips_node_modules(self):
        scanner = LLMBusinessLogicScanner(llm_client=AsyncMock())
        files = {
            "node_modules/express/router.js": "framework code",
            "src/server/routers/deal.ts": "real code",
        }
        selected = scanner._select_files(files)
        assert len(selected) == 1

    def test_limits_file_count(self):
        scanner = LLMBusinessLogicScanner(llm_client=AsyncMock())
        files = {
            f"src/server/routers/route_{i}.ts": f"code {i}"
            for i in range(30)
        }
        selected = scanner._select_files(files)
        assert len(selected) <= LLMBusinessLogicConfig.MAX_FILES_FOR_ANALYSIS

    def test_sends_full_file_content(self):
        """With MAX_FILE_CHARS=0, files are sent without truncation."""
        scanner = LLMBusinessLogicScanner(llm_client=AsyncMock())
        long_content = "x" * 50000
        files = {"src/server/routers/deal.ts": long_content}
        selected = scanner._select_files(files)
        assert len(selected["src/server/routers/deal.ts"]) == 50000


class TestFrameworkDetection:

    def test_detects_trpc(self):
        assert LLMBusinessLogicScanner._detect_framework(
            {"src/server/trpc/router.ts": "code"}
        ) == "tRPC/Next.js"

    def test_detects_nextjs(self):
        assert LLMBusinessLogicScanner._detect_framework(
            {"src/pages/api/deals.ts": "code"}
        ) == "Next.js"

    def test_detects_express(self):
        assert LLMBusinessLogicScanner._detect_framework(
            {"src/express/routes.js": "code"}
        ) == "Express.js"

    def test_unknown_framework(self):
        assert LLMBusinessLogicScanner._detect_framework(
            {"src/main.rs": "code"}
        ) == "unknown"


class TestParseAttackPlans:

    def test_parses_valid_json(self):
        response = json.dumps({
            "attack_plans": [
                {
                    "title": "Test vuln",
                    "severity": "HIGH",
                    "steps": [{"action": "request", "method": "GET", "url": "https://x.com"}],
                }
            ]
        })
        plans = LLMBusinessLogicScanner._parse_attack_plans(response)
        assert len(plans) == 1
        assert plans[0]["title"] == "Test vuln"

    def test_parses_markdown_wrapped_json(self):
        response = "```json\n" + json.dumps({
            "attack_plans": [{"title": "test", "steps": [{"action": "request"}]}]
        }) + "\n```"
        plans = LLMBusinessLogicScanner._parse_attack_plans(response)
        assert len(plans) == 1

    def test_returns_empty_for_no_plans(self):
        response = json.dumps({"attack_plans": []})
        plans = LLMBusinessLogicScanner._parse_attack_plans(response)
        assert plans == []

    def test_returns_empty_for_invalid_json(self):
        plans = LLMBusinessLogicScanner._parse_attack_plans("not json")
        assert plans == []

    def test_skips_plans_without_steps(self):
        response = json.dumps({
            "attack_plans": [
                {"title": "no steps"},
                {"title": "has steps", "steps": [{"action": "request"}]},
            ]
        })
        plans = LLMBusinessLogicScanner._parse_attack_plans(response)
        assert len(plans) == 1


class TestParseJsonResponse:

    def test_parses_clean_json(self):
        result = LLMBusinessLogicScanner._parse_json_response('{"key": "value"}')
        assert result == {"key": "value"}

    def test_strips_markdown_fences(self):
        result = LLMBusinessLogicScanner._parse_json_response(
            '```json\n{"key": "value"}\n```'
        )
        assert result == {"key": "value"}

    def test_extracts_json_from_text(self):
        result = LLMBusinessLogicScanner._parse_json_response(
            'Here is the result: {"confirmed": true}'
        )
        assert result == {"confirmed": True}

    def test_returns_none_for_garbage(self):
        assert LLMBusinessLogicScanner._parse_json_response("garbage") is None


class TestScannerName:

    def test_scanner_name(self):
        scanner = LLMBusinessLogicScanner(llm_client=AsyncMock())
        assert scanner.scanner_name == LLMBusinessLogicConfig.SCANNER_NAME


class TestFullScanFlow:

    @pytest.mark.asyncio
    async def test_returns_empty_for_no_relevant_files(self):
        mock_llm = AsyncMock()
        scanner = LLMBusinessLogicScanner(llm_client=mock_llm)

        findings = await scanner.scan(
            repo_files={"README.md": "# Hello"},
            endpoints=[_make_endpoint("https://x.com/api/deals")],
            admin_session=_make_session(token="admin"),
            regular_session=_make_session(token="regular"),
            target_url="https://x.com",
        )
        assert findings == []
        mock_llm.generate_with_system.assert_not_called()

    @pytest.mark.asyncio
    async def test_generates_plans_and_executes(self):
        mock_llm = AsyncMock()

        # First call: generate attack plans
        mock_llm.generate_with_system.side_effect = [
            json.dumps({
                "attack_plans": [{
                    "title": "IDOR in deal update",
                    "severity": "HIGH",
                    "description": "Regular user can update any deal",
                    "affected_file": "src/server/routers/deal.ts",
                    "affected_line": 42,
                    "success_criteria": "HTTP 200 on unauthorized update",
                    "steps": [
                        {
                            "action": "request",
                            "user": "regular_user",
                            "method": "PATCH",
                            "url": "https://x.com/api/deals/123",
                            "body": {"title": "hacked"},
                            "description": "Update deal as regular user",
                            "expect": "Should get 403 but gets 200",
                        }
                    ],
                }]
            }),
            # Second call: analyze results
            json.dumps({
                "confirmed": True,
                "confidence": 0.9,
                "evidence": "Got HTTP 200 with modified title",
                "severity": "HIGH",
                "remediation": "Add ownership check",
            }),
        ]

        scanner = LLMBusinessLogicScanner(llm_client=mock_llm)

        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.request = AsyncMock(
                return_value=httpx.Response(
                    200, text='{"title":"hacked"}',
                    request=httpx.Request("PATCH", "https://x.com"),
                )
            )
            MockClient.return_value.__aenter__ = AsyncMock(return_value=client_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await scanner.scan(
                repo_files={"src/server/routers/deal.ts": "export const update = ..."},
                endpoints=[_make_endpoint("https://x.com/api/deals/123", "PATCH")],
                admin_session=_make_session(token="admin", user_id="admin-1"),
                regular_session=_make_session(token="regular", user_id="regular-1"),
                target_url="https://x.com",
            )

        assert len(findings) == 1
        assert findings[0].severity == SeverityLevel.HIGH
        assert "IDOR" in findings[0].title
        assert findings[0].code_location is not None
        assert findings[0].code_location.file_path == "src/server/routers/deal.ts"

    @pytest.mark.asyncio
    async def test_no_finding_when_attack_not_confirmed(self):
        mock_llm = AsyncMock()
        mock_llm.generate_with_system.side_effect = [
            json.dumps({
                "attack_plans": [{
                    "title": "Test",
                    "steps": [{"method": "GET", "url": "https://x.com/api", "user": "regular_user"}],
                    "success_criteria": "test",
                }]
            }),
            json.dumps({"confirmed": False, "confidence": 0.2}),
        ]

        scanner = LLMBusinessLogicScanner(llm_client=mock_llm)

        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.request = AsyncMock(
                return_value=httpx.Response(
                    403, text='{"error":"forbidden"}',
                    request=httpx.Request("GET", "https://x.com"),
                )
            )
            MockClient.return_value.__aenter__ = AsyncMock(return_value=client_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await scanner.scan(
                repo_files={"src/server/routers/deal.ts": "code"},
                endpoints=[_make_endpoint("https://x.com/api")],
                admin_session=_make_session(token="admin"),
                regular_session=_make_session(token="regular"),
                target_url="https://x.com",
            )

        assert findings == []
