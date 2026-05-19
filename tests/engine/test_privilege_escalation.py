"""Tests for the privilege escalation scanner (all 8 tests + helpers)."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from isitsecure.engine.auth.protocols import AuthSession
from isitsecure.engine.constants import PrivilegeEscalationConfig
from isitsecure.engine.enums import AuthProvider, EndpointMethod
from isitsecure.engine.models import (
    DiscoveredEndpoint,
    FindingSource,
    InterceptedRequest,
)
from isitsecure.engine.scanners.privilege_escalation_scanner import (
    PrivilegeEscalationScanner,
)
from isitsecure.engine.enums import FindingCategory, SeverityLevel

SUPABASE_URL = "https://test-project.supabase.co"
ANON_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.signature"


# --- Helpers ---


def _make_session(
    user_id: str = "regular-user-id", token: str = "regular-token",
) -> AuthSession:
    return AuthSession(
        user_id=user_id, access_token=token, provider=AuthProvider.SUPABASE,
    )


def _make_response(status_code: int = 200, body: str = "") -> httpx.Response:
    return httpx.Response(
        status_code=status_code, text=body,
        request=httpx.Request("GET", "https://test.com"),
    )


def _make_endpoint(
    url: str = "https://example.com/api/admin/users",
    method: EndpointMethod = EndpointMethod.GET,
    requires_auth: bool | None = None,
) -> DiscoveredEndpoint:
    return DiscoveredEndpoint(url=url, method=method, requires_auth=requires_auth)


def _patch_client(mock_client: AsyncMock):
    return patch(
        "isitsecure.engine.scanners.privilege_escalation_scanner.RateLimitedClient",
        return_value=mock_client,
    )


def _mock_client_with(
    get_response: httpx.Response | None = None,
    patch_response: httpx.Response | None = None,
    post_response: httpx.Response | None = None,
    request_response: httpx.Response | None = None,
) -> AsyncMock:
    client = AsyncMock()
    client.get = AsyncMock(return_value=get_response or _make_response(401))
    client.patch = AsyncMock(return_value=patch_response or _make_response(403))
    client.post = AsyncMock(return_value=post_response or _make_response(403))
    client.request = AsyncMock(return_value=request_response or _make_response(403))
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    return client


# --- Classification Helpers ---


class TestClassificationHelpers:

    def test_scanner_name(self):
        assert PrivilegeEscalationScanner().scanner_name == PrivilegeEscalationConfig.SCANNER_NAME

    def test_is_admin_table(self):
        s = PrivilegeEscalationScanner()
        assert s._is_admin_table("admin_users") is True
        assert s._is_admin_table("user_roles") is True
        assert s._is_admin_table("audit_logs") is True
        assert s._is_admin_table("profiles") is False

    def test_is_role_table(self):
        s = PrivilegeEscalationScanner()
        assert s._is_role_table("user_roles") is True
        assert s._is_role_table("permissions") is True
        assert s._is_role_table("profiles") is False
        assert s._is_role_table("deals") is False

    def test_is_admin_endpoint(self):
        s = PrivilegeEscalationScanner()
        assert s._is_admin_endpoint(_make_endpoint("https://x.com/api/admin/users")) is True
        assert s._is_admin_endpoint(_make_endpoint("https://x.com/settings/general")) is True
        assert s._is_admin_endpoint(_make_endpoint("https://x.com/api/users")) is False

    def test_count_json_records_array(self):
        assert PrivilegeEscalationScanner._count_json_records('[{"id":1},{"id":2}]') == 2

    def test_count_json_records_object_with_data(self):
        assert PrivilegeEscalationScanner._count_json_records('{"data":[1,2,3]}') == 3

    def test_count_json_records_object_with_results(self):
        assert PrivilegeEscalationScanner._count_json_records('{"results":[1]}') == 1

    def test_count_json_records_plain_object(self):
        assert PrivilegeEscalationScanner._count_json_records('{"id":1}') == 1

    def test_count_json_records_invalid_json(self):
        assert PrivilegeEscalationScanner._count_json_records("not json") == 0

    def test_count_json_records_empty_array(self):
        assert PrivilegeEscalationScanner._count_json_records("[]") == 0

    def test_build_auth_headers(self):
        session = _make_session(token="my-token")
        headers = PrivilegeEscalationScanner._build_auth_headers(session)
        assert headers["Authorization"] == "Bearer my-token"

    def test_build_supabase_headers(self):
        session = _make_session(token="my-token")
        headers = PrivilegeEscalationScanner._build_supabase_headers(session, "anon-key")
        assert headers["Authorization"] == "Bearer my-token"
        assert headers["apikey"] == "anon-key"


# --- Test 1: Admin Table Access ---


class TestAdminTableAccess:

    @pytest.mark.asyncio
    async def test_detects_readable_admin_table(self):
        scanner = PrivilegeEscalationScanner()
        client = _mock_client_with(get_response=_make_response(200, '[{"id":"1"}]'))
        with _patch_client(client):
            findings = await scanner.scan(
                _make_session(), supabase_url=SUPABASE_URL,
                anon_key=ANON_KEY, tables=["admin_users"],
            )
        admin = [f for f in findings if "admin table" in f.title.lower()]
        assert len(admin) == 1
        assert admin[0].severity == SeverityLevel.HIGH

    @pytest.mark.asyncio
    async def test_blocked_admin_table(self):
        scanner = PrivilegeEscalationScanner()
        client = _mock_client_with(get_response=_make_response(401))
        with _patch_client(client):
            findings = await scanner.scan(
                _make_session(), supabase_url=SUPABASE_URL,
                anon_key=ANON_KEY, tables=["admin_users"],
            )
        assert not [f for f in findings if "admin table" in f.title.lower()]

    @pytest.mark.asyncio
    async def test_empty_response_safe(self):
        scanner = PrivilegeEscalationScanner()
        client = _mock_client_with(get_response=_make_response(200, "[]"))
        with _patch_client(client):
            findings = await scanner.scan(
                _make_session(), supabase_url=SUPABASE_URL,
                anon_key=ANON_KEY, tables=["admin_users"],
            )
        assert not [f for f in findings if "admin table" in f.title.lower()]


# --- Test 2: Role Self-Elevation ---


class TestRoleEscalation:

    @pytest.mark.asyncio
    async def test_detects_role_escalation(self):
        scanner = PrivilegeEscalationScanner()
        client = _mock_client_with(patch_response=_make_response(204))
        with _patch_client(client):
            findings = await scanner.scan(
                _make_session(), supabase_url=SUPABASE_URL,
                anon_key=ANON_KEY, tables=["user_roles"],
            )
        role = [f for f in findings if "modify their own role" in f.title.lower()]
        assert len(role) >= 1
        assert all(f.severity == SeverityLevel.CRITICAL for f in role)

    @pytest.mark.asyncio
    async def test_role_escalation_blocked(self):
        scanner = PrivilegeEscalationScanner()
        client = _mock_client_with(patch_response=_make_response(403))
        with _patch_client(client):
            findings = await scanner.scan(
                _make_session(), supabase_url=SUPABASE_URL,
                anon_key=ANON_KEY, tables=["user_roles"],
            )
        assert not [f for f in findings if "modify their own role" in f.title.lower()]


# --- Test 3: Admin Route ---


class TestAdminRouteAccess:

    @pytest.mark.asyncio
    async def test_detects_accessible_admin_route(self):
        scanner = PrivilegeEscalationScanner()
        client = _mock_client_with(get_response=_make_response(200, '{"users":[]}'))
        ep = _make_endpoint("https://example.com/api/admin/users")
        with _patch_client(client):
            findings = await scanner.scan(_make_session(), endpoints=[ep])
        route = [f for f in findings if "admin endpoint" in f.title.lower()]
        assert len(route) == 1
        assert route[0].severity == SeverityLevel.HIGH

    @pytest.mark.asyncio
    async def test_admin_route_blocked(self):
        scanner = PrivilegeEscalationScanner()
        client = _mock_client_with(get_response=_make_response(403))
        ep = _make_endpoint("https://example.com/api/admin/users")
        with _patch_client(client):
            findings = await scanner.scan(_make_session(), endpoints=[ep])
        assert not [f for f in findings if "admin endpoint" in f.title.lower()]


# --- Test 4: Authenticated Endpoint Access ---


class TestAuthEndpointAccess:

    @pytest.mark.asyncio
    async def test_regular_user_accesses_auth_endpoint(self):
        scanner = PrivilegeEscalationScanner()
        client = _mock_client_with(get_response=_make_response(200, '{"data":"ok"}'))
        ep = _make_endpoint(
            "https://example.com/api/deals", requires_auth=True,
        )
        with _patch_client(client):
            findings = await scanner.scan(_make_session(), endpoints=[ep])
        auth = [f for f in findings if "authenticated endpoint" in f.title.lower()]
        assert len(auth) == 1
        assert auth[0].severity == SeverityLevel.MEDIUM

    @pytest.mark.asyncio
    async def test_auth_endpoint_blocked(self):
        scanner = PrivilegeEscalationScanner()
        client = _mock_client_with(get_response=_make_response(403))
        ep = _make_endpoint(
            "https://example.com/api/deals", requires_auth=True,
        )
        with _patch_client(client):
            findings = await scanner.scan(_make_session(), endpoints=[ep])
        assert not [f for f in findings if "authenticated endpoint" in f.title.lower()]

    @pytest.mark.asyncio
    async def test_non_auth_endpoint_skipped(self):
        scanner = PrivilegeEscalationScanner()
        client = _mock_client_with(get_response=_make_response(200))
        ep = _make_endpoint("https://example.com/api/public", requires_auth=None)
        with _patch_client(client):
            findings = await scanner.scan(_make_session(), endpoints=[ep])
        assert not [f for f in findings if "authenticated endpoint" in f.title.lower()]

    @pytest.mark.asyncio
    async def test_write_method_uses_request(self):
        scanner = PrivilegeEscalationScanner()
        client = _mock_client_with(request_response=_make_response(201, '{}'))
        ep = _make_endpoint(
            "https://example.com/api/deals",
            method=EndpointMethod.POST, requires_auth=True,
        )
        with _patch_client(client):
            findings = await scanner.scan(_make_session(), endpoints=[ep])
        auth = [f for f in findings if "authenticated endpoint" in f.title.lower()]
        assert len(auth) == 1


# --- Test 5: Differential Response ---


class TestDifferentialResponse:

    @pytest.mark.asyncio
    async def test_detects_differential(self):
        scanner = PrivilegeEscalationScanner()
        admin_session = _make_session(user_id="admin", token="admin-token")
        regular_session = _make_session()

        # Admin gets 100 records, regular gets 5
        admin_body = json.dumps([{"id": i} for i in range(100)])
        regular_body = json.dumps([{"id": i} for i in range(5)])

        call_count = 0

        async def mock_get(url, **kwargs):
            nonlocal call_count
            call_count += 1
            auth = kwargs.get("headers", {}).get("Authorization", "")
            if "admin-token" in auth:
                return _make_response(200, admin_body)
            return _make_response(200, regular_body)

        client = _mock_client_with()
        client.get = mock_get
        ep = _make_endpoint("https://example.com/trpc/deals", requires_auth=True)

        with _patch_client(client):
            findings = await scanner.scan(
                regular_session, admin_session=admin_session, endpoints=[ep],
            )
        diff = [f for f in findings if "admin sees more data" in f.title.lower()]
        assert len(diff) == 1
        assert diff[0].severity == SeverityLevel.HIGH

    @pytest.mark.asyncio
    async def test_same_size_no_finding(self):
        scanner = PrivilegeEscalationScanner()
        body = json.dumps([{"id": i} for i in range(10)])
        client = _mock_client_with(get_response=_make_response(200, body))
        ep = _make_endpoint("https://example.com/api/deals", requires_auth=True)
        with _patch_client(client):
            findings = await scanner.scan(
                _make_session(),
                admin_session=_make_session(token="admin"),
                endpoints=[ep],
            )
        assert not [f for f in findings if "admin sees more data" in f.title.lower()]


# --- Test 6: Mutation Replay ---


class TestMutationReplay:

    @pytest.mark.asyncio
    async def test_detects_mutation_replay(self):
        scanner = PrivilegeEscalationScanner()
        intercepted = [
            InterceptedRequest(
                url="https://example.com/api/deals",
                method="POST",
                response_status=201,
                request_body='{"title":"New Deal"}',
            ),
        ]
        client = _mock_client_with(request_response=_make_response(201, '{"id":"new"}'))
        with _patch_client(client):
            findings = await scanner.scan(
                _make_session(), intercepted_requests=intercepted,
            )
        replay = [f for f in findings if "admin mutation" in f.title.lower()]
        assert len(replay) == 1
        assert replay[0].severity == SeverityLevel.HIGH

    @pytest.mark.asyncio
    async def test_mutation_replay_blocked(self):
        scanner = PrivilegeEscalationScanner()
        intercepted = [
            InterceptedRequest(
                url="https://example.com/api/deals",
                method="POST", response_status=201,
            ),
        ]
        client = _mock_client_with(request_response=_make_response(403))
        with _patch_client(client):
            findings = await scanner.scan(
                _make_session(), intercepted_requests=intercepted,
            )
        assert not [f for f in findings if "admin mutation" in f.title.lower()]

    @pytest.mark.asyncio
    async def test_skips_failed_original_requests(self):
        scanner = PrivilegeEscalationScanner()
        intercepted = [
            InterceptedRequest(
                url="https://example.com/api/deals",
                method="POST", response_status=500,
            ),
        ]
        client = _mock_client_with(request_response=_make_response(201))
        with _patch_client(client):
            findings = await scanner.scan(
                _make_session(), intercepted_requests=intercepted,
            )
        assert not [f for f in findings if "admin mutation" in f.title.lower()]


# --- Test 7: Object-Level Write ---


class TestObjectLevelWrite:

    @pytest.mark.asyncio
    async def test_detects_cross_user_write(self):
        scanner = PrivilegeEscalationScanner()
        resources = {"deals": ["uuid-admin-deal-1"]}
        client = _mock_client_with(patch_response=_make_response(204))
        with _patch_client(client):
            findings = await scanner.scan(
                _make_session(), supabase_url=SUPABASE_URL,
                anon_key=ANON_KEY, owned_resource_ids=resources,
            )
        obj = [f for f in findings if "modify another user" in f.title.lower()]
        assert len(obj) == 1
        assert obj[0].severity == SeverityLevel.CRITICAL

    @pytest.mark.asyncio
    async def test_object_write_blocked(self):
        scanner = PrivilegeEscalationScanner()
        resources = {"deals": ["uuid-1"]}
        client = _mock_client_with(patch_response=_make_response(403))
        with _patch_client(client):
            findings = await scanner.scan(
                _make_session(), supabase_url=SUPABASE_URL,
                anon_key=ANON_KEY, owned_resource_ids=resources,
            )
        assert not [f for f in findings if "modify another user" in f.title.lower()]

    @pytest.mark.asyncio
    async def test_skips_path_based_keys(self):
        """Resource IDs keyed by API paths (not table names) should be skipped."""
        scanner = PrivilegeEscalationScanner()
        resources = {"/api/deals/123": ["uuid-1"]}
        client = _mock_client_with(patch_response=_make_response(204))
        with _patch_client(client):
            findings = await scanner.scan(
                _make_session(), supabase_url=SUPABASE_URL,
                anon_key=ANON_KEY, owned_resource_ids=resources,
            )
        assert not [f for f in findings if "modify another user" in f.title.lower()]


# --- Test 8: RPC Function Access ---


class TestRPCFunctionAccess:

    @pytest.mark.asyncio
    async def test_detects_rpc_access(self):
        scanner = PrivilegeEscalationScanner()
        client = _mock_client_with(post_response=_make_response(200, '{"result":42}'))
        with _patch_client(client):
            findings = await scanner.scan(
                _make_session(), supabase_url=SUPABASE_URL,
                anon_key=ANON_KEY, rpc_functions=["get_admin_stats"],
            )
        rpc = [f for f in findings if "server function" in f.title.lower()]
        assert len(rpc) == 1
        assert rpc[0].severity == SeverityLevel.HIGH

    @pytest.mark.asyncio
    async def test_rpc_blocked(self):
        scanner = PrivilegeEscalationScanner()
        client = _mock_client_with(post_response=_make_response(403))
        with _patch_client(client):
            findings = await scanner.scan(
                _make_session(), supabase_url=SUPABASE_URL,
                anon_key=ANON_KEY, rpc_functions=["admin_func"],
            )
        assert not [f for f in findings if "server function" in f.title.lower()]


# --- Error Handling ---


class TestErrorHandling:

    @pytest.mark.asyncio
    async def test_error_does_not_stop_scan(self):
        scanner = PrivilegeEscalationScanner()

        async def get_with_error(url, **kwargs):
            if "admin_bad" in url:
                raise httpx.ConnectError("Connection refused")
            return _make_response(200, '[{"id":"1"}]')

        client = AsyncMock()
        client.get = get_with_error
        client.patch = AsyncMock(return_value=_make_response(403))
        client.post = AsyncMock(return_value=_make_response(403))
        client.request = AsyncMock(return_value=_make_response(403))
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=False)

        with _patch_client(client):
            findings = await scanner.scan(
                _make_session(), supabase_url=SUPABASE_URL,
                anon_key=ANON_KEY, tables=["admin_bad", "admin_good"],
            )
        good = [f for f in findings if "admin_good" in f.title]
        assert len(good) == 1

    @pytest.mark.asyncio
    async def test_empty_inputs_no_crash(self):
        scanner = PrivilegeEscalationScanner()
        client = _mock_client_with()
        with _patch_client(client):
            findings = await scanner.scan(_make_session())
        assert findings == []


# --- _make_finding Helper ---


class TestMakeFinding:

    def test_creates_finding_with_common_fields(self):
        scanner = PrivilegeEscalationScanner()
        f = scanner._make_finding(
            SeverityLevel.HIGH, "Test Title", "Test desc", 0.9,
            "https://example.com/api", "GET", "response body",
        )
        assert f.source == FindingSource.DAST_AUTHENTICATED
        assert f.category == FindingCategory.PRIVILEGE_ESCALATION
        assert f.scanner_name == PrivilegeEscalationConfig.SCANNER_NAME
        assert f.severity == SeverityLevel.HIGH
        assert f.title == "Test Title"
