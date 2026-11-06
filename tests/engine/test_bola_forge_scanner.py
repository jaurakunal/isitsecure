"""Forged-ownership BOLA scanner (#278): body-supplied owner id, proven by re-read.

The fixture is a tiny in-process app modelling the owner-field handler three ways: trusting the
body (vulnerable), deriving the owner from the token (safe), and echoing the forged owner in the
response while persisting the real one (reflection only).
"""

from __future__ import annotations

import base64
import json
import uuid
from unittest.mock import AsyncMock, patch
from urllib.parse import urlparse

import httpx
import pytest

from isitsecure.engine.agent import DeepSecurityScanAgent
from isitsecure.engine.auth.protocols import AuthSession
from isitsecure.engine.enums import AuthProvider, FindingCategory, SeverityLevel
from isitsecure.engine.factory import create_deep_security_scan_agent
from isitsecure.engine.models import AuthenticatedCrawlResult, InterceptedRequest
from isitsecure.engine.scanners.bola_forge_scanner import (
    BolaForgeConfig,
    BolaForgeScanner,
    ForgeStatus,
    _find_identity_fields,
    _mark_free_text,
    identity_claims,
    is_dangerous_create,
    origin_of,
)

BASE = "https://shop.example.com"
COLLECTION = f"{BASE}/api/feedbacks"


def _jwt(claims: dict) -> str:
    def seg(obj: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")
    return f"{seg({'alg': 'none'})}.{seg(claims)}.sig"


def _session(user_id: str, **claims) -> AuthSession:
    return AuthSession(
        user_id=user_id, access_token=_jwt({"sub": user_id, "iat": 5, **claims}),
        provider=AuthProvider.TOKEN,
    )


def _captured(owner: str, extra: dict | None = None) -> InterceptedRequest:
    body = {"UserId": owner, "message": "great shop", "rating": 5, **(extra or {})}
    return InterceptedRequest(
        url=COLLECTION, method="POST", response_status=201, request_body=json.dumps(body),
    )


class FakeApp:
    """Feedback collection. ``trust_body``: persist the body owner; ``reflect``: echo only."""

    def __init__(self, tokens: dict[str, str], *, trust_body=False, reflect=False,
                 scoped=True, readable=True, reject_foreign=False, preexisting=()):
        self.tokens = tokens                      # access token -> user id
        self.trust_body, self.reflect, self.scoped = trust_body, reflect, scoped
        self.readable, self.reject_foreign = readable, reject_foreign
        self.records = [dict(r) for r in preexisting]
        self.calls: list[tuple[str, str]] = []
        self.requests: list[tuple[str, str, dict]] = []     # method, full url, headers

    async def __call__(self, method, url, **kw):
        self.calls.append((method, urlparse(url).path))
        self.requests.append((method, url, kw["headers"]))
        token = kw["headers"]["Authorization"].removeprefix("Bearer ")
        user = self.tokens[token]
        if not urlparse(url).path.startswith("/api/"):
            return httpx.Response(404, text="{}")
        if method == "POST":
            body = json.loads(kw["content"])
            if self.reject_foreign and body["UserId"] != user:
                return httpx.Response(403, text='{"error":"forbidden"}')
            record = {**body, "id": len(self.records) + 1,
                      "UserId": body["UserId"] if self.trust_body else user}
            self.records.append(record)
            shown = {**record, "UserId": body["UserId"]} if self.reflect else record
            return httpx.Response(201, json=shown)
        if not self.readable:
            return httpx.Response(404, text="{}")
        rows = [r for r in self.records if not self.scoped or r["UserId"] == user]
        return httpx.Response(200, json={"status": "success", "data": rows})


def _get(url: str) -> InterceptedRequest:
    return InterceptedRequest(url=url, method="GET", response_status=200)


async def _scan(app: FakeApp, session_a, session_b=None, *, probe_writes=True, captured=None,
                seed=True, target_url=BASE):
    """Run the scanner; like a real crawl, capture a GET per create and own one record."""
    scanner = BolaForgeScanner(probe_writes=probe_writes)
    with patch("isitsecure.engine.scanners.bola_forge_scanner.RateLimitedClient") as mock_client:
        client = AsyncMock()
        client.request = app
        mock_client.return_value.__aenter__ = AsyncMock(return_value=client)
        mock_client.return_value.__aexit__ = AsyncMock(return_value=False)
        owner = session_a.user_id if session_a else ""
        reqs = list(captured or [_captured(owner)])
        if seed and session_a:       # the worst case: an old record shaped like what we post
            first = json.loads(next(r.request_body for r in reqs if r.method == "POST"))
            app.records.append({**first, "id": 0, "UserId": owner, "message": "seed"})
        reqs += [_get(r.url) for r in reqs if r.method == "POST"]
        findings = await scanner.scan(reqs, session_a, session_b, target_url=target_url)
    return scanner, findings


def _pair(a="a" * 8 + "-1111", b="b" * 8 + "-2222"):
    sa, sb = _session(a), _session(b)
    return sa, sb, {sa.access_token: a, sb.access_token: b}


# ---------------------------------------------------------------- two identities

@pytest.mark.asyncio
async def test_vulnerable_scoped_listing_is_proven_high():
    sa, sb, tokens = _pair()
    app = FakeApp(tokens, trust_body=True, scoped=True)
    scanner, findings = await _scan(app, sa, sb)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == SeverityLevel.HIGH
    assert finding.category == FindingCategory.IDOR
    assert finding.confidence == BolaForgeConfig.CONFIDENCE_SCOPED
    assert "UserId" in finding.title
    assert BolaForgeConfig.MARKER_PREFIX in finding.request_payload
    assert scanner.outcomes[COLLECTION].status is ForgeStatus.PROVEN


@pytest.mark.asyncio
async def test_vulnerable_global_listing_with_opaque_ids_is_proven_lower_confidence():
    sa, sb, tokens = _pair(str(uuid.uuid4()), str(uuid.uuid4()))
    app = FakeApp(tokens, trust_body=True, scoped=False)
    _, findings = await _scan(app, sa, sb)
    assert len(findings) == 1
    assert findings[0].confidence == BolaForgeConfig.CONFIDENCE_FIELD_VALUE


@pytest.mark.asyncio
async def test_global_listing_with_short_numeric_ids_is_inconclusive():
    """'UserId == 2' on a global listing could be any unrelated numeric field."""
    sa, sb, tokens = _pair("1", "2")
    app = FakeApp(tokens, trust_body=True, scoped=False)
    scanner, findings = await _scan(app, sa, sb)
    assert findings == []
    assert scanner.outcomes[COLLECTION].status is ForgeStatus.INCONCLUSIVE


@pytest.mark.asyncio
async def test_safe_app_deriving_owner_from_token_is_not_reported():
    sa, sb, tokens = _pair()
    scanner, findings = await _scan(FakeApp(tokens, scoped=True), sa, sb)
    assert findings == []
    assert scanner.outcomes[COLLECTION].status is ForgeStatus.NOT_VULNERABLE


@pytest.mark.asyncio
async def test_reflection_only_app_is_not_reported():
    """The response echoes the forged owner but the persisted record keeps the real one."""
    sa, sb, tokens = _pair()
    for scoped in (True, False):
        _, findings = await _scan(FakeApp(tokens, reflect=True, scoped=scoped), sa, sb)
        assert findings == []


@pytest.mark.asyncio
async def test_preexisting_victim_record_is_not_mistaken_for_proof():
    sa, sb, tokens = _pair()
    old = {"id": 99, "UserId": sb.user_id, "message": "mine", "rating": 4}
    scanner, findings = await _scan(FakeApp(tokens, scoped=False, preexisting=[old]), sa, sb)
    assert findings == []


@pytest.mark.asyncio
async def test_server_rejecting_foreign_owner_is_not_reported():
    sa, sb, tokens = _pair()
    app = FakeApp(tokens, trust_body=True, reject_foreign=True)
    scanner, findings = await _scan(app, sa, sb)
    assert findings == []
    assert scanner.outcomes[COLLECTION].reason == "forged write rejected"


@pytest.mark.asyncio
async def test_no_read_endpoint_is_inconclusive_not_a_finding():
    sa, sb, tokens = _pair()
    app = FakeApp(tokens, trust_body=True, readable=False)
    scanner, findings = await _scan(app, sa, sb)
    assert findings == []
    assert scanner.outcomes[COLLECTION].status is ForgeStatus.INCONCLUSIVE
    assert not [c for c in app.calls if c[0] == "POST"]       # known BEFORE any write


@pytest.mark.asyncio
async def test_read_endpoint_without_a_record_of_ours_means_zero_writes():
    sa, sb, tokens = _pair()
    app = FakeApp(tokens, trust_body=True)
    scanner, findings = await _scan(app, sa, sb, seed=False)
    assert findings == [] and not [c for c in app.calls if c[0] == "POST"]
    assert "no verified read endpoint" in scanner.outcomes[COLLECTION].reason


@pytest.mark.asyncio
async def test_body_without_our_identity_is_skipped_without_writing():
    sa, sb, tokens = _pair()
    app = FakeApp(tokens, trust_body=True)
    req = _captured("someone-else-entirely")
    scanner, findings = await _scan(app, sa, sb, captured=[req])
    assert findings == [] and app.calls == []


# ---------------------------------------------------------------- one identity

@pytest.mark.asyncio
async def test_single_identity_forges_synthetic_id_and_reports_medium():
    own = str(uuid.uuid4())
    sa = _session(own)
    app = FakeApp({sa.access_token: own}, trust_body=True, scoped=False)
    _, findings = await _scan(app, sa)
    assert len(findings) == 1
    assert findings[0].severity == SeverityLevel.MEDIUM
    assert findings[0].confidence == BolaForgeConfig.CONFIDENCE_SYNTHETIC
    forged = {r["UserId"] for r in app.records} - {own}
    assert len(forged) == 1 and uuid.UUID(forged.pop())   # same shape, belongs to nobody


@pytest.mark.asyncio
async def test_single_identity_owner_scoped_listing_hides_the_proof():
    """Known limit: the forged record is no longer in our own scoped view, so nothing is shown."""
    own = str(uuid.uuid4())
    sa = _session(own)
    _, findings = await _scan(FakeApp({sa.access_token: own}, trust_body=True), sa)
    assert findings == []


@pytest.mark.asyncio
async def test_single_identity_safe_app_is_not_reported():
    own = str(uuid.uuid4())
    sa = _session(own)
    _, findings = await _scan(FakeApp({sa.access_token: own}), sa)
    assert findings == []


@pytest.mark.asyncio
async def test_single_identity_numeric_id_is_never_forged():
    """Any number we picked could be a real user: nothing is written."""
    sa = _session("42")
    app = FakeApp({sa.access_token: "42"}, trust_body=True)
    scanner, findings = await _scan(app, sa)
    assert findings == [] and app.calls == []
    assert scanner.outcomes[COLLECTION].status is ForgeStatus.INCONCLUSIVE


# ---------------------------------------------------------------- safety

@pytest.mark.asyncio
async def test_inert_without_probe_writes():
    sa, sb, tokens = _pair()
    app = FakeApp(tokens, trust_body=True)
    _, findings = await _scan(app, sa, sb, probe_writes=False)
    assert findings == [] and app.calls == []


@pytest.mark.asyncio
async def test_only_creates_and_reads_bounded_and_marked():
    sa, sb, tokens = _pair()
    app = FakeApp(tokens, trust_body=True)
    put = InterceptedRequest(
        url=f"{COLLECTION}/3", method="PUT", response_status=200,
        request_body=json.dumps({"UserId": sa.user_id, "message": "x"}),
    )
    await _scan(app, sa, sb, captured=[put, _captured(sa.user_id)])
    assert {m for m, _ in app.calls} == {"POST", "GET"}          # no PUT/PATCH/DELETE
    assert len(app.calls) <= BolaForgeConfig.MAX_READ_URLS + 6
    probes = [r for r in app.records if r["id"] != 0]               # id 0 is our seed record
    assert all(BolaForgeConfig.MARKER_PREFIX in r["message"] for r in probes)
    assert len(probes) == 2                                         # control + treatment only


@pytest.mark.asyncio
async def test_endpoints_are_bounded():
    sa, sb, tokens = _pair()
    reqs = [
        InterceptedRequest(
            url=f"{BASE}/api/thing{i}", method="POST", response_status=201,
            request_body=json.dumps({"UserId": sa.user_id, "message": "m"}),
        )
        for i in range(BolaForgeConfig.MAX_ENDPOINTS + 4)
    ]
    scanner, _ = await _scan(FakeApp(tokens, trust_body=True), sa, sb, captured=reqs)
    assert len(scanner.outcomes) <= BolaForgeConfig.MAX_ENDPOINTS


# ---------------------------------------------------------------- unit + wiring

def test_identity_field_found_by_value_not_by_name():
    own = identity_claims(_session("acct-12345678"))
    fields = _find_identity_fields({"zzz": "acct-12345678", "other": "x"}, own, {})
    assert [f.key for f in fields] == ["zzz"]


def test_jwt_time_claims_are_not_identities():
    assert "iat" not in identity_claims(_session("u-1"))


def test_factory_wires_scanner_with_probe_writes_flag():
    assert create_deep_security_scan_agent(probe_writes=True)._bola_forge_scanner._probe_writes
    assert not create_deep_security_scan_agent()._bola_forge_scanner._probe_writes


@pytest.mark.asyncio
async def test_agent_runs_scanner_in_authenticated_phase():
    stub = AsyncMock()
    stub.scan.return_value = []
    agent = DeepSecurityScanAgent(
        ingestion_service=AsyncMock(), endpoint_scanner=AsyncMock(), bola_forge_scanner=stub,
    )
    sa, sb, _ = _pair()
    crawl = AuthenticatedCrawlResult(intercepted_requests=[_captured(sa.user_id)])
    _, names = await agent._run_authenticated_scanners(
        sa, sb, [], None, None, None, [], crawl_result=crawl,
    )
    assert "bola_forge" in names
    stub.scan.assert_awaited_once_with(crawl.intercepted_requests, sa, sb, target_url=None)


# ---------------------------------------------------------------- review hardening

def _post(path: str, body: dict, host: str = BASE) -> InterceptedRequest:
    return InterceptedRequest(
        url=f"{host}{path}", method="POST", response_status=201,
        request_body=json.dumps(body),
    )


def _posts(app: FakeApp) -> list[str]:
    return [url for method, url, _ in app.requests if method == "POST"]


@pytest.mark.asyncio
@pytest.mark.parametrize("path", [
    "/api/checkout", "/api/Orders", "/api/send-email", "/api/users/password/reset",
    "/api/sendEmail", "/api/payments", "/api/invite_user", "/rest/user/login",
])
async def test_dangerous_paths_are_never_requested(path):
    sa, sb, tokens = _pair()
    app = FakeApp(tokens, trust_body=True)
    _, findings = await _scan(
        app, sa, sb, captured=[_post(path, {"UserId": sa.user_id, "message": "hi there"})],
    )
    assert findings == [] and app.requests == []


def test_benign_paths_are_not_mistaken_for_dangerous():
    body = {"UserId": "u", "message": "m"}
    assert not is_dangerous_create(f"{BASE}/api/feedbacks", body)
    assert not is_dangerous_create(f"{BASE}/api/borders/reviews", body)   # token, not substring


@pytest.mark.asyncio
@pytest.mark.parametrize("extra", [
    {"cardNumber": "4242"}, {"cvv": "123"}, {"iban": "DE00"},
    {"amount": 5, "currency": "EUR"},
])
async def test_payment_looking_bodies_are_never_replayed(extra):
    sa, sb, tokens = _pair()
    app = FakeApp(tokens, trust_body=True)
    body = {"UserId": sa.user_id, "message": "hi there", **extra}
    _, findings = await _scan(app, sa, sb, captured=[_post("/api/feedbacks", body)])
    assert findings == [] and app.requests == []


@pytest.mark.asyncio
async def test_cross_origin_captures_are_never_sent_and_credentials_stay_home():
    sa, sb, tokens = _pair()
    app = FakeApp(tokens, trust_body=True)
    evil = "https://analytics.thirdparty.example"
    body = {"UserId": sa.user_id, "message": "hi there", "rating": 5}
    captured = [_post("/api/feedbacks", body, evil), _get(f"{evil}/api/feedbacks"),
                _post("/api/feedbacks", body)]
    _, findings = await _scan(app, sa, sb, captured=captured)
    assert len(findings) == 1                                   # the on-origin one still works
    assert app.requests
    assert all(url.startswith(BASE) for _, url, _ in app.requests)
    assert all(not url.startswith(evil) for _, url, _ in app.requests)


@pytest.mark.asyncio
async def test_only_cross_origin_captures_send_nothing_and_unknown_target_sends_nothing():
    sa, sb, tokens = _pair()
    body = {"UserId": sa.user_id, "message": "hi there"}
    app = FakeApp(tokens, trust_body=True)
    foreign = [_post("/api/feedbacks", body, "http://other.example:8080")]
    await _scan(app, sa, sb, captured=foreign)
    assert app.requests == []
    app2 = FakeApp(tokens, trust_body=True)
    await _scan(app2, sa, sb, target_url=None)                   # origin unknown: fail closed
    assert app2.requests == []


def test_origin_normalises_default_ports_and_rejects_junk():
    assert origin_of("https://a.example/x") == origin_of("HTTPS://A.example:443/y")
    assert origin_of("https://a.example") != origin_of("http://a.example")
    assert origin_of("not a url") is None and origin_of("ftp://a.example/") is None


@pytest.mark.asyncio
async def test_rating_equal_to_user_id_is_not_taken_for_the_owner_field():
    """{"rating": 1, "UserId": 1}: two keys share the short id, so the owner field is unclear."""
    sa, sb, tokens = _pair("1", "2")
    app = FakeApp(tokens, trust_body=True, scoped=False)
    body = {"UserId": 1, "rating": 1, "message": "hi there"}
    scanner, findings = await _scan(app, sa, sb, captured=[_post("/api/feedbacks", body)])
    assert findings == [] and app.requests == []
    assert scanner.outcomes[COLLECTION].status is ForgeStatus.INCONCLUSIVE


@pytest.mark.asyncio
@pytest.mark.parametrize("claims,body", [
    ({"role": "user"}, {"role": "user", "message": "hi there"}),
    ({"iss": "https://auth.example.com/"}, {"iss": "https://auth.example.com/", "message": "x y"}),
    ({"accountId": 1}, {"quantity": 1, "message": "hi there"}),       # small non-session claim
    ({}, {"quantity": 1, "message": "hi there"}),                      # user id is not 1
])
async def test_coincidental_claim_values_cause_no_write(claims, body):
    sa = _session("user-0001-abcdef", **claims)
    sb = _session("user-0002-abcdef", **{k: (2 if v == 1 else v) for k, v in claims.items()})
    app = FakeApp({sa.access_token: sa.user_id, sb.access_token: sb.user_id}, trust_body=True)
    _, findings = await _scan(app, sa, sb, captured=[_post("/api/feedbacks", body)])
    assert findings == [] and not _posts(app)


@pytest.mark.asyncio
async def test_non_session_claim_equal_in_both_sessions_is_inconclusive_not_synthetic():
    shared = "tenant-abcdef123"
    sa = _session("user-0001-abcdef", tenant=shared)
    sb = _session("user-0002-abcdef", tenant=shared)
    app = FakeApp({sa.access_token: sa.user_id, sb.access_token: sb.user_id}, trust_body=True)
    body = {"tenant": shared, "message": "hi there"}
    scanner, findings = await _scan(app, sa, sb, captured=[_post("/api/feedbacks", body)])
    assert findings == [] and not _posts(app)
    assert scanner.outcomes[COLLECTION].status is ForgeStatus.INCONCLUSIVE


def test_marker_never_lands_in_a_secret_or_url_field():
    ids = {"UserId"}
    body = {"UserId": "u", "password": "correct horse battery",
            "avatar_url": "https://x.example/a b", "apiKey": "a b c", "message": "hi there"}
    marked = _mark_free_text(body, ids, "MARK")
    assert marked["message"].endswith("MARK")
    assert all("MARK" not in str(v) for k, v in marked.items() if k != "message")


def test_free_text_prefers_prose_over_a_longer_single_token():
    marked = _mark_free_text({"slug": "abcdefghijklmn", "note": "a b"}, set(), "MARK")
    assert marked["note"].endswith("MARK") and marked["slug"] == "abcdefghijklmn"


@pytest.mark.asyncio
@pytest.mark.parametrize("body", [
    {"UserId": "x", "password": "correct horse battery"},
    {"UserId": "x", "avatar": "https://img.example/a.png"},
    {"UserId": "x", "token": "abcdefghijklmnopqrstuvwxyz0123"},
])
async def test_no_safe_free_text_field_means_zero_writes(body):
    sa, sb, tokens = _pair()
    app = FakeApp(tokens, trust_body=True)
    body = {**body, "UserId": sa.user_id}
    scanner, findings = await _scan(app, sa, sb, captured=[_post("/api/feedbacks", body)])
    assert findings == [] and not _posts(app)
    assert scanner.outcomes[COLLECTION].status is ForgeStatus.INCONCLUSIVE


@pytest.mark.asyncio
async def test_missing_session_is_skipped_cleanly():
    app = FakeApp({})
    scanner = BolaForgeScanner(probe_writes=True)
    assert await scanner.scan([_captured("u")], None, None, target_url=BASE) == []
    assert identity_claims(None) == {}
    _, findings = await _scan(app, None)
    assert findings == [] and app.requests == []
