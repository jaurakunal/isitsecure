"""Tests for the active injection scanner."""

from __future__ import annotations

import datetime
import time
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from isitsecure.engine.constants import InjectionConfig
from isitsecure.engine.enums import EndpointMethod
from isitsecure.engine.models import (
    DeepFinding,
    DiscoveredEndpoint,
    FindingSource,
)
from isitsecure.engine.scanners.active_injection_scanner import (
    ActiveInjectionScanner,
)
from isitsecure.engine.shared.url_utils import inject_query_param
from isitsecure.engine.scanners.protocols import DASTScannerProtocol
from isitsecure.engine.enums import FindingCategory, SeverityLevel


def _make_endpoint(
    url: str = "https://example.com/api/items",
    method: EndpointMethod = EndpointMethod.GET,
    query_param_names: list[str] | None = None,
) -> DiscoveredEndpoint:
    """Helper to create a test endpoint."""
    return DiscoveredEndpoint(
        url=url,
        method=method,
        query_param_names=query_param_names or [],
    )


def _make_response(
    status_code: int = 200,
    text: str = "",
) -> httpx.Response:
    """Helper to create a mock httpx.Response."""
    resp = httpx.Response(
        status_code=status_code,
        text=text,
        request=httpx.Request("GET", "https://example.com"),
    )
    resp.elapsed = datetime.timedelta(milliseconds=100)
    return resp


def _make_mock_client(get_return: httpx.Response | None = None) -> AsyncMock:
    """Create a mock RateLimitedClient with a working async get method."""
    mock = AsyncMock()
    if get_return is not None:
        mock.get.return_value = get_return
    return mock


class TestActiveInjectionScannerProtocolCompliance:
    """Protocol compliance tests for ActiveInjectionScanner."""

    def test_implements_dast_protocol(self) -> None:
        """ActiveInjectionScanner should implement DASTScannerProtocol."""
        scanner = ActiveInjectionScanner()
        assert isinstance(scanner, DASTScannerProtocol)

    def test_has_scanner_name(self) -> None:
        scanner = ActiveInjectionScanner()
        assert isinstance(scanner.scanner_name, str)
        assert len(scanner.scanner_name) > 0

    def test_has_scan_method(self) -> None:
        scanner = ActiveInjectionScanner()
        assert hasattr(scanner, "scan")
        assert callable(scanner.scan)


class TestScannerProperties:
    """Tests for scanner metadata properties."""

    def test_scanner_name(self) -> None:
        scanner = ActiveInjectionScanner()
        assert scanner.scanner_name == InjectionConfig.SCANNER_NAME

    def test_scan_categories(self) -> None:
        scanner = ActiveInjectionScanner()
        assert scanner.scan_categories == [FindingCategory.INJECTION_RISK]


class TestSQLErrorPatternDetection:
    """Tests for _response_has_sql_error pattern matching."""

    def setup_method(self) -> None:
        self.scanner = ActiveInjectionScanner()

    def test_sql_error_pattern_mysql(self) -> None:
        """Should detect MySQL error messages."""
        body = "You have an error in your SQL syntax near 'foo'"
        result = self.scanner._response_has_sql_error(body)
        assert result is not None
        assert "SQL syntax" in result

    def test_sql_error_pattern_mysql_fetch(self) -> None:
        """Should detect mysql_fetch errors."""
        body = "Warning: mysql_fetch_array() failed"
        result = self.scanner._response_has_sql_error(body)
        assert result is not None

    def test_sql_error_pattern_postgres(self) -> None:
        """Should detect PostgreSQL error messages."""
        body = "ERROR: syntax error at or near 'SELECT'"
        result = self.scanner._response_has_sql_error(body)
        assert result is not None

    def test_sql_error_pattern_pg_query(self) -> None:
        """Should detect pg_query errors."""
        body = "Warning: pg_query(): Query failed"
        result = self.scanner._response_has_sql_error(body)
        assert result is not None

    def test_sql_error_pattern_oracle(self) -> None:
        """Should detect Oracle error messages."""
        body = "ORA-00942: table or view does not exist"
        result = self.scanner._response_has_sql_error(body)
        assert result is not None

    def test_sql_error_pattern_sqlite(self) -> None:
        """Should detect SQLite errors."""
        body = "SQLITE_ERROR: no such table"
        result = self.scanner._response_has_sql_error(body)
        assert result is not None

    def test_sql_error_pattern_pdo(self) -> None:
        """Should detect PDOException."""
        body = "Fatal error: Uncaught PDOException: SQLSTATE[42000]"
        result = self.scanner._response_has_sql_error(body)
        assert result is not None

    def test_sql_error_pattern_sqlstate(self) -> None:
        """Should detect SQLSTATE errors."""
        body = "SQLSTATE[HY000]: General error"
        result = self.scanner._response_has_sql_error(body)
        assert result is not None

    def test_sql_error_pattern_unclosed_quote(self) -> None:
        """Should detect unclosed quotation mark."""
        body = "Unclosed quotation mark after the character string ''"
        result = self.scanner._response_has_sql_error(body)
        assert result is not None

    def test_no_sql_error_in_normal_text(self) -> None:
        """Normal HTML should not match SQL error patterns."""
        body = (
            "<html><body><h1>Welcome</h1>"
            "<p>Your search returned 0 results.</p></body></html>"
        )
        result = self.scanner._response_has_sql_error(body)
        assert result is None

    def test_no_sql_error_in_empty_response(self) -> None:
        """Empty response should not match."""
        assert self.scanner._response_has_sql_error("") is None

    def test_case_insensitive_matching(self) -> None:
        """SQL error patterns should match regardless of case."""
        body = "you have an error in your sql syntax"
        result = self.scanner._response_has_sql_error(body)
        assert result is not None


class TestErrorBasedSQLi:
    """Tests for error-based SQL injection detection."""

    def setup_method(self) -> None:
        self.scanner = ActiveInjectionScanner()

    @pytest.mark.asyncio
    async def test_detects_sql_error_in_response(self) -> None:
        """SQL error message in response -> confirmed SQLi."""
        endpoint = _make_endpoint(
            url="https://example.com/api/items?id=1",
            query_param_names=["id"],
        )
        error_body = "You have an error in your SQL syntax near '1 OR'"

        mock_client = _make_mock_client()
        mock_client.get.return_value = _make_response(text=error_body)

        finding = await self.scanner._test_error_based_sqli(
            mock_client, endpoint, "id"
        )

        assert finding is not None
        assert finding.source == FindingSource.DAST_URL
        assert finding.category == FindingCategory.INJECTION_RISK
        assert finding.severity == SeverityLevel.CRITICAL
        assert finding.title == InjectionConfig.TITLE_SQLI_ERROR
        assert finding.confidence == InjectionConfig.CONFIDENCE_ERROR_BASED
        assert finding.scanner_name == InjectionConfig.SCANNER_NAME
        assert finding.endpoint_url == endpoint.url

    @pytest.mark.asyncio
    async def test_no_finding_for_clean_response(self) -> None:
        """Normal response without SQL errors -> no finding."""
        endpoint = _make_endpoint(
            url="https://example.com/api/items?id=1",
            query_param_names=["id"],
        )
        clean_body = '{"items": [], "total": 0}'

        mock_client = _make_mock_client()
        mock_client.get.return_value = _make_response(text=clean_body)

        finding = await self.scanner._test_error_based_sqli(
            mock_client, endpoint, "id"
        )
        assert finding is None

    @pytest.mark.asyncio
    async def test_handles_http_error_gracefully(self) -> None:
        """HTTP errors should not crash the scanner."""
        endpoint = _make_endpoint(query_param_names=["id"])

        mock_client = _make_mock_client()
        mock_client.get.side_effect = httpx.ConnectError("Connection refused")

        finding = await self.scanner._test_error_based_sqli(
            mock_client, endpoint, "id"
        )
        assert finding is None

    @pytest.mark.asyncio
    async def test_stops_at_first_confirmed_sqli(self) -> None:
        """Should return on first confirmed payload, not test all payloads."""
        endpoint = _make_endpoint(query_param_names=["id"])
        error_body = "You have an error in your SQL syntax"

        mock_client = _make_mock_client()
        mock_client.get.return_value = _make_response(text=error_body)

        finding = await self.scanner._test_error_based_sqli(
            mock_client, endpoint, "id"
        )

        assert finding is not None
        # Should have called get only once since first payload triggers match
        assert mock_client.get.call_count == 1


class TestTimeBasedSQLi:
    """Tests for time-based blind SQL injection detection."""

    def setup_method(self) -> None:
        self.scanner = ActiveInjectionScanner()

    @pytest.mark.asyncio
    async def test_detects_time_based_sqli(self) -> None:
        """Response delay > threshold -> time-based SQLi detected."""
        endpoint = _make_endpoint(query_param_names=["id"])

        call_count = 0

        async def mock_get(url: str, **kwargs: object) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            return _make_response(text="ok")

        mock_client = _make_mock_client()
        mock_client.get = mock_get

        # Mock time.monotonic to simulate delay on injected requests.
        # Each _measure_response_time call consumes a (start, end) pair. A hit
        # is now CONFIRMED with a second baseline+injected measurement, so the
        # delay must reproduce.
        time_values = iter([
            100.0, 100.1,   # baseline: 0.1s
            200.0, 203.5,   # first time payload: 3.5s -> delta = 3.4s
            300.0, 300.1,   # confirm baseline: 0.1s
            400.0, 403.5,   # confirm payload: 3.5s -> reproduces
        ])

        with patch("isitsecure.engine.scanners.active_injection_scanner.time") as mock_time:
            mock_time.monotonic = lambda: next(time_values)

            finding = await self.scanner._test_time_based_sqli(
                mock_client, endpoint, "id"
            )

        assert finding is not None
        assert finding.title == InjectionConfig.TITLE_SQLI_TIME
        assert finding.severity == SeverityLevel.CRITICAL
        assert finding.confidence == InjectionConfig.CONFIDENCE_TIME_BASED

    async def test_time_based_noise_not_flagged(self) -> None:
        """A one-off slow response that does NOT reproduce is not flagged."""
        endpoint = _make_endpoint(query_param_names=["id"])

        async def mock_get(url: str, **kwargs: object) -> httpx.Response:
            return _make_response(text="ok")

        mock_client = _make_mock_client()
        mock_client.get = mock_get

        # First injected measurement is slow (noise), but the confirmation
        # re-measurement is fast -> must be rejected as a false positive.
        time_values = iter([
            100.0, 100.1,   # baseline: 0.1s
            200.0, 203.5,   # injected: 3.5s -> crosses threshold (noise spike)
            300.0, 300.1,   # confirm baseline: 0.1s
            400.0, 400.2,   # confirm injected: 0.2s -> did NOT reproduce
        ])

        with patch("isitsecure.engine.scanners.active_injection_scanner.time") as mock_time:
            mock_time.monotonic = lambda: next(time_values)
            finding = await self.scanner._test_time_based_sqli(
                mock_client, endpoint, "id"
            )

        assert finding is None

    @pytest.mark.asyncio
    async def test_no_time_finding_for_fast_response(self) -> None:
        """Fast response -> no time-based finding."""
        endpoint = _make_endpoint(query_param_names=["id"])

        mock_client = _make_mock_client()
        mock_client.get.return_value = _make_response(text="ok")

        # All responses are fast: 0.1s each -> delta = 0
        # baseline + 3 time payloads = 8 monotonic calls
        time_values = iter([
            100.0, 100.1,   # baseline: 0.1s
            200.0, 200.1,   # payload 1: 0.1s
            300.0, 300.1,   # payload 2: 0.1s
            400.0, 400.1,   # payload 3: 0.1s
        ])

        with patch("isitsecure.engine.scanners.active_injection_scanner.time") as mock_time:
            mock_time.monotonic = lambda: next(time_values)

            finding = await self.scanner._test_time_based_sqli(
                mock_client, endpoint, "id"
            )

        assert finding is None

    @pytest.mark.asyncio
    async def test_baseline_failure_returns_none(self) -> None:
        """If baseline request fails, skip time-based testing."""
        endpoint = _make_endpoint(query_param_names=["id"])

        mock_client = _make_mock_client()
        mock_client.get.side_effect = httpx.ConnectError("Connection refused")

        finding = await self.scanner._test_time_based_sqli(
            mock_client, endpoint, "id"
        )
        assert finding is None


class TestCommandInjection:
    """Tests for command injection detection."""

    def setup_method(self) -> None:
        self.scanner = ActiveInjectionScanner()

    @pytest.mark.asyncio
    async def test_detects_command_injection(self) -> None:
        """Canary in response -> command injection detected."""
        endpoint = _make_endpoint(query_param_names=["cmd"])
        body_with_canary = f"output: {InjectionConfig.COMMAND_INJECTION_CANARY}"

        mock_client = _make_mock_client()
        mock_client.get.return_value = _make_response(text=body_with_canary)

        finding = await self.scanner._test_command_injection(
            mock_client, endpoint, "cmd"
        )

        assert finding is not None
        assert finding.title == InjectionConfig.TITLE_COMMAND_INJECTION
        assert finding.severity == SeverityLevel.CRITICAL
        assert finding.confidence == InjectionConfig.CONFIDENCE_COMMAND_INJECTION

    @pytest.mark.asyncio
    async def test_no_cmd_finding_without_canary(self) -> None:
        """No canary in response -> no finding."""
        endpoint = _make_endpoint(query_param_names=["cmd"])
        clean_body = '{"result": "search completed"}'

        mock_client = _make_mock_client()
        mock_client.get.return_value = _make_response(text=clean_body)

        finding = await self.scanner._test_command_injection(
            mock_client, endpoint, "cmd"
        )
        assert finding is None

    @pytest.mark.asyncio
    async def test_handles_http_error_gracefully(self) -> None:
        """HTTP errors should not crash."""
        endpoint = _make_endpoint(query_param_names=["cmd"])

        mock_client = _make_mock_client()
        mock_client.get.side_effect = httpx.ConnectError("refused")

        finding = await self.scanner._test_command_injection(
            mock_client, endpoint, "cmd"
        )
        assert finding is None


class TestHelpers:
    """Tests for endpoint filtering and URL injection helpers."""

    def setup_method(self) -> None:
        self.scanner = ActiveInjectionScanner()

    def test_get_testable_endpoints_filters_by_method(self) -> None:
        """Only GET and POST endpoints are testable."""
        endpoints = [
            _make_endpoint(method=EndpointMethod.GET),
            _make_endpoint(method=EndpointMethod.POST),
            _make_endpoint(method=EndpointMethod.PUT),
            _make_endpoint(method=EndpointMethod.DELETE),
            _make_endpoint(method=EndpointMethod.PATCH),
        ]
        result = self.scanner._get_testable_endpoints(endpoints)
        assert len(result) == 2
        assert all(ep.method.value in ("GET", "POST") for ep in result)

    def test_get_testable_endpoints_empty(self) -> None:
        """Empty list returns empty."""
        assert self.scanner._get_testable_endpoints([]) == []

    def test_inject_param_adds_new_param(self) -> None:
        """Should add a parameter to a URL without existing query string."""
        url = "https://example.com/api/items"
        result = inject_query_param(url, "id", "' OR '1'='1")
        assert "id=" in result
        assert "example.com/api/items?" in result

    def test_inject_param_replaces_existing(self) -> None:
        """Should replace an existing parameter value."""
        url = "https://example.com/api/items?id=5&name=foo"
        result = inject_query_param(url, "id", "payload")
        assert "id=payload" in result
        assert "name=foo" in result

    def test_inject_param_preserves_other_params(self) -> None:
        """Other query params should remain intact."""
        url = "https://example.com/search?q=test&page=1"
        result = inject_query_param(url, "q", "injected")
        assert "q=injected" in result
        assert "page=1" in result

    def test_get_testable_params_from_url(self) -> None:
        """Should extract params from the URL query string."""
        endpoint = _make_endpoint(url="https://example.com/api?id=1&name=foo")
        params = self.scanner._get_testable_params(endpoint)
        assert "id" in params
        assert "name" in params

    def test_get_testable_params_from_model_field(self) -> None:
        """Should include params from endpoint.query_param_names."""
        endpoint = _make_endpoint(
            url="https://example.com/api",
            query_param_names=["user_id", "token"],
        )
        params = self.scanner._get_testable_params(endpoint)
        assert "user_id" in params
        assert "token" in params

    def test_get_testable_params_falls_back_to_defaults(self) -> None:
        """Should use default fuzz params when no params are known."""
        endpoint = _make_endpoint(url="https://example.com/api")
        params = self.scanner._get_testable_params(endpoint)
        assert params == list(InjectionConfig.DEFAULT_FUZZ_PARAMS)[
            : InjectionConfig.MAX_PARAMS_PER_ENDPOINT
        ]

    def test_get_testable_params_no_duplicates(self) -> None:
        """Should not duplicate params present in both URL and model."""
        endpoint = _make_endpoint(
            url="https://example.com/api?id=1",
            query_param_names=["id", "extra"],
        )
        params = self.scanner._get_testable_params(endpoint)
        assert params.count("id") == 1
        assert "extra" in params


class TestFullScan:
    """Integration-level tests for the full scan() method."""

    @pytest.mark.asyncio
    async def test_scan_with_vulnerable_endpoint(self) -> None:
        """Full scan should detect SQLi when error is returned."""
        scanner = ActiveInjectionScanner()
        endpoint = _make_endpoint(
            url="https://example.com/api/items?id=1",
            query_param_names=["id"],
        )
        error_body = "You have an error in your SQL syntax"

        async def mock_get(url: str, **kwargs: object) -> httpx.Response:
            return _make_response(text=error_body)

        with patch.object(
            ActiveInjectionScanner, "_get_testable_endpoints", return_value=[endpoint]
        ):
            with patch(
                "isitsecure.engine.scanners.active_injection_scanner.RateLimitedClient"
            ) as MockClient:
                mock_instance = AsyncMock()
                mock_instance.get = mock_get
                mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
                mock_instance.__aexit__ = AsyncMock(return_value=False)
                MockClient.return_value = mock_instance

                findings = await scanner.scan([endpoint])

        assert len(findings) >= 1
        assert all(isinstance(f, DeepFinding) for f in findings)
        assert findings[0].source == FindingSource.DAST_URL

    @pytest.mark.asyncio
    async def test_scan_with_clean_endpoint(self) -> None:
        """Full scan should produce no findings for clean responses."""
        scanner = ActiveInjectionScanner()
        endpoint = _make_endpoint(
            url="https://example.com/api/items?id=1",
            query_param_names=["id"],
        )
        clean_body = '{"data": []}'

        async def mock_get(url: str, **kwargs: object) -> httpx.Response:
            return _make_response(text=clean_body)

        # Also mock time so time-based tests produce no delta
        time_counter = iter(range(0, 1000))

        with patch.object(
            ActiveInjectionScanner, "_get_testable_endpoints", return_value=[endpoint]
        ):
            with patch(
                "isitsecure.engine.scanners.active_injection_scanner.RateLimitedClient"
            ) as MockClient:
                mock_instance = AsyncMock()
                mock_instance.get = mock_get
                mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
                mock_instance.__aexit__ = AsyncMock(return_value=False)
                MockClient.return_value = mock_instance

                with patch(
                    "isitsecure.engine.scanners.active_injection_scanner.time"
                ) as mock_time:
                    # All requests take ~0.05s -> no time delta
                    vals = []
                    for i in range(100):
                        vals.extend([float(i), float(i) + 0.05])
                    time_iter = iter(vals)
                    mock_time.monotonic = lambda: next(time_iter)

                    findings = await scanner.scan([endpoint])

        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_scan_with_no_endpoints(self) -> None:
        """Scan with empty endpoint list should return empty findings."""
        scanner = ActiveInjectionScanner()

        with patch(
            "isitsecure.engine.scanners.active_injection_scanner.RateLimitedClient"
        ) as MockClient:
            mock_instance = AsyncMock()
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_instance

            findings = await scanner.scan([])

        assert findings == []
