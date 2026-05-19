"""Tests for OpenAPIScanner."""

from __future__ import annotations

import pytest

from isitsecure.engine.code_analysis.openapi_scanner import (
    OpenAPIScanner,
)
from isitsecure.engine.code_analysis.protocols import RepoSnapshot
from isitsecure.engine.constants import OpenAPIScannerConfig
from isitsecure.engine.enums import FindingCategory, SeverityLevel


# ---------------------------------------------------------------------------
# Content fixtures
# ---------------------------------------------------------------------------

SPEC_NO_GLOBAL_SECURITY = """\
openapi: "3.0.3"
info:
  title: My API
  version: 1.0.0
paths:
  /users:
    get:
      summary: List users
      responses:
        '200':
          description: OK
"""

SPEC_HTTP_SERVER = """\
openapi: "3.0.3"
info:
  title: My API
  version: 1.0.0
servers:
  - url: http://api.example.com/v1
security:
  - bearerAuth: []
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
paths:
  /health:
    get:
      summary: Health check
"""

SPEC_BASIC_AUTH = """\
openapi: "3.0.3"
info:
  title: My API
  version: 1.0.0
security:
  - basicAuth: []
components:
  securitySchemes:
    basicAuth:
      type: http
      scheme: basic
paths:
  /users:
    get:
      summary: List users
"""

SPEC_APIKEY_IN_QUERY = """\
openapi: "3.0.3"
info:
  title: My API
  version: 1.0.0
security:
  - apiKeyAuth: []
components:
  securitySchemes:
    apiKeyAuth:
      type: apiKey
      in: query
      name: api_key
paths:
  /data:
    get:
      summary: Get data
"""

SPEC_EMPTY_SECURITY_OVERRIDE = """\
openapi: "3.0.3"
info:
  title: My API
  version: 1.0.0
security:
  - bearerAuth: []
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
paths:
  /public:
    get:
      summary: Public endpoint
      security: []
"""

SPEC_SENSITIVE_PATHS_NO_SECURITY = """\
openapi: "3.0.3"
info:
  title: My API
  version: 1.0.0
paths:
  /admin/dashboard:
    get:
      summary: Admin dashboard
  /users:
    get:
      summary: List users
"""

SPEC_SECURE = """\
openapi: "3.0.3"
info:
  title: My API
  version: 1.0.0
servers:
  - url: https://api.example.com/v1
security:
  - bearerAuth: []
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT
paths:
  /users:
    get:
      summary: List users
      responses:
        '200':
          description: OK
"""

NO_OPENAPI_CODE = """\
const express = require('express');
const app = express();
app.listen(3000);
"""


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _make_repo(
    file_index: dict[str, str] | None = None,
) -> RepoSnapshot:
    return RepoSnapshot(
        repo_url="https://github.com/test/repo",
        branch="main",
        clone_path="/tmp/repo",
        file_index=file_index or {},
        route_map=[],
        package_json={},
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestScannerName:
    def test_scanner_name(self) -> None:
        scanner = OpenAPIScanner()
        assert scanner.scanner_name == OpenAPIScannerConfig.SCANNER_NAME


class TestNoOpenAPIFiles:
    @pytest.mark.asyncio
    async def test_empty_when_no_spec_files(self) -> None:
        """No OpenAPI/Swagger spec files -> no findings."""
        repo = _make_repo(file_index={"src/app.ts": NO_OPENAPI_CODE})
        scanner = OpenAPIScanner()
        findings = await scanner.scan(repo)
        assert len(findings) == 0


class TestMissingGlobalSecurity:
    @pytest.mark.asyncio
    async def test_flags_no_global_security(self) -> None:
        """OpenAPI spec without global security -> HIGH finding."""
        repo = _make_repo(
            file_index={"api/openapi.yaml": SPEC_NO_GLOBAL_SECURITY}
        )
        scanner = OpenAPIScanner()
        findings = await scanner.scan(repo)

        security_findings = [
            f for f in findings
            if f.title == OpenAPIScannerConfig.TITLE_NO_GLOBAL_SECURITY
        ]
        assert len(security_findings) == 1
        assert security_findings[0].severity == SeverityLevel.HIGH
        assert security_findings[0].category == FindingCategory.AUTH_WEAKNESS
        assert security_findings[0].confidence == OpenAPIScannerConfig.CONFIDENCE_NO_GLOBAL_SECURITY


class TestHTTPServer:
    @pytest.mark.asyncio
    async def test_flags_http_server_url(self) -> None:
        """Server URL using http:// instead of https:// -> MEDIUM finding."""
        repo = _make_repo(
            file_index={"api/openapi.yaml": SPEC_HTTP_SERVER}
        )
        scanner = OpenAPIScanner()
        findings = await scanner.scan(repo)

        http_findings = [
            f for f in findings
            if f.title == OpenAPIScannerConfig.TITLE_HTTP_SERVER
        ]
        assert len(http_findings) == 1
        assert http_findings[0].severity == SeverityLevel.MEDIUM
        assert http_findings[0].category == FindingCategory.MIXED_CONTENT
        assert http_findings[0].confidence == OpenAPIScannerConfig.CONFIDENCE_HTTP_SERVER


class TestBasicAuth:
    @pytest.mark.asyncio
    async def test_flags_basic_auth_scheme(self) -> None:
        """HTTP Basic auth scheme -> MEDIUM finding."""
        repo = _make_repo(
            file_index={"api/openapi.yaml": SPEC_BASIC_AUTH}
        )
        scanner = OpenAPIScanner()
        findings = await scanner.scan(repo)

        basic_findings = [
            f for f in findings
            if f.title == OpenAPIScannerConfig.TITLE_BASIC_AUTH
        ]
        assert len(basic_findings) == 1
        assert basic_findings[0].severity == SeverityLevel.MEDIUM
        assert basic_findings[0].category == FindingCategory.AUTH_WEAKNESS
        assert basic_findings[0].confidence == OpenAPIScannerConfig.CONFIDENCE_BASIC_AUTH


class TestAPIKeyInQuery:
    @pytest.mark.asyncio
    async def test_flags_apikey_in_query_param(self) -> None:
        """API key in query parameter -> MEDIUM finding."""
        repo = _make_repo(
            file_index={"api/openapi.yaml": SPEC_APIKEY_IN_QUERY}
        )
        scanner = OpenAPIScanner()
        findings = await scanner.scan(repo)

        apikey_findings = [
            f for f in findings
            if f.title == OpenAPIScannerConfig.TITLE_APIKEY_IN_QUERY
        ]
        assert len(apikey_findings) == 1
        assert apikey_findings[0].severity == SeverityLevel.MEDIUM
        assert apikey_findings[0].category == FindingCategory.EXPOSED_SECRETS
        assert apikey_findings[0].confidence == OpenAPIScannerConfig.CONFIDENCE_APIKEY_IN_QUERY


class TestEndpointsWithoutSecurity:
    @pytest.mark.asyncio
    async def test_flags_empty_security_override(self) -> None:
        """Endpoint with security: [] -> MEDIUM finding."""
        repo = _make_repo(
            file_index={"api/openapi.yaml": SPEC_EMPTY_SECURITY_OVERRIDE}
        )
        scanner = OpenAPIScanner()
        findings = await scanner.scan(repo)

        override_findings = [
            f for f in findings
            if f.title == OpenAPIScannerConfig.TITLE_EMPTY_SECURITY_OVERRIDE
        ]
        assert len(override_findings) == 1
        assert override_findings[0].severity == SeverityLevel.MEDIUM
        assert override_findings[0].category == FindingCategory.AUTH_WEAKNESS
        assert override_findings[0].confidence == OpenAPIScannerConfig.CONFIDENCE_EMPTY_SECURITY_OVERRIDE


class TestSensitivePathsNoSecurity:
    @pytest.mark.asyncio
    async def test_flags_admin_and_users_paths(self) -> None:
        """Sensitive paths /admin, /users without global security -> findings."""
        repo = _make_repo(
            file_index={"api/openapi.yaml": SPEC_SENSITIVE_PATHS_NO_SECURITY}
        )
        scanner = OpenAPIScanner()
        findings = await scanner.scan(repo)

        sensitive_findings = [
            f for f in findings
            if f.category == FindingCategory.AUTH_WEAKNESS
            and "Sensitive path" in f.title
        ]
        # Should flag both /admin/dashboard and /users
        assert len(sensitive_findings) >= 2


class TestSecureSpec:
    @pytest.mark.asyncio
    async def test_no_findings_for_secure_spec(self) -> None:
        """Well-configured spec with HTTPS, bearer auth, global security -> 0 findings."""
        repo = _make_repo(
            file_index={"api/openapi.yaml": SPEC_SECURE}
        )
        scanner = OpenAPIScanner()
        findings = await scanner.scan(repo)
        assert len(findings) == 0
