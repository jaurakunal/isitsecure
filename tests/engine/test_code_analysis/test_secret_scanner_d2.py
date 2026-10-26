"""D2 regression tests: secret regex accuracy (JWT role, modern keys, DB URLs)."""

from __future__ import annotations

import base64
import json

from isitsecure.engine.code_analysis.secret_scanner import GitSecretScanner
from isitsecure.engine.enums import SeverityLevel


def _b64(obj: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")


def _jwt(role: str | None) -> str:
    payload = {"iss": "supabase", "ref": "abc"}
    if role:
        payload["role"] = role
    return f"{_b64({'alg': 'HS256', 'typ': 'JWT'})}.{_b64(payload)}.sigsigsigsigsig"


def _scan(content: str, path: str = "config.ts"):
    return GitSecretScanner()._scan_content_for_secrets(content, path)


class TestJwtRole:
    def test_anon_key_not_reported_as_service_role(self) -> None:
        findings = _scan(f'const k = "{_jwt("anon")}"')
        assert findings == []

    def test_service_role_still_critical(self) -> None:  # positive control
        findings = _scan(f'const k = "{_jwt("service_role")}"')
        assert len(findings) == 1
        assert findings[0].severity == SeverityLevel.CRITICAL
        assert "Supabase service role key" in findings[0].title

    def test_unknown_role_jwt_kept_at_lower_tier(self) -> None:
        findings = _scan(f'const k = "{_jwt(None)}"')
        assert len(findings) == 1
        assert findings[0].severity == SeverityLevel.MEDIUM
        assert "service role" not in findings[0].title.lower()


class TestModernKeys:
    def test_openai_project_key(self) -> None:
        key = "sk-proj-" + "aB3_-" * 20
        findings = _scan(f"OPENAI_API_KEY={key}", ".env")
        assert any("OpenAI" in f.title for f in findings)

    def test_legacy_openai_key_still_matched(self) -> None:
        findings = _scan("K=sk-" + "a1B2" * 12, ".env")
        assert any("OpenAI" in f.title for f in findings)

    def test_anthropic_key_not_labelled_openai(self) -> None:
        findings = _scan("K=sk-ant-" + "a1B2-" * 20, ".env")
        assert not any("OpenAI" in f.title for f in findings)
        assert any("Anthropic" in f.title for f in findings)

    def test_openssh_private_key(self) -> None:
        findings = _scan("-----BEGIN OPENSSH PRIVATE KEY-----\nabc", "id_ed25519")
        assert any(f.severity == SeverityLevel.CRITICAL for f in findings)

    def test_encrypted_and_pgp_private_keys(self) -> None:
        assert _scan("-----BEGIN ENCRYPTED PRIVATE KEY-----\nabc", "k.txt")
        assert _scan("-----BEGIN PGP PRIVATE KEY BLOCK-----\nabc", "k.txt")


class TestDatabaseUrls:
    def test_postgresql_scheme_with_credentials(self) -> None:
        findings = _scan("DATABASE_URL=postgresql://app:s3cr3tPw@db.internal:5432/prod", ".env")
        assert len(findings) == 1
        assert findings[0].severity == SeverityLevel.CRITICAL

    def test_mongodb_srv_with_credentials(self) -> None:
        findings = _scan("U=mongodb+srv://admin:Xk29fj3@cluster0.mongodb.net/db", ".env")
        assert len(findings) == 1
        assert findings[0].severity == SeverityLevel.CRITICAL

    def test_credentialless_url_not_reported(self) -> None:
        assert _scan("DATABASE_URL=postgres://localhost:5432/db", ".env") == []

    def test_templated_url_not_reported(self) -> None:
        assert _scan("url = 'postgres://${DB_USER}:${DB_PASS}@db/app'", "a.js") == []

    def test_placeholder_password_downgraded_not_silent(self) -> None:
        findings = _scan("DATABASE_URL=postgres://user:password@localhost:5432/db", ".env")
        assert len(findings) == 1
        assert findings[0].severity == SeverityLevel.MEDIUM
