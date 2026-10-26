"""DB URL secrets: unencoded '/', '<' in passwords and query-string credentials."""

from __future__ import annotations

from isitsecure.engine.code_analysis.secret_scanner import GitSecretScanner
from isitsecure.engine.enums import SeverityLevel


def _scan(content: str, path: str = ".env"):
    return GitSecretScanner()._scan_content_for_secrets(content, path)


def test_slash_in_password_is_reported_critical() -> None:
    f = _scan("DATABASE_URL=postgres://admin:ab/cd1234@db.internal/app")
    assert len(f) == 1 and f[0].severity == SeverityLevel.CRITICAL


def test_angle_bracket_in_password_is_reported_critical() -> None:
    f = _scan("DATABASE_URL=postgres://admin:pa<ss9Qx7@db.internal/app")
    assert len(f) == 1 and f[0].severity == SeverityLevel.CRITICAL


def test_password_in_query_string_is_reported_critical() -> None:
    f = _scan("DATABASE_URL=postgres://db.internal/app?user=a&password=Hunter22xx")
    assert len(f) == 1 and f[0].severity == SeverityLevel.CRITICAL


def test_pwd_query_parameter_is_reported() -> None:
    f = _scan("DATABASE_URL=mysql://db.internal/app?uid=a&pwd=Hunter22xx")
    assert len(f) == 1 and f[0].severity == SeverityLevel.CRITICAL


def test_placeholders_still_drop_to_medium_or_nothing() -> None:
    q = _scan("DATABASE_URL=postgres://db.internal/app?user=a&password=changeme")
    assert len(q) == 1 and q[0].severity == SeverityLevel.MEDIUM
    p = _scan("DATABASE_URL=postgres://user:password@localhost:5432/db")
    assert len(p) == 1 and p[0].severity == SeverityLevel.MEDIUM
    assert _scan("url='postgres://${DB_USER}:${DB_PASS}@db/app'", "a.js") == []
    assert _scan("url='postgres://user:<password>@db/app'", "a.js") == []


def test_empty_query_password_and_credentialless_not_reported() -> None:
    assert _scan("DATABASE_URL=postgres://db.internal/app?user=a&password=") == []
    assert _scan("DATABASE_URL=postgres://localhost:5432/db") == []
    assert _scan("DATABASE_URL=postgres://localhost:5432/db?sslmode=require") == []


def test_positive_control_plain_credentials_unchanged() -> None:
    f = _scan("DATABASE_URL=postgresql://app:s3cr3tPw@db.internal:5432/prod")
    assert len(f) == 1 and f[0].severity == SeverityLevel.CRITICAL
