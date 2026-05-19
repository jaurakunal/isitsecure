"""Tests for GitSecretScanner."""

from __future__ import annotations

import re
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from isitsecure.engine.code_analysis.models import CodeFinding
from isitsecure.engine.code_analysis.protocols import RepoSnapshot
from isitsecure.engine.code_analysis.secret_scanner import (
    GitSecretScanner,
)
from isitsecure.engine.constants import SecretScannerConfig
from isitsecure.engine.enums import FindingCategory, SeverityLevel


def _make_repo(file_index: dict[str, str] | None = None) -> RepoSnapshot:
    """Create a minimal RepoSnapshot for testing."""
    return RepoSnapshot(
        repo_url="https://github.com/test/repo",
        branch="main",
        clone_path="/tmp/test-repo",
        file_index=file_index or {},
    )


class TestGitSecretScanner:
    """Tests for GitSecretScanner."""

    def setup_method(self) -> None:
        self.scanner = GitSecretScanner()

    # --- Protocol compliance ---

    def test_scanner_name(self) -> None:
        """Should return 'git_secret_scanner'."""
        assert self.scanner.scanner_name == "git_secret_scanner"

    def test_has_scan_method(self) -> None:
        """Should have an async scan method accepting RepoSnapshot."""
        assert hasattr(self.scanner, "scan")
        assert callable(self.scanner.scan)

    # --- Pattern Detection Tests ---

    def test_detects_supabase_service_role_key(self) -> None:
        """Should detect Supabase service role JWT."""
        content = (
            "const key = "
            '"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
            ".eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InBzamFuZW93a3VreWdydnR0aXZwIi"
            "wicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTczMjA0MjE0NSwiZXhwIjoyMD"
            '.fakeSignatureHere1234567890"'
        )
        findings = self.scanner._scan_content_for_secrets(content, "config.ts")
        assert len(findings) >= 1
        assert findings[0].category == FindingCategory.EXPOSED_SECRETS
        assert findings[0].severity == SeverityLevel.CRITICAL

    def test_detects_stripe_secret_key(self) -> None:
        """Should detect Stripe secret API key."""
        content = "STRIPE_KEY=sk_live_abcdefghijklmnopqrstuvwxyz"
        findings = self.scanner._scan_content_for_secrets(content, ".env")
        assert len(findings) >= 1
        assert any(
            f.severity == SeverityLevel.CRITICAL
            and "Stripe secret" in f.title
            for f in findings
        )

    def test_detects_stripe_restricted_key(self) -> None:
        """Should detect Stripe restricted API key."""
        content = "STRIPE_RESTRICTED=rk_live_abcdefghijklmnopqrstuvwxyz"
        findings = self.scanner._scan_content_for_secrets(content, ".env")
        assert len(findings) >= 1
        assert any(
            f.severity == SeverityLevel.HIGH
            and "Stripe restricted" in f.title
            for f in findings
        )

    def test_detects_aws_access_key(self) -> None:
        """Should detect AWS access key ID."""
        content = "AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE"
        findings = self.scanner._scan_content_for_secrets(content, "config.py")
        assert len(findings) >= 1
        assert any(
            f.severity == SeverityLevel.CRITICAL and "AWS" in f.title
            for f in findings
        )

    def test_detects_github_pat(self) -> None:
        """Should detect GitHub personal access token."""
        content = 'token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh1234"'
        findings = self.scanner._scan_content_for_secrets(content, "ci.yml")
        assert len(findings) >= 1
        assert any(
            f.severity == SeverityLevel.CRITICAL and "GitHub personal" in f.title
            for f in findings
        )

    def test_detects_github_oauth_token(self) -> None:
        """Should detect GitHub OAuth token."""
        content = 'oauth = "gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh1234"'
        findings = self.scanner._scan_content_for_secrets(content, "auth.ts")
        assert len(findings) >= 1
        assert any(
            f.severity == SeverityLevel.HIGH and "GitHub OAuth" in f.title
            for f in findings
        )

    def test_detects_openai_key(self) -> None:
        """Should detect OpenAI API key."""
        content = (
            "OPENAI_KEY=sk-abcdefghijklmnopqrstuvwxyz"
            "ABCDEFGHIJKLMNOP01234567"
        )
        findings = self.scanner._scan_content_for_secrets(content, ".env")
        assert len(findings) >= 1
        assert any(
            f.severity == SeverityLevel.HIGH and "OpenAI" in f.title
            for f in findings
        )

    def test_detects_database_url(self) -> None:
        """Should detect database connection string."""
        content = "DATABASE_URL=postgres://user:pass@host:5432/dbname"
        findings = self.scanner._scan_content_for_secrets(content, ".env")
        assert len(findings) >= 1
        assert any(
            f.severity == SeverityLevel.CRITICAL and "Database" in f.title
            for f in findings
        )

    def test_detects_mongodb_url(self) -> None:
        """Should detect MongoDB connection string."""
        content = "MONGO_URI=mongodb://admin:secret@mongo.example.com:27017/mydb"
        findings = self.scanner._scan_content_for_secrets(content, ".env")
        assert len(findings) >= 1
        assert any("Database" in f.title for f in findings)

    def test_detects_firebase_key(self) -> None:
        """Should detect Firebase/Google API key."""
        content = "FIREBASE_KEY=AIzaSyB1234567890abcdefghijklmnopqrstuv"
        findings = self.scanner._scan_content_for_secrets(content, "config.ts")
        assert len(findings) >= 1
        assert any("Firebase" in f.title for f in findings)

    def test_detects_sendgrid_key(self) -> None:
        """Should detect SendGrid API key."""
        content = (
            "SENDGRID=SG.abcdefghijklmnopqrstuv."
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop123"
        )
        findings = self.scanner._scan_content_for_secrets(content, ".env")
        assert len(findings) >= 1
        assert any("SendGrid" in f.title for f in findings)

    def test_detects_twilio_key(self) -> None:
        """Should detect Twilio API key."""
        content = "TWILIO_KEY=SK1234567890abcdef1234567890abcdef"
        findings = self.scanner._scan_content_for_secrets(content, ".env")
        assert len(findings) >= 1
        assert any("Twilio" in f.title for f in findings)

    def test_detects_private_key(self) -> None:
        """Should detect private key file content."""
        content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA..."
        findings = self.scanner._scan_content_for_secrets(content, "key.pem")
        assert len(findings) >= 1
        assert any(
            f.severity == SeverityLevel.CRITICAL and "Private key" in f.title
            for f in findings
        )

    def test_detects_ec_private_key(self) -> None:
        """Should detect EC private key."""
        content = "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEE..."
        findings = self.scanner._scan_content_for_secrets(content, "ec.key")
        assert len(findings) >= 1

    def test_detects_generic_private_key(self) -> None:
        """Should detect generic private key header."""
        content = "-----BEGIN PRIVATE KEY-----\nMIIEvgIB..."
        findings = self.scanner._scan_content_for_secrets(content, "server.key")
        assert len(findings) >= 1

    def test_no_false_positive_on_clean_code(self) -> None:
        """Should NOT flag normal code without secrets."""
        content = (
            'const greeting = "hello world";\n'
            "const count = 42;\n"
            'function fetchData(url: string) { return fetch(url); }\n'
        )
        findings = self.scanner._scan_content_for_secrets(content, "app.ts")
        assert len(findings) == 0

    def test_no_false_positive_on_short_strings(self) -> None:
        """Should not flag strings shorter than MIN_SECRET_LENGTH."""
        content = 'const x = "sk_li"'  # Too short
        findings = self.scanner._scan_content_for_secrets(content, "app.ts")
        assert len(findings) == 0

    # --- Skip file tests ---

    def test_skip_package_lock(self) -> None:
        """Should skip package-lock.json."""
        assert self.scanner._should_skip_file("package-lock.json") is True

    def test_skip_yarn_lock(self) -> None:
        """Should skip yarn.lock."""
        assert self.scanner._should_skip_file("yarn.lock") is True

    def test_skip_pnpm_lock(self) -> None:
        """Should skip pnpm-lock.yaml."""
        assert self.scanner._should_skip_file("pnpm-lock.yaml") is True

    def test_skip_minified_js(self) -> None:
        """Should skip .min.js files."""
        assert self.scanner._should_skip_file("vendor.min.js") is True

    def test_skip_node_modules(self) -> None:
        """Should skip node_modules paths."""
        assert self.scanner._should_skip_file("node_modules/lodash/index.js") is True

    def test_does_not_skip_normal_files(self) -> None:
        """Should not skip regular source files."""
        assert self.scanner._should_skip_file("src/config.ts") is False
        assert self.scanner._should_skip_file(".env") is False

    # --- Sensitive File Pattern Tests ---

    def test_sensitive_pattern_env_file(self) -> None:
        """Should match .env in sensitive file patterns."""
        assert any(
            re.search(p, ".env")
            for p in SecretScannerConfig.SENSITIVE_FILE_PATTERNS
        )

    def test_sensitive_pattern_env_local(self) -> None:
        """Should match .env.local."""
        assert any(
            re.search(p, ".env.local")
            for p in SecretScannerConfig.SENSITIVE_FILE_PATTERNS
        )

    def test_sensitive_pattern_env_production(self) -> None:
        """Should match .env.production."""
        assert any(
            re.search(p, ".env.production")
            for p in SecretScannerConfig.SENSITIVE_FILE_PATTERNS
        )

    def test_sensitive_pattern_pem_file(self) -> None:
        """Should match .pem files."""
        assert any(
            re.search(p, "server.pem")
            for p in SecretScannerConfig.SENSITIVE_FILE_PATTERNS
        )

    def test_sensitive_pattern_key_file(self) -> None:
        """Should match .key files."""
        assert any(
            re.search(p, "private.key")
            for p in SecretScannerConfig.SENSITIVE_FILE_PATTERNS
        )

    def test_sensitive_pattern_credentials_json(self) -> None:
        """Should match credentials.json."""
        assert any(
            re.search(p, "credentials.json")
            for p in SecretScannerConfig.SENSITIVE_FILE_PATTERNS
        )

    def test_sensitive_pattern_service_account(self) -> None:
        """Should match service account JSON files."""
        assert any(
            re.search(p, "service_account.json")
            for p in SecretScannerConfig.SENSITIVE_FILE_PATTERNS
        )
        assert any(
            re.search(p, "service-account-key.json")
            for p in SecretScannerConfig.SENSITIVE_FILE_PATTERNS
        )

    # --- Line Number + Masking Tests ---

    def test_correct_line_number(self) -> None:
        """Should report correct line number for match."""
        content = (
            "line1\nline2\n"
            "SECRET=sk_live_abcdefghijklmnopqrstuvwxyz\n"
            "line4"
        )
        findings = self.scanner._scan_content_for_secrets(content, "test.env")
        assert len(findings) >= 1
        assert findings[0].line_number == 3

    def test_correct_line_number_first_line(self) -> None:
        """Should report line 1 for match on first line."""
        content = "STRIPE_KEY=sk_live_abcdefghijklmnopqrstuvwxyz"
        findings = self.scanner._scan_content_for_secrets(content, "test.env")
        assert len(findings) >= 1
        assert findings[0].line_number == 1

    def test_secret_is_masked_in_evidence(self) -> None:
        """Should mask the middle of the secret value."""
        content = "KEY=sk_live_abcdefghijklmnopqrstuvwxyz"
        findings = self.scanner._scan_content_for_secrets(content, "test.env")
        assert len(findings) >= 1
        snippet = findings[0].code_snippet
        # Should contain *** and NOT contain the full secret
        assert "***" in snippet
        assert "sk_live_" in snippet  # Prefix preserved
        # Full secret should NOT appear
        assert "sk_live_abcdefghijklmnopqrstuvwxyz" not in snippet

    def test_mask_secret_short(self) -> None:
        """Should mask short secrets appropriately."""
        masked = self.scanner._mask_secret("AKIA1234ABCD5678")
        assert masked.startswith("AKIA1234")
        assert "***" in masked

    def test_mask_secret_very_short(self) -> None:
        """Should handle very short secrets."""
        masked = self.scanner._mask_secret("sk-12345")
        assert masked == "sk-1***"

    # --- Entropy Tests ---

    def test_entropy_high_for_random_string(self) -> None:
        """High entropy string should score above threshold."""
        random_str = "aB3$kL9#mN7@pQ2&rS5*tU8!"
        entropy = self.scanner._calculate_entropy(random_str)
        assert entropy > SecretScannerConfig.ENTROPY_THRESHOLD

    def test_entropy_low_for_repetitive_string(self) -> None:
        """Low entropy string should score below threshold."""
        repetitive = "aaaaaaaaaaaaaaaa"
        entropy = self.scanner._calculate_entropy(repetitive)
        assert entropy < SecretScannerConfig.ENTROPY_THRESHOLD

    def test_entropy_zero_for_empty_string(self) -> None:
        """Empty string should have zero entropy."""
        assert self.scanner._calculate_entropy("") == 0.0

    def test_entropy_one_for_binary(self) -> None:
        """Binary string 'ab' should have entropy of 1.0."""
        assert abs(self.scanner._calculate_entropy("ab") - 1.0) < 0.001

    # --- Git Log Parsing Tests ---

    def test_parse_git_log_output_finds_secrets_in_diff(self) -> None:
        """Should extract secrets from git log -p output."""
        repo = _make_repo()
        log_output = (
            "commit abc123 Initial commit\n"
            "diff --git a/.env b/.env\n"
            "+++ b/.env\n"
            "@@ -0,0 +1,2 @@\n"
            "+DATABASE_URL=postgres://user:pass@host:5432/db\n"
            "+OTHER=value\n"
        )
        findings = self.scanner._parse_git_log_output(log_output, repo)
        assert len(findings) >= 1
        assert any("Database" in f.title for f in findings)
        assert findings[0].commit_hash == "abc123"

    def test_parse_git_log_output_multiple_files(self) -> None:
        """Should handle diffs spanning multiple files."""
        repo = _make_repo()
        log_output = (
            "commit def456 Add config\n"
            "diff --git a/config.ts b/config.ts\n"
            "+++ b/config.ts\n"
            "@@ -0,0 +1 @@\n"
            "+const key = 'sk_live_abcdefghijklmnopqrstuvwxyz'\n"
            "diff --git a/db.ts b/db.ts\n"
            "+++ b/db.ts\n"
            "@@ -0,0 +1 @@\n"
            "+const db = 'postgres://admin:secret@db.example.com:5432/prod'\n"
        )
        findings = self.scanner._parse_git_log_output(log_output, repo)
        assert len(findings) >= 2
        file_paths = {f.file_path for f in findings}
        assert "config.ts" in file_paths
        assert "db.ts" in file_paths

    def test_parse_git_log_skips_lock_files(self) -> None:
        """Should skip secrets found in lock file diffs."""
        repo = _make_repo()
        log_output = (
            "commit aaa111 Add deps\n"
            "diff --git a/package-lock.json b/package-lock.json\n"
            "+++ b/package-lock.json\n"
            "@@ -0,0 +1 @@\n"
            "+  sk_live_abcdefghijklmnopqrstuvwxyz\n"
        )
        findings = self.scanner._parse_git_log_output(log_output, repo)
        assert len(findings) == 0

    def test_parse_git_log_empty_output(self) -> None:
        """Should handle empty git log output."""
        repo = _make_repo()
        findings = self.scanner._parse_git_log_output("", repo)
        assert findings == []

    def test_is_in_current_head_flag_for_history(self) -> None:
        """Findings from history for files not at HEAD should be flagged."""
        repo = _make_repo(file_index={"other.ts": "clean"})
        log_output = (
            "commit abc123 old commit\n"
            "diff --git a/.env b/.env\n"
            "+++ b/.env\n"
            "@@ -0,0 +1 @@\n"
            "+DATABASE_URL=postgres://user:pass@host:5432/db\n"
        )
        findings = self.scanner._parse_git_log_output(log_output, repo)
        assert len(findings) >= 1
        assert findings[0].is_in_current_head is False

    def test_is_in_current_head_flag_for_present_file(self) -> None:
        """Findings for files still at HEAD should be flagged as in HEAD."""
        repo = _make_repo(
            file_index={".env": "DATABASE_URL=postgres://user:pass@host:5432/db"}
        )
        log_output = (
            "commit abc123 old commit\n"
            "diff --git a/.env b/.env\n"
            "+++ b/.env\n"
            "@@ -0,0 +1 @@\n"
            "+DATABASE_URL=postgres://user:pass@host:5432/db\n"
        )
        findings = self.scanner._parse_git_log_output(log_output, repo)
        assert len(findings) >= 1
        assert findings[0].is_in_current_head is True

    # --- Current File Scanning ---

    def test_scan_current_files_detects_secrets(self) -> None:
        """Should detect secrets in file_index contents."""
        repo = _make_repo(
            file_index={
                "config.ts": 'const key = "sk_live_abcdefghijklmnopqrstuvwxyz"',
                "clean.ts": "const x = 42;",
            }
        )
        findings = self.scanner._scan_current_files(repo)
        assert len(findings) >= 1
        assert findings[0].file_path == "config.ts"
        assert findings[0].is_in_current_head is True

    def test_scan_current_files_skips_lock_files(self) -> None:
        """Should skip lock files in file_index."""
        repo = _make_repo(
            file_index={
                "package-lock.json": "sk_live_abcdefghijklmnopqrstuvwxyz",
            }
        )
        findings = self.scanner._scan_current_files(repo)
        assert len(findings) == 0

    # --- Integration: Full async scan ---

    @pytest.mark.asyncio
    async def test_scan_repo_snapshot_current_files(self) -> None:
        """Full scan should find secrets in current files."""
        repo = _make_repo(
            file_index={
                "src/config.ts": "const key = 'sk_live_abcdefghijklmnopqrstuvwxyz'",
                "src/app.ts": "console.log('hello')",
            }
        )

        # Mock git subprocess calls to avoid needing a real repo
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))
        mock_proc.returncode = 0

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            findings = await self.scanner.scan(repo)

        secret_findings = [
            f for f in findings if "Stripe secret" in f.title
        ]
        assert len(secret_findings) >= 1
        assert secret_findings[0].scanner_name == "git_secret_scanner"

    @pytest.mark.asyncio
    async def test_scan_handles_git_timeout(self) -> None:
        """Should handle git log timeout gracefully."""
        import asyncio as aio

        repo = _make_repo()

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(
            side_effect=aio.TimeoutError()
        )

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            # Should not raise
            findings = await self.scanner.scan(repo)

        # May still return findings from other passes (current files, etc.)
        assert isinstance(findings, list)

    @pytest.mark.asyncio
    async def test_scan_handles_git_error(self) -> None:
        """Should handle git errors gracefully without crashing."""
        repo = _make_repo()

        with patch(
            "asyncio.create_subprocess_exec",
            side_effect=OSError("git not found"),
        ):
            findings = await self.scanner.scan(repo)

        assert isinstance(findings, list)

    @pytest.mark.asyncio
    async def test_scan_sensitive_files_finds_env(self) -> None:
        """Should detect .env files in git history."""
        repo = _make_repo()

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(
            return_value=(b".env\n.env.local\nsrc/app.ts\n", b"")
        )
        mock_proc.returncode = 0

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            findings = await self.scanner._scan_sensitive_files(repo)

        env_findings = [f for f in findings if ".env" in f.file_path]
        assert len(env_findings) >= 1

    @pytest.mark.asyncio
    async def test_scan_sensitive_files_finds_pem(self) -> None:
        """Should detect .pem files in git history."""
        repo = _make_repo()

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(
            return_value=(b"server.pem\nREADME.md\n", b"")
        )

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            findings = await self.scanner._scan_sensitive_files(repo)

        assert any("server.pem" in f.file_path for f in findings)

    @pytest.mark.asyncio
    async def test_scan_sensitive_files_finds_credentials_json(self) -> None:
        """Should detect credentials.json in git history."""
        repo = _make_repo()

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(
            return_value=(b"credentials.json\n", b"")
        )

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            findings = await self.scanner._scan_sensitive_files(repo)

        assert len(findings) == 1
        assert "credentials.json" in findings[0].file_path

    @pytest.mark.asyncio
    async def test_scan_sensitive_files_deduplicates(self) -> None:
        """Should not create duplicate findings for the same file."""
        repo = _make_repo()

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(
            return_value=(b".env\n.env\n.env\n", b"")
        )

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            findings = await self.scanner._scan_sensitive_files(repo)

        env_findings = [f for f in findings if f.file_path == ".env"]
        assert len(env_findings) == 1

    # --- Description text tests ---

    def test_finding_description_current_head(self) -> None:
        """Finding for file at HEAD should say 'currently in the codebase'."""
        content = "KEY=sk_live_abcdefghijklmnopqrstuvwxyz"
        findings = self.scanner._scan_content_for_secrets(
            content, ".env", is_in_current_head=True
        )
        assert "currently in the codebase" in findings[0].description

    def test_finding_description_history_only(self) -> None:
        """Finding for file not at HEAD should mention git history."""
        content = "KEY=sk_live_abcdefghijklmnopqrstuvwxyz"
        findings = self.scanner._scan_content_for_secrets(
            content, ".env", is_in_current_head=False
        )
        assert "git history" in findings[0].description

    # --- CodeFinding model integrity ---

    def test_finding_has_correct_category(self) -> None:
        """All findings should use EXPOSED_SECRETS category."""
        content = "sk_live_abcdefghijklmnopqrstuvwxyz"
        findings = self.scanner._scan_content_for_secrets(content, "test.ts")
        for finding in findings:
            assert finding.category == FindingCategory.EXPOSED_SECRETS

    def test_finding_has_confidence(self) -> None:
        """All findings should have confidence set."""
        content = "sk_live_abcdefghijklmnopqrstuvwxyz"
        findings = self.scanner._scan_content_for_secrets(content, "test.ts")
        for finding in findings:
            assert 0.0 < finding.confidence <= 1.0

    def test_finding_has_scanner_name(self) -> None:
        """All findings should carry the scanner name."""
        content = "sk_live_abcdefghijklmnopqrstuvwxyz"
        findings = self.scanner._scan_content_for_secrets(content, "test.ts")
        for finding in findings:
            assert finding.scanner_name == "git_secret_scanner"
