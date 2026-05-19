"""Tests for the FirebaseRulesAnalyzer."""

from __future__ import annotations

import pytest

from isitsecure.engine.code_analysis.firebase_rules_analyzer import (
    FirebaseRulesAnalyzer,
)
from isitsecure.engine.code_analysis.protocols import RepoSnapshot
from isitsecure.engine.constants import FirebaseRulesConfig
from isitsecure.engine.enums import FindingCategory, SeverityLevel

# ---------------------------------------------------------------------------
# Fixture rules
# ---------------------------------------------------------------------------

OPEN_FIRESTORE_RULES = """
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} {
      allow read, write: if true;
    }
  }
}
"""

SECURE_FIRESTORE_RULES = """
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /users/{userId} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }
  }
}
"""

MISSING_AUTH_FIRESTORE_RULES = """
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /public/{docId} {
      allow read: if true;
    }
    match /private/{docId} {
      allow write: if resource.data.status == 'draft';
    }
  }
}
"""

OPEN_RTDB_RULES = '{"rules": {".read": true, ".write": true}}'

SECURE_RTDB_RULES = '{"rules": {".read": "auth != null", ".write": "auth != null"}}'

OPEN_STORAGE_RULES = """
rules_version = '2';
service firebase.storage {
  match /b/{bucket}/o {
    match /{allPaths=**} {
      allow read, write: if true;
    }
  }
}
"""

SECURE_STORAGE_RULES = """
rules_version = '2';
service firebase.storage {
  match /b/{bucket}/o {
    match /users/{userId}/{allPaths=**} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }
  }
}
"""

WILDCARD_FIRESTORE_RULES = """
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} {
      allow read: if request.auth != null;
    }
  }
}
"""


def _make_repo(**file_map: str) -> RepoSnapshot:
    """Create a minimal RepoSnapshot with the given file_index."""
    return RepoSnapshot(
        repo_url="https://github.com/test/repo",
        branch="main",
        clone_path="/tmp/repo",
        file_index=file_map,
    )


class TestFirebaseRulesAnalyzer:
    """Tests for FirebaseRulesAnalyzer."""

    def test_scanner_name(self) -> None:
        analyzer = FirebaseRulesAnalyzer()
        assert analyzer.scanner_name == FirebaseRulesConfig.SCANNER_NAME

    @pytest.mark.asyncio
    async def test_detects_open_read_write(self) -> None:
        analyzer = FirebaseRulesAnalyzer()
        repo = _make_repo(**{"firestore.rules": OPEN_FIRESTORE_RULES})

        findings = await analyzer.scan(repo)

        assert len(findings) >= 1
        critical = [f for f in findings if f.severity == SeverityLevel.CRITICAL]
        assert len(critical) >= 1
        assert critical[0].category == FindingCategory.AUTH_WEAKNESS
        assert "Firestore" in critical[0].title
        assert "unrestricted" in critical[0].description.lower()

    @pytest.mark.asyncio
    async def test_detects_missing_auth(self) -> None:
        analyzer = FirebaseRulesAnalyzer()
        repo = _make_repo(**{"firestore.rules": MISSING_AUTH_FIRESTORE_RULES})

        findings = await analyzer.scan(repo)

        # Should detect the 'allow write;' without auth check
        auth_findings = [
            f for f in findings
            if "authentication" in f.title.lower() or "missing" in f.title.lower()
        ]
        assert len(auth_findings) >= 1

    @pytest.mark.asyncio
    async def test_no_finding_for_secure_rules(self) -> None:
        analyzer = FirebaseRulesAnalyzer()
        repo = _make_repo(**{"firestore.rules": SECURE_FIRESTORE_RULES})

        findings = await analyzer.scan(repo)

        # Secure rules should produce no critical or high findings
        serious = [
            f for f in findings
            if f.severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH)
        ]
        assert len(serious) == 0

    @pytest.mark.asyncio
    async def test_detects_rtdb_open_rules(self) -> None:
        analyzer = FirebaseRulesAnalyzer()
        repo = _make_repo(**{"database.rules.json": OPEN_RTDB_RULES})

        findings = await analyzer.scan(repo)

        assert len(findings) >= 1
        # Both .read: true and .write: true should be flagged
        critical = [f for f in findings if f.severity == SeverityLevel.CRITICAL]
        assert len(critical) >= 2
        assert any("Realtime Database" in f.title for f in critical)

    @pytest.mark.asyncio
    async def test_handles_no_rules_files(self) -> None:
        analyzer = FirebaseRulesAnalyzer()
        repo = _make_repo(**{
            "src/index.ts": "console.log('hello');",
            "package.json": '{"name": "test"}',
        })

        findings = await analyzer.scan(repo)

        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_detects_storage_rules_issues(self) -> None:
        analyzer = FirebaseRulesAnalyzer()
        repo = _make_repo(**{"storage.rules": OPEN_STORAGE_RULES})

        findings = await analyzer.scan(repo)

        assert len(findings) >= 1
        critical = [f for f in findings if f.severity == SeverityLevel.CRITICAL]
        assert len(critical) >= 1
        assert any("Storage" in f.title for f in critical)

    @pytest.mark.asyncio
    async def test_secure_storage_rules(self) -> None:
        analyzer = FirebaseRulesAnalyzer()
        repo = _make_repo(**{"storage.rules": SECURE_STORAGE_RULES})

        findings = await analyzer.scan(repo)

        serious = [
            f for f in findings
            if f.severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH)
        ]
        assert len(serious) == 0

    @pytest.mark.asyncio
    async def test_detects_wildcard_collection(self) -> None:
        analyzer = FirebaseRulesAnalyzer()
        repo = _make_repo(**{"firestore.rules": WILDCARD_FIRESTORE_RULES})

        findings = await analyzer.scan(repo)

        wildcard_findings = [
            f for f in findings
            if "wildcard" in f.title.lower()
        ]
        assert len(wildcard_findings) >= 1
        assert wildcard_findings[0].severity == SeverityLevel.MEDIUM

    @pytest.mark.asyncio
    async def test_secure_rtdb_rules(self) -> None:
        analyzer = FirebaseRulesAnalyzer()
        repo = _make_repo(**{"database.rules.json": SECURE_RTDB_RULES})

        findings = await analyzer.scan(repo)

        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_firebase_subdir_rules(self) -> None:
        """Rules inside a firebase/ subdirectory should also be detected."""
        analyzer = FirebaseRulesAnalyzer()
        repo = _make_repo(**{
            "firebase/firestore.rules": OPEN_FIRESTORE_RULES
        })

        findings = await analyzer.scan(repo)

        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_line_numbers_reported(self) -> None:
        analyzer = FirebaseRulesAnalyzer()
        repo = _make_repo(**{"firestore.rules": OPEN_FIRESTORE_RULES})

        findings = await analyzer.scan(repo)

        critical = [f for f in findings if f.severity == SeverityLevel.CRITICAL]
        assert len(critical) >= 1
        # The "allow read, write: if true" is on line 6
        assert critical[0].line_number is not None
        assert critical[0].line_number > 0
