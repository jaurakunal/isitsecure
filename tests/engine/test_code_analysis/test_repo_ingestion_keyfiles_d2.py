"""D2: key-file variants the scanners look for must reach file_index."""

from __future__ import annotations

from pathlib import Path

from isitsecure.engine.code_analysis.framework_detector import FrameworkDetector
from isitsecure.engine.code_analysis.repo_ingestion import RepoIngestionService
from isitsecure.engine.code_analysis.route_mapper import NextJSRouteMapper

INDEXED = [
    "Dockerfile.prod",
    "Dockerfile.staging",
    "api.Dockerfile",
    "compose.yaml",
    "compose.yml",
    "docker-compose.prod.yml",
    "docker-compose.override.yml",
    "requirements-dev.txt",
    "requirements/base.txt",
    "svc/requirements/prod.txt",
    "openapi.yml",
    "swagger.yml",
    ".env.development",
    ".env.test",
    "Dockerfile",  # positive control: previously indexed names still are
    "app/Dockerfile",
]
NOT_INDEXED = [
    ".env.example",
    ".env.sample",
    "notes.txt",
    "node_modules/pkg/Dockerfile.prod",
    "requirements.md",
]


def test_key_file_variants_are_indexed(tmp_path: Path) -> None:
    for rel in INDEXED + NOT_INDEXED:
        f = tmp_path / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("x: 1\n")
    svc = RepoIngestionService(
        framework_detector=FrameworkDetector(), route_mappers=[NextJSRouteMapper()]
    )
    index, _, _ = svc._index_key_files(str(tmp_path))
    for rel in INDEXED:
        assert rel in index, rel
    for rel in NOT_INDEXED:
        assert rel not in index, rel
