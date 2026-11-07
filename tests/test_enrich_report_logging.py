"""A per-finding enrichment failure is logged by exception type only (CodeQL
clear-text-logging) and the finding is still returned."""

from __future__ import annotations

import logging

from isitsecure.server import app as server_app
from tests._f2_support import make_finding


def test_finding_enrich_failure_logs_type_only(monkeypatch, caplog):
    finding = make_finding("a.py").model_dump(mode="json")
    finding["id"] = "SECRET-LOOKING-ID"

    def boom(*args, **kwargs):
        raise ValueError("secret-token-123")

    monkeypatch.setattr(server_app, "_glossary_for_finding", boom)
    with caplog.at_level(logging.ERROR, logger="isitsecure.server.app"):
        out = server_app._enrich_report({"findings": [finding]})

    assert [f["id"] for f in out["findings"]] == ["SECRET-LOOKING-ID"]
    text = caplog.text
    assert "ValueError" in text
    assert "SECRET-LOOKING-ID" not in text and "secret-token-123" not in text
