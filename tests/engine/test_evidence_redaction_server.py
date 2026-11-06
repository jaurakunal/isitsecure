"""Server outbound report redaction (#282)."""

import json

from isitsecure.engine.models import DeepScanReport
from isitsecure.server.app import _redact_report_dict
from tests.engine.test_evidence_redaction import HEX_KEY, SECRETS, _planted_finding


def test_outbound_payload_is_redacted_but_stored_report_is_not():
    raw = DeepScanReport(findings=[_planted_finding()]).model_dump(mode="json")
    out = json.dumps(_redact_report_dict(raw))
    for secret in SECRETS:
        assert secret not in out, secret
    assert HEX_KEY in json.dumps(raw)


def test_unparseable_report_is_returned_unchanged():
    assert _redact_report_dict({"findings": "nope"}) == {"findings": "nope"}
