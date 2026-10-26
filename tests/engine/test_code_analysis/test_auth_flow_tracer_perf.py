"""The auth tracer scales linearly with the number of routes in one file."""

from __future__ import annotations

import time

import pytest

from isitsecure.engine.code_analysis.lsp.auth_flow_tracer import AuthFlowTracer
from isitsecure.engine.code_analysis.protocols import RepoSnapshot, RouteEntry

PATH = "app/views.py"


class _NoLSP:
    async def get_definition(self, f, line, col):
        return []


def _source(n: int) -> str:
    parts = ["from flask import Flask\napp = Flask(__name__)\n"]
    for i in range(n):
        guard = "@login_required\n" if i % 3 == 0 else ""
        inline = (
            "    user = get_current_user_or_401()\n" if i % 3 == 1 else ""
        )
        parts.append(
            f"@app.route('/api/r{i}', methods=['POST'])\n{guard}"
            f"def handler_{i}():\n{inline}    return 'ok'\n\n"
        )
    return "".join(parts)


async def _verdicts(n: int) -> dict[str, bool]:
    routes = [
        RouteEntry(file_path=PATH, http_methods=["POST"], route_pattern=f"/api/r{i}")
        for i in range(n)
    ]
    repo = RepoSnapshot(
        repo_url="x", branch="m", clone_path="/tmp/nonexistent-perf",
        file_index={PATH: _source(n)},
    )
    out = await AuthFlowTracer(_NoLSP(), repo).trace_routes(routes)
    return {k.split(":", 1)[1]: v.has_verified_auth for k, v in out.items()}


@pytest.mark.asyncio
async def test_1500_routes_in_one_file_finish_quickly_with_identical_verdicts() -> None:
    small = await _verdicts(30)
    started = time.monotonic()
    big = await _verdicts(1500)
    elapsed = time.monotonic() - started
    assert elapsed < 2.0, f"took {elapsed:.1f}s"
    # Same per-route verdicts as the small-file run (the generator is periodic).
    for key, verdict in small.items():
        assert big[key] == verdict
    # Positive control: guarded routes verified, unguarded ones not.
    assert big["POST /api/r0"] is True
    assert big["POST /api/r2"] is False
    assert sum(big.values()) >= 500
