"""FastAPI server for the isitsecure web UI.

Serves the pre-built static SPA and provides API endpoints for:
- Starting scans (SSE streaming)
- Retrieving scan reports
- Managing findings (verify, false positive, edit)
- LLM-powered investigation
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import uuid
from urllib.parse import urlsplit
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from isitsecure import __version__
from isitsecure.config import load_api_key

logger = logging.getLogger(__name__)

app = FastAPI(
    title="isitsecure",
    version=__version__,
    description="AI-powered security scanner for modern web apps",
)

# The server holds the user's LLM key, scans arbitrary URLs, and can write
# files (via /api/fix). A wildcard origin let any website the user has open
# drive it cross-origin. Restrict to loopback origins only (the UI is served
# same-origin from this server).
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^https?://(127\.0\.0\.1|localhost)(:\d+)?$",
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Host / Origin allow-list (DNS-rebinding and cross-origin protection)
# ---------------------------------------------------------------------------
# The server has no authentication. Without a Host check, a web page the user
# visits can DNS-rebind a hostname to 127.0.0.1 and drive this API same-origin.
# Only loopback names (plus the host the server was told to bind to, plus
# anything listed in ISITSECURE_ALLOWED_HOSTS) are accepted; everything else
# gets 421 (Host is parsed strictly; exactly one Host header). State-changing
# requests and WebSocket upgrades carrying an Origin that is not same-origin with
# the request (or listed in ISITSECURE_ALLOWED_ORIGINS) get 403.

ALLOWED_HOSTS_ENV = "ISITSECURE_ALLOWED_HOSTS"
BIND_HOST_ENV = "ISITSECURE_BIND_HOST"
ALLOWED_ORIGINS_ENV = "ISITSECURE_ALLOWED_ORIGINS"
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
_WILDCARD_HOSTS = frozenset({"", "0.0.0.0", "::", "*"})
_STATE_CHANGING = frozenset({"POST", "PUT", "PATCH", "DELETE"})


_HOST_NAME_RE = re.compile(r"^[a-z0-9._-]+$")


def _split_host(value: str) -> tuple[str, str] | None:
    """Strictly parse a Host header value into ``(hostname, port)``.

    Returns None for anything that is not ``name``, ``ipv4`` or ``[ipv6]``
    optionally followed by ``:port`` (1-65535). Userinfo, ``#?/\\``,
    whitespace, control or non-ASCII characters and empty hosts are rejected.
    """
    if not isinstance(value, str) or not value or not value.isascii():
        return None
    if any(c.isspace() or ord(c) < 32 or ord(c) == 127 or c in "@#?/\\" for c in value):
        return None
    value = value.lower()
    if value.startswith("["):
        end = value.find("]")
        if end < 0:
            return None
        host, rest = value[1:end], value[end + 1:]
        if not host or not re.fullmatch(r"[0-9a-f:.]+", host) or ":" not in host:
            return None
        if rest and not rest.startswith(":"):
            return None
        port = rest[1:] if rest else ""
        has_port = bool(rest)
    else:
        host, sep, port = value.partition(":")
        has_port = bool(sep)
        if not _HOST_NAME_RE.match(host) or ":" in port:
            return None
    if has_port and not (port.isdigit() and port.isascii() and 1 <= int(port) <= 65535):
        return None
    host = host.rstrip(".")
    return (host, port) if host else None


def _normalize_host(value: str) -> str:
    """Return the lower-cased hostname of a Host header value (no port/brackets);
    "" when the value is malformed."""
    parts = _split_host((value or "").strip())
    return parts[0] if parts else ""


def _allowed_origins() -> frozenset[str]:
    """Extra exact origins from ISITSECURE_ALLOWED_ORIGINS (comma separated)."""
    return frozenset(o.strip().rstrip("/").lower()
                     for o in os.environ.get(ALLOWED_ORIGINS_ENV, "").split(",") if o.strip())


def _origin_ok(origin: str, host_header: str) -> bool:
    """Same-origin check: http(s) Origin whose host:port equals the request's
    Host header, or an exact origin listed in ISITSECURE_ALLOWED_ORIGINS."""
    origin = origin.strip().lower()
    if origin in _allowed_origins():
        return True
    try:
        parts = urlsplit(origin)
        parts.port  # noqa: B018 - raises ValueError on a bad port
    except ValueError:
        return False
    if parts.scheme not in ("http", "https") or parts.path or parts.query or parts.fragment:
        return False
    if "#" in origin or "@" in parts.netloc or not parts.netloc:
        return False
    return parts.netloc == host_header.strip().lower()


def allowed_hosts() -> frozenset[str]:
    """Hostnames the server accepts. ``app.state.allowed_hosts`` overrides the
    computed default (loopback + bind host + ISITSECURE_ALLOWED_HOSTS)."""
    override = getattr(app.state, "allowed_hosts", None)
    if override is not None:
        return frozenset(_normalize_host(h) for h in override)
    hosts = set(LOOPBACK_HOSTS)
    bind = _normalize_host(os.environ.get(BIND_HOST_ENV, ""))
    if bind and bind not in _WILDCARD_HOSTS:
        hosts.add(bind)
    for h in os.environ.get(ALLOWED_HOSTS_ENV, "").split(","):
        h = _normalize_host(h)
        if h:
            hosts.add(h)
    return frozenset(hosts)


class HostOriginGuard:
    """Pure-ASGI middleware enforcing the Host and Origin allow-lists."""

    def __init__(self, asgi_app):
        self.app = asgi_app

    async def __call__(self, scope, receive, send):
        if scope["type"] not in ("http", "websocket"):
            return await self.app(scope, receive, send)
        raw = scope.get("headers", [])
        hosts = [v.decode("latin-1") for k, v in raw if k.lower() == b"host"]
        allowed = allowed_hosts()
        # Exactly one Host header: the guard and the framework must agree on it.
        if len(hosts) != 1 or _normalize_host(hosts[0]) not in allowed:
            return await self._reject(scope, receive, send, 421,
                                      "Host not allowed (see ISITSECURE_ALLOWED_HOSTS)")
        origins = [v.decode("latin-1") for k, v in raw if k.lower() == b"origin"]
        if origins and (scope["type"] == "websocket" or scope.get("method") in _STATE_CHANGING):
            if len(origins) != 1 or not _origin_ok(origins[0], hosts[0]):
                return await self._reject(scope, receive, send, 403, "Origin not allowed")
        return await self.app(scope, receive, send)

    @staticmethod
    async def _reject(scope, receive, send, status, detail):
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return
        from fastapi.responses import JSONResponse
        await JSONResponse({"detail": detail}, status_code=status)(scope, receive, send)


# Added last so it is the outermost middleware: rejects before CORS/routing.
app.add_middleware(HostOriginGuard)

# In-memory scan storage (per-process, not persistent yet)
_scans: dict[str, dict] = {}
# Finished (complete/failed) scans kept for report retrieval; older ones are
# evicted oldest-first. Running/pending scans are never evicted.
MAX_RETAINED_SCANS = 50
# In-memory "fix all" job storage
_fix_jobs: dict[str, dict] = {}


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    target_url: Optional[str] = None
    repo_url: Optional[str] = None
    github_token: Optional[str] = None
    branch: Optional[str] = None  # None = the repository's default branch
    scan_mode: Optional[str] = None
    auth_email: Optional[str] = None
    auth_password: Optional[str] = None
    auth_provider: str = "supabase"
    llm_provider: str = "anthropic"
    api_key: Optional[str] = None


class FindingStatusUpdate(BaseModel):
    status: str  # "verified" | "false_positive" | "pending"


# ---------------------------------------------------------------------------
# API Routes
# ---------------------------------------------------------------------------

def _evict_scans() -> None:
    """Drop the oldest finished scans beyond MAX_RETAINED_SCANS."""
    finished = [k for k, v in _scans.items() if v.get("status") in ("complete", "failed")]
    for k in finished[:max(0, len(finished) - MAX_RETAINED_SCANS)]:
        del _scans[k]


def _settle_scan_key(scan: dict) -> None:
    """Forget the request-supplied LLM key once no fix-all can still need it:
    the scan failed or produced nothing to fix. Otherwise it is kept only until
    the first fix-all started from this scan finishes (or the scan is evicted)."""
    report = scan.get("report")
    if scan.get("status") == "failed" or not (isinstance(report, dict) and report.get("findings")):
        scan["api_key"] = None


@app.post("/api/scan")
async def start_scan(request: ScanRequest):
    """Start a new security scan. Returns scan_id for SSE streaming."""
    scan_id = str(uuid.uuid4())[:8]
    _scans[scan_id] = {
        "status": "pending",
        "report": None,
        "events": [],
        "llm_provider": request.llm_provider,
        # Kept server-side only so fix-all can reuse the key the scan used.
        "api_key": request.api_key,
        "error": None,
    }

    _evict_scans()

    # Launch scan in background
    asyncio.create_task(_run_scan_background(scan_id, request))

    return {"scan_id": scan_id}


@app.get("/api/scan/{scan_id}/stream")
async def stream_scan(scan_id: str):
    """SSE endpoint for real-time scan progress."""
    if scan_id not in _scans:
        raise HTTPException(status_code=404, detail="Scan not found")

    async def event_generator():
        last_idx = 0
        while True:
            scan = _scans.get(scan_id)
            if not scan:
                break

            events = scan["events"]
            while last_idx < len(events):
                yield f"data: {json.dumps(events[last_idx])}\n\n"
                last_idx += 1

            if scan["status"] in ("complete", "failed"):
                if scan["report"]:
                    yield f"data: {json.dumps({'type': 'report', 'data': scan['report']})}\n\n"
                yield f"data: {json.dumps({'type': 'done'})}\n\n"
                break

            await asyncio.sleep(0.5)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


def _enrich_report(raw_report: dict) -> dict:
    """Return the raw scan report augmented with plain-English fields.

    The React UI consumes the RAW ``DeepScanReport`` shape (flat ``findings``
    list with ``scanner_name``/``code_location.file_path``/``owner_summary``).
    We keep that shape intact and add the Wave 1 plain-English layer as a
    SUPERSET so nothing existing breaks:

    * top-level: ``grade``, ``grade_base``, ``grade_label``, ``grade_legend``,
      and ``launch_verdict`` (``ready``/``headline``/``detail``/``line``).
    * per finding (matched by ``id``): ``plain_explanation``,
      ``business_impact`` and ``glossary``.

    The enrichment is rule-based and LLM-free, so it works for every scan
    (including ``--llm none``). Any failure falls back to the raw report so
    the endpoint never 500s on a report that would otherwise render fine.
    """
    from isitsecure.engine.models import DeepScanReport
    from isitsecure.engine.reporting.report_generator import ReportGenerator
    from isitsecure.engine.reporting import plain_english

    try:
        report_model = DeepScanReport.model_validate(raw_report)
        generated = ReportGenerator().generate(report_model)
    except Exception:
        logger.exception("Failed to enrich report; returning raw report")
        return raw_report

    # Shallow copy so we don't mutate the stored scan report.
    enriched = dict(raw_report)

    # Top-level plain-English / grade / launch-verdict fields (from generate()).
    for key in ("grade", "grade_base", "grade_label", "grade_legend", "launch_verdict"):
        if key in generated:
            enriched[key] = generated[key]

    # Per-finding enrichment derived directly from the raw findings via the
    # rule-based plain_english layer. Deriving it here (rather than from
    # generate()'s severity groups) guarantees EVERY finding is covered,
    # including INFO-severity ones the report groups omit.
    # Detected stack drives the stack-tailored remediation snippets (#48).
    framework = enriched.get("framework", "")
    backend = enriched.get("backend", "")

    raw_findings = enriched.get("findings")
    if isinstance(raw_findings, list):
        merged_findings = []
        for f in raw_findings:
            merged = dict(f)
            category = f.get("category", "")
            try:
                explanation = plain_english.explain_finding_category(category)
                merged["plain_explanation"] = explanation.as_dict()
                merged["business_impact"] = plain_english.business_impact(category)
                merged["glossary"] = _glossary_for_finding(f, plain_english)
                # #47/#48 — specific + stack-tailored remediation. Prefer the
                # finding's own (LLM-enriched) guidance when present.
                merged["remediation_guidance"] = (
                    f.get("remediation_guidance")
                    or plain_english.remediation_detail(
                        category, framework, backend
                    )
                )
                merged["remediation_snippet"] = plain_english.framework_remediation(
                    category, framework, backend
                )
                # #49 — numbered step-by-step walkthrough for the top-4 fixes.
                walk = plain_english.walkthrough_for(category)
                merged["walkthrough"] = walk.as_dict() if walk else None
            except Exception:
                logger.exception("Failed to enrich finding %s", f.get("id"))
            merged_findings.append(merged)
        enriched["findings"] = merged_findings

    return enriched


def _glossary_for_finding(finding: dict, plain_english) -> dict[str, str]:
    """Return {term: definition} for glossary terms in a finding's text.

    Mirrors ReportGenerator._glossary_for but operates on the raw finding
    dict so tooltips can be attached in the UI.
    """
    import re

    text = f"{finding.get('title', '')} {finding.get('category', '')}".lower()
    found: dict[str, str] = {}
    for term, definition in plain_english.GLOSSARY.items():
        if re.search(rf"\b{re.escape(term)}\b", text):
            found[term] = definition
    return found


def _raise_unless_ready(scan: dict) -> None:
    """202 while running, a failed-status error once the scan failed."""
    if scan["report"]:
        return
    if scan["status"] == "failed":
        raise HTTPException(
            status_code=500,
            detail=f"Scan failed: {scan.get('error') or 'unknown error'}",
        )
    raise HTTPException(status_code=202, detail="Scan still in progress")


@app.get("/api/scan/{scan_id}/report")
async def get_report(scan_id: str):
    """Get the completed scan report (raw shape + plain-English superset)."""
    scan = _scans.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    _raise_unless_ready(scan)
    return _enrich_report(scan["report"])


@app.get("/api/scan/{scan_id}/report.html")
async def get_report_html(scan_id: str):
    """Get the completed scan report as a self-contained HTML document."""
    scan = _scans.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    _raise_unless_ready(scan)

    from isitsecure.engine.models import DeepScanReport
    from isitsecure.engine.reporting.report_generator import ReportGenerator
    from isitsecure.engine.reporting.html_renderer import HTMLReportRenderer

    report_model = DeepScanReport.model_validate(scan["report"])
    generator = ReportGenerator()
    renderer = HTMLReportRenderer()
    report_data = generator.generate(report_model)
    html = renderer.render(report_data)

    return HTMLResponse(html, headers={"Content-Type": "text/html; charset=utf-8"})


class FixRequest(BaseModel):
    finding_id: str
    file_content: str
    llm_provider: str = "anthropic"
    api_key: Optional[str] = None


@app.post("/api/fix")
async def generate_fix(request: FixRequest):
    """Generate an AI-powered fix for a single finding."""
    # Resolve the API key: request wins, else server environment/config.
    api_key = request.api_key or load_api_key(request.llm_provider)
    if not api_key:
        raise HTTPException(
            status_code=400,
            detail=(
                f"No API key found for {request.llm_provider}. Set "
                f"{request.llm_provider.upper()}_API_KEY or run 'isitsecure setup'."
            ),
        )

    # Find the scan that contains this finding
    finding_data = None
    for scan in _scans.values():
        if not scan.get("report"):
            continue
        for f in scan["report"].get("findings", []):
            if f.get("id") == request.finding_id:
                finding_data = f
                break
        if finding_data:
            break

    if not finding_data:
        raise HTTPException(status_code=404, detail="Finding not found")

    from isitsecure.engine.models import DeepFinding
    from isitsecure.engine.fixes.fix_generator import FixGenerator
    from isitsecure.llm.adapters import create_llm_client

    llm_client = create_llm_client(request.llm_provider, api_key)
    generator = FixGenerator(llm_client)

    finding = DeepFinding.model_validate(finding_data)
    result = await generator.generate_fix(finding, request.file_content)

    # Plain-language verify status for the UI (#50). A single-finding fix is
    # generated but not applied/re-scanned here, so a successful fix is
    # "needs_review" (a human should look before trusting it), and a failure is
    # "couldnt_fix".
    from isitsecure.engine.fixes import plain_results
    status = plain_results.status_for_single(result.success, verified=None)

    return {
        "success": result.success,
        "status": status,
        "diff": result.diff,
        "explanation": result.explanation,
        "error": result.error,
    }


class FixAllRequest(BaseModel):
    scan_id: str
    severities: Optional[list[str]] = None
    # Remote-repo → pull-request flow (GitHub only). The token is used for the
    # push + PR API and is NEVER persisted or logged.
    github_token: Optional[str] = None
    pr_strategy: Optional[str] = None
    max_prs: Optional[int] = None


@app.post("/api/fix-all")
async def start_fix_all(request: FixAllRequest):
    """Start a batch fix job for a scan's findings. Returns job_id for SSE."""
    scan = _scans.get(request.scan_id)
    if not scan or not scan.get("report"):
        raise HTTPException(status_code=404, detail="Scan report not found")

    from isitsecure.server.fix_service import (
        DEFAULT_SEVERITIES,
        DEFAULT_MAX_PRS,
        DEFAULT_STRATEGY,
    )

    job_id = str(uuid.uuid4())[:8]
    _fix_jobs[job_id] = {"status": "running", "events": [], "result": None}
    severities = tuple(request.severities) if request.severities else DEFAULT_SEVERITIES
    # Fixes always need an LLM. If the scan ran without one ("none"), default
    # to anthropic and let the server-side key resolution handle it.
    provider = scan.get("llm_provider") or "anthropic"
    if provider == "none":
        provider = "anthropic"

    api_key = scan.get("api_key")

    async def _job_then_forget_key():
        try:
            await _run_fix_all_job(
                job_id,
                scan["report"],
                provider,
                severities,
                github_token=request.github_token,
                pr_strategy=request.pr_strategy or DEFAULT_STRATEGY,
                max_prs=request.max_prs or DEFAULT_MAX_PRS,
                api_key=api_key,
            )
        finally:
            # The fix-all that needed the key has finished; do not keep it.
            scan["api_key"] = None

    asyncio.create_task(_job_then_forget_key())
    return {"job_id": job_id}


@app.get("/api/fix-all/{job_id}/stream")
async def stream_fix_all(job_id: str):
    """SSE endpoint for real-time fix-all progress and the final result."""
    if job_id not in _fix_jobs:
        raise HTTPException(status_code=404, detail="Fix job not found")

    async def event_generator():
        last_idx = 0
        while True:
            job = _fix_jobs.get(job_id)
            if not job:
                break
            events = job["events"]
            while last_idx < len(events):
                yield f"data: {json.dumps(events[last_idx])}\n\n"
                last_idx += 1
            if job["status"] in ("complete", "failed"):
                if job["result"] is not None:
                    yield f"data: {json.dumps({'type': 'done', 'result': job['result']})}\n\n"
                else:
                    yield f"data: {json.dumps({'type': 'error', 'message': job.get('error', 'Fix failed')})}\n\n"
                break
            await asyncio.sleep(0.3)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


async def _run_fix_all_job(
    job_id,
    report,
    provider,
    severities,
    *,
    github_token=None,
    pr_strategy="per-category",
    max_prs=8,
    api_key=None,
):
    """Run the batch fix service, streaming progress into the job store."""
    from isitsecure.server.fix_service import run_fix_all

    async def emit(event: dict) -> None:
        _fix_jobs[job_id]["events"].append(event)

    try:
        result = await run_fix_all(
            report=report,
            llm_provider=provider,
            severities=severities,
            emit=emit,
            github_token=github_token,
            pr_strategy=pr_strategy,
            max_prs=max_prs,
            api_key=api_key,
        )
        _fix_jobs[job_id]["result"] = result
        _fix_jobs[job_id]["status"] = "complete"
    except Exception as e:
        # Defense-in-depth: the GitHub token must never surface to the client or
        # the log. pr_flow scrubs its own git/GitHub errors, but any unexpected
        # exception that bubbles up here gets scrubbed once more before storing.
        logger.exception("Fix-all job %s failed", job_id)
        msg = str(e)
        if github_token and github_token in msg:
            msg = msg.replace(github_token, "***")
        _fix_jobs[job_id]["error"] = msg
        _fix_jobs[job_id]["status"] = "failed"


@app.get("/api/health")
async def health():
    return {"status": "ok", "version": __version__}


# ---------------------------------------------------------------------------
# Static UI serving
# ---------------------------------------------------------------------------

STATIC_DIR = Path(__file__).parent / "static"

if STATIC_DIR.exists() and (STATIC_DIR / "index.html").exists():
    app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")
else:
    @app.get("/")
    async def placeholder_ui():
        return HTMLResponse(f"""
        <!DOCTYPE html>
        <html>
        <head><title>isitsecure v{__version__}</title>
        <style>
            body {{ font-family: system-ui; background: #0c0a1a; color: #e2e0f0;
                   display: flex; align-items: center; justify-content: center;
                   min-height: 100vh; margin: 0; }}
            .container {{ text-align: center; max-width: 600px; padding: 2rem; }}
            h1 {{ color: #c4b5fd; }}
            code {{ background: #1a1533; padding: 2px 8px; border-radius: 4px; }}
            a {{ color: #7c3aed; }}
        </style>
        </head>
        <body>
        <div class="container">
            <h1>isitsecure v{__version__}</h1>
            <p>The web UI is not yet built. Use the CLI instead:</p>
            <p><code>isitsecure scan https://your-app.com</code></p>
            <p><code>isitsecure scan --repo github.com/you/app --mode full</code></p>
            <p>API is available at <a href="/api/health">/api/health</a></p>
        </div>
        </body>
        </html>
        """)


# ---------------------------------------------------------------------------
# Background scan runner
# ---------------------------------------------------------------------------

async def _run_scan_background(scan_id: str, request: ScanRequest) -> None:
    """Run the scan engine and stream events to the scan store."""
    try:
        _scans[scan_id]["status"] = "running"

        # Build LLM client. The key comes from the request if provided,
        # otherwise from the server environment/config (env var, .env, or
        # ~/.isitsecure/config.toml) — same resolution the CLI uses.
        llm_client = None
        judgment_llm_client = None
        api_key = request.api_key or load_api_key(request.llm_provider)
        if request.llm_provider != "none" and api_key:
            from isitsecure.llm.adapters import create_llm_client
            llm_client = create_llm_client(request.llm_provider, api_key)
            judgment_llm_client = create_llm_client(
                request.llm_provider, api_key, judgment=True
            )

        from isitsecure.engine.factory import (
            create_deep_security_scan_agent,
            create_repo_ingestion_service,
        )

        repo_service = create_repo_ingestion_service() if request.repo_url else None
        agent = create_deep_security_scan_agent(
            llm_client=llm_client,
            judgment_llm_client=judgment_llm_client,
            repo_ingestion_service=repo_service,
        )

        # Build credentials
        credentials_a = None
        if request.auth_email and request.auth_password:
            from isitsecure.engine.auth.protocols import AuthCredentials
            from isitsecure.engine.enums import AuthProvider as AuthProviderEnum
            credentials_a = AuthCredentials(
                provider=AuthProviderEnum(request.auth_provider),
                email=request.auth_email,
                password=request.auth_password,
            )

        # Resolve scan mode
        from isitsecure.engine.enums import ScanMode
        scan_mode = None
        if request.scan_mode:
            mode_map = {
                "url_only": ScanMode.URL_ONLY,
                "code_only": ScanMode.CODE_ONLY,
                "authenticated": ScanMode.AUTHENTICATED,
                "full": ScanMode.FULL,
            }
            scan_mode = mode_map.get(request.scan_mode)

        report_json = None
        async for event in agent.scan(
            target_url=request.target_url,
            repo_url=request.repo_url,
            github_token=request.github_token,
            credentials_a=credentials_a,
            scan_mode=scan_mode,
            repo_branch=request.branch,
        ):
            phase = getattr(event, "phase", "")
            message = getattr(event, "message", "")
            progress = getattr(event, "progress", 0)
            data = getattr(event, "data", None)

            _scans[scan_id]["events"].append({
                "type": "progress",
                "phase": phase,
                "message": message,
                "progress": progress,
            })

            # The final COMPLETE event carries the report as a JSON-ready dict
            # under data["report"].
            if isinstance(data, dict) and "report" in data:
                report_json = data["report"]

        if report_json:
            _scans[scan_id]["report"] = report_json
            _scans[scan_id]["status"] = "complete"
        else:
            msg = "Scan finished without producing a report."
            _scans[scan_id]["status"] = "failed"
            _scans[scan_id]["error"] = msg
            _scans[scan_id]["events"].append({"type": "error", "message": msg})
        _settle_scan_key(_scans[scan_id])
        _evict_scans()

    except Exception as e:
        logger.exception(f"Scan {scan_id} failed")
        _scans[scan_id]["status"] = "failed"
        _scans[scan_id]["error"] = str(e)
        _scans[scan_id]["events"].append({
            "type": "error",
            "message": str(e),
        })
        _settle_scan_key(_scans[scan_id])
        _evict_scans()
