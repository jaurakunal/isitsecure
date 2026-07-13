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
import uuid
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

# In-memory scan storage (per-process, not persistent yet)
_scans: dict[str, dict] = {}
# In-memory "fix all" job storage
_fix_jobs: dict[str, dict] = {}


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    target_url: Optional[str] = None
    repo_url: Optional[str] = None
    github_token: Optional[str] = None
    branch: str = "main"
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

@app.post("/api/scan")
async def start_scan(request: ScanRequest):
    """Start a new security scan. Returns scan_id for SSE streaming."""
    scan_id = str(uuid.uuid4())[:8]
    _scans[scan_id] = {
        "status": "pending",
        "report": None,
        "events": [],
        "llm_provider": request.llm_provider,
    }

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


@app.get("/api/scan/{scan_id}/report")
async def get_report(scan_id: str):
    """Get the completed scan report (raw shape + plain-English superset)."""
    scan = _scans.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if not scan["report"]:
        raise HTTPException(status_code=202, detail="Scan still in progress")
    return _enrich_report(scan["report"])


@app.get("/api/scan/{scan_id}/report.html")
async def get_report_html(scan_id: str):
    """Get the completed scan report as a self-contained HTML document."""
    scan = _scans.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if not scan["report"]:
        raise HTTPException(status_code=202, detail="Scan still in progress")

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

    return {
        "success": result.success,
        "diff": result.diff,
        "explanation": result.explanation,
        "error": result.error,
    }


class FixAllRequest(BaseModel):
    scan_id: str
    severities: Optional[list[str]] = None


@app.post("/api/fix-all")
async def start_fix_all(request: FixAllRequest):
    """Start a batch fix job for a scan's findings. Returns job_id for SSE."""
    scan = _scans.get(request.scan_id)
    if not scan or not scan.get("report"):
        raise HTTPException(status_code=404, detail="Scan report not found")

    from isitsecure.server.fix_service import DEFAULT_SEVERITIES

    job_id = str(uuid.uuid4())[:8]
    _fix_jobs[job_id] = {"status": "running", "events": [], "result": None}
    severities = tuple(request.severities) if request.severities else DEFAULT_SEVERITIES
    # Fixes always need an LLM. If the scan ran without one ("none"), default
    # to anthropic and let the server-side key resolution handle it.
    provider = scan.get("llm_provider") or "anthropic"
    if provider == "none":
        provider = "anthropic"

    asyncio.create_task(
        _run_fix_all_job(job_id, scan["report"], provider, severities)
    )
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


async def _run_fix_all_job(job_id, report, provider, severities):
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
        )
        _fix_jobs[job_id]["result"] = result
        _fix_jobs[job_id]["status"] = "complete"
    except Exception as e:
        logger.exception(f"Fix-all job {job_id} failed")
        _fix_jobs[job_id]["error"] = str(e)
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

    except Exception as e:
        logger.exception(f"Scan {scan_id} failed")
        _scans[scan_id]["status"] = "failed"
        _scans[scan_id]["events"].append({
            "type": "error",
            "message": str(e),
        })
