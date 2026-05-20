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

logger = logging.getLogger(__name__)

app = FastAPI(
    title="isitsecure",
    version=__version__,
    description="AI-powered security scanner for modern web apps",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory scan storage (per-process, not persistent yet)
_scans: dict[str, dict] = {}


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
    _scans[scan_id] = {"status": "pending", "report": None, "events": []}

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


@app.get("/api/scan/{scan_id}/report")
async def get_report(scan_id: str):
    """Get the completed scan report."""
    scan = _scans.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if not scan["report"]:
        raise HTTPException(status_code=202, detail="Scan still in progress")
    return scan["report"]


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
    api_key: str


@app.post("/api/fix")
async def generate_fix(request: FixRequest):
    """Generate an AI-powered fix for a single finding."""
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

    llm_client = create_llm_client(request.llm_provider, request.api_key)
    generator = FixGenerator(llm_client)

    finding = DeepFinding.model_validate(finding_data)
    result = await generator.generate_fix(finding, request.file_content)

    return {
        "success": result.success,
        "diff": result.diff,
        "explanation": result.explanation,
        "error": result.error,
    }


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

        # Build LLM client
        llm_client = None
        judgment_llm_client = None
        if request.llm_provider != "none" and request.api_key:
            from isitsecure.llm.adapters import create_llm_client
            llm_client = create_llm_client(request.llm_provider, request.api_key)
            judgment_llm_client = create_llm_client(
                request.llm_provider, request.api_key, judgment=True
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

        report = None
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

            if data and hasattr(data, "findings"):
                report = data

        if report:
            _scans[scan_id]["report"] = json.loads(report.model_dump_json())
        _scans[scan_id]["status"] = "complete"

    except Exception as e:
        logger.exception(f"Scan {scan_id} failed")
        _scans[scan_id]["status"] = "failed"
        _scans[scan_id]["events"].append({
            "type": "error",
            "message": str(e),
        })
