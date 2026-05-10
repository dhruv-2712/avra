"""
AVRA API Routes
───────────────
POST /api/scans              — kick off a scan
GET  /api/scans/{id}         — get scan result + report
GET  /api/scans/{id}/stream  — SSE stream of agent steps, findings, report
GET  /api/scans              — list recent scans
"""
import asyncio
import json
import uuid
from datetime import datetime
from typing import AsyncGenerator

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from core.database import get_db, Scan, ScanStatus as DBScanStatus, AsyncSessionLocal
from models.scan import (
    ScanRequest, ScanResponse, ScanResult, ScanState, ScanStatus, Finding, AgentStep, Report
)
from core.pipeline import run_pipeline

router = APIRouter()

# In-memory SSE store: scan_id → list of events
_scan_events: dict[str, list[dict]] = {}
_scan_complete: dict[str, asyncio.Event] = {}


def _emit(scan_id: str, event: dict):
    _scan_events.setdefault(scan_id, []).append(event)


async def _run_scan_background(scan_id: str, repo_url: str, db_session_factory):
    """Run the full 5-node pipeline in background, emit SSE events, persist to DB."""
    async with db_session_factory() as db:
        try:
            result = await db.execute(select(Scan).where(Scan.id == scan_id))
            scan_row = result.scalar_one_or_none()
            if not scan_row:
                return

            scan_row.status = DBScanStatus.RUNNING
            await db.commit()

            state = ScanState(
                scan_id=scan_id,
                repo_url=repo_url,
                status=ScanStatus.RUNNING,
            )

            loop = asyncio.get_running_loop()
            result_state = await loop.run_in_executor(None, run_pipeline, state)

            # Emit agent steps
            for step in result_state.steps:
                _emit(scan_id, {"type": "step", "data": step.model_dump()})

            # Use most-enriched findings available
            final_findings = (
                result_state.findings_with_context
                or result_state.triaged_findings
                or result_state.raw_findings
            )
            findings_data = [f.model_dump() for f in final_findings]
            _emit(scan_id, {"type": "findings", "data": findings_data})

            # Emit report if generated
            report_data = result_state.report.model_dump() if result_state.report else None
            if report_data:
                _emit(scan_id, {"type": "report", "data": report_data})

            # Persist
            scan_row.status = (
                DBScanStatus.COMPLETE if not result_state.error else DBScanStatus.FAILED
            )
            scan_row.language = result_state.language
            scan_row.findings_raw = findings_data
            scan_row.steps_raw = [s.model_dump() for s in result_state.steps]
            scan_row.report = report_data
            scan_row.error = result_state.error
            await db.commit()

            final_status = "complete" if not result_state.error else "failed"
            _emit(scan_id, {"type": "done", "data": {"status": final_status}})

        except Exception as e:
            _emit(scan_id, {"type": "error", "data": {"message": str(e)}})
            async with db_session_factory() as db2:
                result = await db2.execute(select(Scan).where(Scan.id == scan_id))
                row = result.scalar_one_or_none()
                if row:
                    row.status = DBScanStatus.FAILED
                    row.error = str(e)
                    await db2.commit()
        finally:
            if scan_id in _scan_complete:
                _scan_complete[scan_id].set()


@router.post("/scans", response_model=ScanResponse)
async def create_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    scan_id = str(uuid.uuid4())

    scan_row = Scan(
        id=scan_id,
        repo_url=request.repo_url,
        status=DBScanStatus.PENDING,
    )
    db.add(scan_row)
    await db.commit()

    _scan_events[scan_id] = []
    _scan_complete[scan_id] = asyncio.Event()

    background_tasks.add_task(
        _run_scan_background, scan_id, request.repo_url, AsyncSessionLocal
    )

    return ScanResponse(
        scan_id=scan_id,
        status=ScanStatus.PENDING,
        repo_url=request.repo_url,
        created_at=datetime.utcnow().isoformat(),
    )


@router.get("/scans/{scan_id}/stream")
async def stream_scan(scan_id: str):
    """SSE — streams steps, findings, report, and done events."""

    async def event_generator() -> AsyncGenerator[str, None]:
        sent = 0
        timeout = 600  # 10 min max for large repos + LLM triage
        elapsed = 0

        while elapsed < timeout:
            events = _scan_events.get(scan_id, [])

            while sent < len(events):
                event = events[sent]
                yield f"data: {json.dumps(event)}\n\n"
                sent += 1
                if event.get("type") in ("done", "error"):
                    return

            await asyncio.sleep(0.5)
            elapsed += 0.5

        yield f"data: {json.dumps({'type': 'error', 'data': {'message': 'Scan timed out'}})}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@router.get("/scans/{scan_id}", response_model=ScanResult)
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = [Finding(**f) for f in (row.findings_raw or [])]
    steps = [AgentStep(**s) for s in (row.steps_raw or [])]
    report = Report(**row.report) if row.report else None

    return ScanResult(
        scan_id=row.id,
        status=ScanStatus(row.status.value),
        repo_url=row.repo_url,
        language=row.language,
        findings=findings,
        steps=steps,
        report=report,
        error=row.error,
    )


@router.get("/scans")
async def list_scans(db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Scan).order_by(Scan.created_at.desc()).limit(20)
    )
    rows = result.scalars().all()
    return [
        {
            "scan_id": r.id,
            "repo_url": r.repo_url,
            "status": r.status.value,
            "language": r.language,
            "finding_count": len(r.findings_raw or []),
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]
