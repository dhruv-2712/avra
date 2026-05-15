"""
AVRA API Routes
───────────────
POST   /api/scans                  — kick off a scan (auth + rate-limited)
DELETE /api/scans/{id}             — cancel a running scan
GET    /api/scans/{id}             — get scan result + report
GET    /api/scans/{id}/stream      — SSE: live agent steps, findings, report
GET    /api/scans/{id}/report.md   — download Markdown report
GET    /api/scans/{id}/report.pdf  — download PDF report
GET    /api/scans                  — list recent scans
"""
import asyncio
import json
import queue as _queue
import shutil
import uuid
from datetime import datetime, timezone
from typing import AsyncGenerator

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Request
from fastapi.responses import StreamingResponse, Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from core.limiter import limiter
from core.database import get_db, Scan, ScanStatus as DBScanStatus, AsyncSessionLocal
from core.pipeline import run_pipeline, register_step_queue, unregister_step_queue
from core.config import SCAN_TIMEOUT, SSE_GRACE_SECONDS
from models.scan import (
    ScanRequest, ScanResponse, ScanResult, ScanState, ScanStatus, Finding, AgentStep, Report
)

router = APIRouter()

# In-memory SSE store: scan_id → asyncio.Queue of serialised events
# Queues are created on scan start and cleaned up SSE_GRACE_SECONDS after stream ends.
_scan_queues: dict[str, asyncio.Queue] = {}
_scan_complete: dict[str, asyncio.Event] = {}
_cancelled_scans: set[str] = set()


def _emit(scan_id: str, event: dict) -> None:
    q = _scan_queues.get(scan_id)
    if q is not None:
        q.put_nowait(event)


async def _cleanup_scan(scan_id: str) -> None:
    """Remove per-scan state after a grace window for late SSE subscribers."""
    await asyncio.sleep(SSE_GRACE_SECONDS)
    _scan_queues.pop(scan_id, None)
    _scan_complete.pop(scan_id, None)
    _cancelled_scans.discard(scan_id)


async def _run_scan_background(scan_id: str, repo_url: str, db_session_factory):
    """Run the 6-node pipeline, streaming each agent step live via SSE."""
    if scan_id in _cancelled_scans:
        return

    async with db_session_factory() as db:
        try:
            result = await db.execute(select(Scan).where(Scan.id == scan_id))
            scan_row = result.scalar_one_or_none()
            if not scan_row:
                return

            if scan_id in _cancelled_scans:
                return

            scan_row.status = DBScanStatus.RUNNING
            await db.commit()

            state = ScanState(scan_id=scan_id, repo_url=repo_url, status=ScanStatus.RUNNING)

            # Wire live step queue — _wrap() in pipeline pushes steps here as each node finishes
            step_q: _queue.Queue = _queue.Queue()
            register_step_queue(scan_id, step_q)

            loop = asyncio.get_running_loop()
            pipeline_future = loop.run_in_executor(None, run_pipeline, state)

            # Drain queue while pipeline runs — this is what makes SSE feel live
            while not pipeline_future.done():
                while not step_q.empty():
                    step: AgentStep = step_q.get_nowait()
                    _emit(scan_id, {"type": "step", "data": step.model_dump()})
                await asyncio.sleep(0.2)

            # Final drain (catch any steps emitted in the last node)
            while not step_q.empty():
                step: AgentStep = step_q.get_nowait()
                _emit(scan_id, {"type": "step", "data": step.model_dump()})

            unregister_step_queue(scan_id)
            result_state: ScanState = await pipeline_future

            # Clean up cloned repo — all data is now in result_state
            if result_state.local_path:
                shutil.rmtree(result_state.local_path, ignore_errors=True)

            # Emit findings
            final_findings = (
                result_state.findings_with_context
                or result_state.triaged_findings
                or result_state.raw_findings
            )
            findings_data = [f.model_dump() for f in final_findings]
            _emit(scan_id, {"type": "findings", "data": findings_data})

            # Emit report
            report_data = result_state.report.model_dump() if result_state.report else None
            if report_data:
                _emit(scan_id, {"type": "report", "data": report_data})

            # Persist
            scan_row.status = DBScanStatus.COMPLETE if not result_state.error else DBScanStatus.FAILED
            scan_row.language = result_state.language
            scan_row.findings_raw = findings_data
            scan_row.finding_count = len(findings_data)
            scan_row.steps_raw = [s.model_dump() for s in result_state.steps]
            scan_row.report = report_data
            scan_row.report_markdown = result_state.report_markdown
            scan_row.error = result_state.error
            await db.commit()

            final_status = "complete" if not result_state.error else "failed"
            _emit(scan_id, {"type": "done", "data": {"status": final_status}})

        except Exception as e:
            unregister_step_queue(scan_id)
            _emit(scan_id, {"type": "error", "data": {"message": str(e)}})
            try:
                result = await db.execute(select(Scan).where(Scan.id == scan_id))
                row = result.scalar_one_or_none()
                if row:
                    row.status = DBScanStatus.FAILED
                    row.error = str(e)
                    await db.rollback()
                    await db.commit()
            except Exception:
                pass
        finally:
            if scan_id in _scan_complete:
                _scan_complete[scan_id].set()
            asyncio.create_task(_cleanup_scan(scan_id))


@router.post("/scans", response_model=ScanResponse)
@limiter.limit("10/minute")
async def create_scan(
    request: Request,
    body: ScanRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    scan_id = str(uuid.uuid4())
    scan_row = Scan(id=scan_id, repo_url=body.repo_url, status=DBScanStatus.PENDING)
    db.add(scan_row)
    await db.commit()

    _scan_queues[scan_id] = asyncio.Queue()
    _scan_complete[scan_id] = asyncio.Event()

    background_tasks.add_task(_run_scan_background, scan_id, body.repo_url, AsyncSessionLocal)

    return ScanResponse(
        scan_id=scan_id,
        status=ScanStatus.PENDING,
        repo_url=body.repo_url,
        created_at=datetime.now(timezone.utc).isoformat(),
    )


@router.delete("/scans/{scan_id}", status_code=200)
async def cancel_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")
    if row.status not in (DBScanStatus.PENDING, DBScanStatus.RUNNING):
        raise HTTPException(status_code=409, detail="Scan already finished")

    _cancelled_scans.add(scan_id)
    row.status = DBScanStatus.FAILED
    row.error = "Cancelled by user"
    await db.commit()

    _emit(scan_id, {"type": "done", "data": {"status": "cancelled"}})
    if scan_id in _scan_complete:
        _scan_complete[scan_id].set()
    asyncio.create_task(_cleanup_scan(scan_id))

    return {"scan_id": scan_id, "status": "cancelled"}


@router.get("/scans/{scan_id}/stream")
async def stream_scan(scan_id: str):
    """SSE — live agent steps, then findings + report + done."""

    async def event_generator() -> AsyncGenerator[str, None]:
        q = _scan_queues.get(scan_id)
        if q is None:
            yield f"data: {json.dumps({'type': 'error', 'data': {'message': 'Scan not found or already expired'}})}\n\n"
            return

        elapsed = 0.0
        while elapsed < SCAN_TIMEOUT:
            try:
                event = q.get_nowait()
                yield f"data: {json.dumps(event)}\n\n"
                if event.get("type") in ("done", "error"):
                    return
            except asyncio.QueueEmpty:
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


@router.get("/scans/{scan_id}/report.md")
async def get_report_markdown(scan_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")
    if not row.report_markdown:
        raise HTTPException(status_code=404, detail="Report not yet generated")

    repo_slug = row.repo_url.rstrip("/").split("/")[-1]
    filename = f"avra-report-{repo_slug}-{scan_id[:8]}.md"
    return Response(
        content=row.report_markdown,
        media_type="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/scans/{scan_id}/report.pdf")
async def get_report_pdf(scan_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")
    if not row.report:
        raise HTTPException(status_code=404, detail="Report not yet generated")

    from core.report_writer import to_pdf_bytes
    report = Report(**row.report)
    findings = [Finding(**f) for f in (row.findings_raw or [])]
    pdf_bytes = to_pdf_bytes(report, findings)

    repo_slug = row.repo_url.rstrip("/").split("/")[-1]
    filename = f"avra-report-{repo_slug}-{scan_id[:8]}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/scans")
async def list_scans(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Scan).order_by(Scan.created_at.desc()).limit(20))
    rows = result.scalars().all()
    return [
        {
            "scan_id": r.id,
            "repo_url": r.repo_url,
            "status": r.status.value,
            "language": r.language,
            "finding_count": r.finding_count or 0,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]
