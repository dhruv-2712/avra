"""
Context Agent
─────────────
Enriches each triaged finding with:
- Surrounding file lines (±10 lines, with >> markers on the flagged range)
- is_reachable flag: heuristic for whether the file sits in a web-facing path
"""
from pathlib import Path
from datetime import datetime
from typing import Optional

from models.scan import ScanState, AgentStep, Finding, ScanStatus

CONTEXT_LINES = 10

REACHABLE_PATTERNS = {
    "route", "view", "controller", "handler", "endpoint",
    "api", "server", "app", "wsgi", "asgi", "index",
}


def _step(agent: str, status: str, message: str, data=None) -> AgentStep:
    return AgentStep(
        agent=agent,
        status=status,
        message=message,
        timestamp=datetime.utcnow().isoformat(),
        data=data,
    )


def _read_context(local_path: str, file_path: str, line_start: int, line_end: Optional[int]) -> str:
    """Return annotated lines surrounding the finding."""
    try:
        full = Path(local_path) / file_path
        if not full.exists():
            return ""
        lines = full.read_text(encoding="utf-8", errors="ignore").splitlines()
        lo = max(0, line_start - CONTEXT_LINES - 1)
        hi = min(len(lines), (line_end or line_start) + CONTEXT_LINES)
        flagged = set(range(line_start, (line_end or line_start) + 1))
        out = []
        for i, line in enumerate(lines[lo:hi], start=lo + 1):
            marker = ">>" if i in flagged else "  "
            out.append(f"{marker} {i:4d} | {line}")
        return "\n".join(out)
    except Exception:
        return ""


def _is_reachable(file_path: str, entry_points: list[str]) -> bool:
    """Heuristic: true if the file is an entry point or sits in a web-facing path."""
    fp = file_path.lower()
    if file_path in entry_points:
        return True
    # Same parent directory as any entry point
    for ep in entry_points:
        if Path(file_path).parent == Path(ep).parent:
            return True
    # Filename / directory contains a web-facing keyword
    for part in Path(fp).parts:
        for pat in REACHABLE_PATTERNS:
            if pat in part:
                return True
    return False


def context_agent(state: ScanState) -> ScanState:
    """
    LangGraph node: Context Agent
    Input:  state with triaged_findings + local_path + entry_points
    Output: state with findings_with_context (file_context + is_reachable annotated)
    """
    agent_name = "Context Agent"

    if state.error:
        return state

    findings = state.triaged_findings
    if not findings:
        state.steps.append(_step(agent_name, "complete", "No findings to enrich — skipping"))
        state.findings_with_context = []
        return state

    if not state.local_path:
        state.steps.append(_step(agent_name, "complete", "No local path — skipping context enrichment"))
        state.findings_with_context = findings
        return state

    try:
        state.steps.append(_step(
            agent_name, "running",
            f"Enriching {len(findings)} findings with file context..."
        ))

        enriched: list[Finding] = []
        for f in findings:
            f.file_context = _read_context(state.local_path, f.file_path, f.line_start, f.line_end)
            f.is_reachable = _is_reachable(f.file_path, state.entry_points)
            enriched.append(f)

        reachable = sum(1 for f in enriched if f.is_reachable)
        state.findings_with_context = enriched
        state.steps.append(_step(
            agent_name, "complete",
            f"Context enrichment complete — {reachable}/{len(enriched)} findings in reachable paths",
            data={"enriched": len(enriched), "reachable": reachable},
        ))

    except Exception as e:
        state.steps.append(_step(
            agent_name, "complete",
            f"Context enrichment error ({e}) — using triaged findings without context",
        ))
        state.findings_with_context = state.triaged_findings

    return state
