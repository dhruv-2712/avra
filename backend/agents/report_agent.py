"""
Report Agent
────────────
Computes severity stats, calls Groq for an executive summary,
and assembles the final Report object.
"""
import os
from datetime import datetime

from models.scan import ScanState, AgentStep, Finding, Severity, ScanStatus, Report

SEV_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def _step(agent: str, status: str, message: str, data=None) -> AgentStep:
    return AgentStep(
        agent=agent,
        status=status,
        message=message,
        timestamp=datetime.utcnow().isoformat(),
        data=data,
    )


def _executive_summary(llm, state: ScanState, stats: dict) -> str:
    top = state.findings_with_context or state.triaged_findings or state.raw_findings
    top_sorted = sorted(top, key=lambda f: SEV_ORDER.get(f.severity, 5))[:10]

    bullets = "\n".join(
        f"- [{f.severity.value.upper()}] {f.title} — {f.file_path}:{f.line_start}"
        + (f"\n  Reasoning: {f.llm_reasoning}" if f.llm_reasoning else "")
        for f in top_sorted
    )

    prompt = (
        f"Write a 3-4 sentence professional executive summary for this security scan report.\n\n"
        f"Repository: {state.repo_url}\n"
        f"Language: {state.language}  "
        f"Frameworks: {', '.join(state.frameworks) if state.frameworks else 'None detected'}\n\n"
        f"Findings: {stats['total']} confirmed  "
        f"({stats['critical']} critical, {stats['high']} high, "
        f"{stats['medium']} medium, {stats['low']} low)\n\n"
        f"Top findings:\n{bullets}\n\n"
        f"Be specific about the most serious issues. Write for a technical audience."
    )

    try:
        from langchain_core.messages import HumanMessage
        response = llm.invoke([HumanMessage(content=prompt)])
        return response.content.strip()
    except Exception:
        return (
            f"Security scan of {state.repo_url} identified {stats['total']} confirmed findings "
            f"({stats['critical']} critical, {stats['high']} high, "
            f"{stats['medium']} medium, {stats['low']} low). "
            f"Immediate review of all critical and high severity findings is recommended."
        )


def report_agent(state: ScanState) -> ScanState:
    """
    LangGraph node: Report Agent
    Input:  state with findings_with_context (falls back to triaged/raw)
    Output: state.report populated; state.status set to COMPLETE
    """
    agent_name = "Report Agent"

    if state.error:
        return state

    try:
        state.steps.append(_step(agent_name, "running", "Compiling security report..."))

        findings = state.findings_with_context or state.triaged_findings or state.raw_findings

        by_severity = {sev.value: 0 for sev in Severity}
        for f in findings:
            by_severity[f.severity.value] += 1

        stats = {
            "total": len(findings),
            "critical": by_severity.get("critical", 0),
            "high": by_severity.get("high", 0),
            "medium": by_severity.get("medium", 0),
            "low": by_severity.get("low", 0),
        }

        # LLM executive summary
        executive_summary: str
        api_key = os.getenv("GROQ_API_KEY")
        if api_key and findings:
            try:
                from langchain_groq import ChatGroq
                llm = ChatGroq(
                    model="llama-3.3-70b-versatile",
                    api_key=api_key,
                    temperature=0.2,
                    max_tokens=400,
                )
                state.steps.append(_step(agent_name, "running", "Generating executive summary..."))
                executive_summary = _executive_summary(llm, state, stats)
            except Exception as e:
                executive_summary = (
                    f"Scan complete. {stats['total']} findings identified "
                    f"({stats['critical']} critical, {stats['high']} high). "
                    f"LLM summary unavailable: {e}"
                )
        else:
            executive_summary = (
                f"Security scan of {state.repo_url} identified {stats['total']} confirmed findings "
                f"({stats['critical']} critical, {stats['high']} high, "
                f"{stats['medium']} medium, {stats['low']} low). "
                f"Manual review recommended."
            ) if findings else "No findings identified in this repository."

        top_findings = sorted(findings, key=lambda f: SEV_ORDER.get(f.severity, 5))[:10]

        state.report = Report(
            scan_id=state.scan_id,
            repo_url=state.repo_url,
            language=state.language,
            frameworks=state.frameworks,
            executive_summary=executive_summary,
            total_findings=stats["total"],
            by_severity=by_severity,
            top_findings=top_findings,
            generated_at=datetime.utcnow().isoformat(),
        )

        # JSON → Markdown (PDF rendered on-demand by the API)
        from core.report_writer import to_markdown
        state.report_markdown = to_markdown(state.report, findings)

        state.status = ScanStatus.COMPLETE
        state.steps.append(_step(
            agent_name, "complete",
            f"Report ready — {stats['total']} findings "
            f"({stats['critical']} critical / {stats['high']} high / "
            f"{stats['medium']} medium / {stats['low']} low)",
            data=stats,
        ))

    except Exception as e:
        state.error = str(e)
        state.status = ScanStatus.FAILED
        state.steps.append(_step(agent_name, "error", f"Report generation failed: {e}"))

    return state
