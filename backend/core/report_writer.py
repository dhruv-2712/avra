"""
AVRA Report Writer
──────────────────
Converts a Report + findings into Markdown text and PDF bytes.
Used by report_agent (pipeline) and the /report.md + /report.pdf endpoints.
"""
import io
from datetime import datetime
from typing import List

from models.scan import Report, Finding, Severity

_SEV_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

_SEV_COLORS = {
    "critical": (255, 45,  85),
    "high":     (255, 107, 53),
    "medium":   (200, 160,  8),
    "low":      (48,  209, 88),
    "info":     (99,  99,  102),
}


def to_markdown(report: Report, findings: List[Finding]) -> str:
    lines = [
        "# AVRA Security Report",
        "",
        "| | |",
        "|---|---|",
        f"| **Repository** | {report.repo_url} |",
        f"| **Language** | {report.language or 'Unknown'} |",
        f"| **Frameworks** | {', '.join(report.frameworks) if report.frameworks else 'None detected'} |",
        f"| **Generated** | {report.generated_at} |",
        f"| **Scan ID** | `{report.scan_id}` |",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        report.executive_summary,
        "",
        "---",
        "",
        "## Severity Breakdown",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]

    for sev in ["critical", "high", "medium", "low", "info"]:
        lines.append(f"| {sev.capitalize()} | {report.by_severity.get(sev, 0)} |")

    lines += [
        f"| **Total** | **{report.total_findings}** |",
        "",
        "---",
        "",
        "## Top Findings",
        "",
    ]

    top = sorted(findings, key=lambda f: _SEV_ORDER.get(f.severity, 5))[:10]

    for i, f in enumerate(top, 1):
        lines += [
            f"### {i}. [{f.severity.value.upper()}] {f.title}",
            "",
            f"- **File:** `{f.file_path}:{f.line_start}`",
            f"- **Tool:** {f.tool.upper()}",
        ]
        if f.cwe:
            lines.append(f"- **CWE:** {f.cwe}")
        if f.attack_vector:
            lines.append(f"- **Attack Vector:** {f.attack_vector}")
        if f.is_reachable is not None:
            lines.append(f"- **Reachable:** {'Yes' if f.is_reachable else 'No'}")

        lines += ["", f.description, ""]

        if f.code_snippet:
            lines += ["```", f.code_snippet.strip(), "```", ""]

        if f.llm_reasoning:
            lines += [f"> **Analysis:** {f.llm_reasoning}", ""]

        if f.cve_matches:
            lines += ["**Related CVEs:**", ""]
            for cve in f.cve_matches[:3]:
                score = f" (CVSS {cve.cvss_score})" if cve.cvss_score else ""
                lines.append(f"- [{cve.cve_id}]{score} — {cve.description[:120]}...")
            lines.append("")

        lines += ["---", ""]

    return "\n".join(lines)


def to_pdf_bytes(report: Report, findings: List[Finding]) -> bytes:
    from fpdf import FPDF

    def _safe(text: str) -> str:
        return text.encode("latin-1", "replace").decode("latin-1")

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()

    # Header
    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(230, 230, 234)
    pdf.cell(0, 12, "AVRA Security Report", ln=True)

    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(99, 99, 102)
    pdf.cell(0, 6, _safe(report.repo_url), ln=True)
    pdf.cell(0, 6, f"Language: {report.language or 'Unknown'}  |  {report.generated_at[:19]}", ln=True)
    pdf.cell(0, 6, f"Scan ID: {report.scan_id}", ln=True)
    pdf.ln(3)
    pdf.set_draw_color(44, 44, 46)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(6)

    # Executive Summary
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(230, 230, 234)
    pdf.cell(0, 8, "Executive Summary", ln=True)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(174, 174, 178)
    pdf.multi_cell(0, 6, _safe(report.executive_summary))
    pdf.ln(4)

    # Severity table
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(230, 230, 234)
    pdf.cell(0, 8, "Severity Breakdown", ln=True)
    pdf.ln(2)

    col = 35
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_fill_color(28, 28, 30)
    pdf.set_text_color(99, 99, 102)
    pdf.cell(col, 7, "SEVERITY", border=1, fill=True)
    pdf.cell(col, 7, "COUNT", border=1, fill=True, ln=True)

    pdf.set_font("Helvetica", "", 10)
    for sev in ["critical", "high", "medium", "low", "info"]:
        r, g, b = _SEV_COLORS.get(sev, (99, 99, 102))
        pdf.set_text_color(r, g, b)
        pdf.cell(col, 7, sev.upper(), border=1)
        pdf.set_text_color(230, 230, 234)
        pdf.cell(col, 7, str(report.by_severity.get(sev, 0)), border=1, ln=True)

    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(230, 230, 234)
    pdf.cell(col, 7, "TOTAL", border=1)
    pdf.cell(col, 7, str(report.total_findings), border=1, ln=True)
    pdf.ln(6)

    # Top Findings
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(230, 230, 234)
    pdf.cell(0, 8, "Top Findings", ln=True)
    pdf.ln(2)

    top = sorted(findings, key=lambda f: _SEV_ORDER.get(f.severity, 5))[:10]

    for i, f in enumerate(top, 1):
        r, g, b = _SEV_COLORS.get(f.severity.value, (99, 99, 102))
        pdf.set_font("Helvetica", "B", 11)
        pdf.set_text_color(r, g, b)
        pdf.cell(0, 7, _safe(f"{i}. [{f.severity.value.upper()}] {f.title}"), ln=True)

        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(99, 99, 102)
        meta = f"{f.file_path}:{f.line_start}  |  {f.tool.upper()}"
        if f.cwe:
            meta += f"  |  {f.cwe}"
        pdf.cell(0, 5, _safe(meta), ln=True)

        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(174, 174, 178)
        pdf.multi_cell(0, 5, _safe(f.description[:300]))

        if f.llm_reasoning:
            pdf.set_font("Helvetica", "I", 9)
            pdf.set_text_color(99, 99, 102)
            pdf.multi_cell(0, 5, _safe(f"Analysis: {f.llm_reasoning[:200]}"))

        pdf.ln(4)

    # Footer
    pdf.set_y(-15)
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(58, 58, 60)
    pdf.cell(0, 5, f"Generated by AVRA  |  {datetime.utcnow().strftime('%Y-%m-%d')}", align="C")

    return bytes(pdf.output())
