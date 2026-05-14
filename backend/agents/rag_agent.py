"""
RAG Agent
─────────
Enriches findings with CWE descriptions and OWASP Top-10 context
using a static mapping — no external vector DB required.
"""
from datetime import datetime

from models.scan import ScanState, AgentStep

_CWE_CONTEXT: dict[str, dict] = {
    "CWE-22":   {"name": "Path Traversal",                         "owasp": "A01:2021 – Broken Access Control"},
    "CWE-78":   {"name": "OS Command Injection",                   "owasp": "A03:2021 – Injection"},
    "CWE-79":   {"name": "Cross-Site Scripting (XSS)",             "owasp": "A03:2021 – Injection"},
    "CWE-89":   {"name": "SQL Injection",                          "owasp": "A03:2021 – Injection"},
    "CWE-94":   {"name": "Code Injection",                         "owasp": "A03:2021 – Injection"},
    "CWE-116":  {"name": "Improper Encoding / Escaping",           "owasp": "A03:2021 – Injection"},
    "CWE-200":  {"name": "Exposure of Sensitive Information",      "owasp": "A02:2021 – Cryptographic Failures"},
    "CWE-295":  {"name": "Improper Certificate Validation",        "owasp": "A02:2021 – Cryptographic Failures"},
    "CWE-312":  {"name": "Cleartext Storage of Sensitive Info",    "owasp": "A02:2021 – Cryptographic Failures"},
    "CWE-326":  {"name": "Inadequate Encryption Strength",         "owasp": "A02:2021 – Cryptographic Failures"},
    "CWE-327":  {"name": "Broken Cryptographic Algorithm",         "owasp": "A02:2021 – Cryptographic Failures"},
    "CWE-330":  {"name": "Insufficient Randomness",                "owasp": "A02:2021 – Cryptographic Failures"},
    "CWE-352":  {"name": "Cross-Site Request Forgery (CSRF)",      "owasp": "A01:2021 – Broken Access Control"},
    "CWE-400":  {"name": "Uncontrolled Resource Consumption",      "owasp": "A04:2021 – Insecure Design"},
    "CWE-434":  {"name": "Unrestricted File Upload",               "owasp": "A04:2021 – Insecure Design"},
    "CWE-502":  {"name": "Deserialization of Untrusted Data",      "owasp": "A08:2021 – Software and Data Integrity Failures"},
    "CWE-601":  {"name": "Open Redirect",                          "owasp": "A01:2021 – Broken Access Control"},
    "CWE-611":  {"name": "XML External Entity (XXE)",              "owasp": "A05:2021 – Security Misconfiguration"},
    "CWE-732":  {"name": "Incorrect Permission Assignment",        "owasp": "A01:2021 – Broken Access Control"},
    "CWE-798":  {"name": "Hardcoded Credentials",                  "owasp": "A07:2021 – Identification and Authentication Failures"},
    "CWE-915":  {"name": "Mass Assignment",                        "owasp": "A04:2021 – Insecure Design"},
    "CWE-918":  {"name": "Server-Side Request Forgery (SSRF)",     "owasp": "A10:2021 – SSRF"},
    "CWE-1021": {"name": "Clickjacking",                           "owasp": "A05:2021 – Security Misconfiguration"},
}


def _step(agent: str, status: str, message: str, data=None) -> AgentStep:
    return AgentStep(
        agent=agent,
        status=status,
        message=message,
        timestamp=datetime.utcnow().isoformat(),
        data=data,
    )


def rag_agent(state: ScanState) -> ScanState:
    """
    LangGraph node: RAG Agent
    Input:  state with findings_with_context
    Output: findings annotated with owasp_category + cwe_description
    """
    agent_name = "RAG Agent"

    if state.error:
        return state

    findings = state.findings_with_context
    if not findings:
        state.steps.append(_step(agent_name, "complete", "No findings to enrich — skipping"))
        return state

    state.steps.append(_step(
        agent_name, "running",
        f"Enriching {len(findings)} findings with CWE/OWASP context..."
    ))

    enriched = 0
    for finding in findings:
        cwe = (finding.cwe or "").strip()
        if not cwe:
            continue
        # Normalise e.g. "CWE-79: ..." → "CWE-79"
        cwe_id = cwe.split(":")[0].strip().upper()
        ctx = _CWE_CONTEXT.get(cwe_id)
        if ctx:
            if not finding.owasp_category:
                finding.owasp_category = ctx["owasp"]
            if not finding.description or len(finding.description) < 20:
                finding.description = ctx["name"]
            enriched += 1

    state.findings_with_context = findings
    state.steps.append(_step(
        agent_name, "complete",
        f"CWE enrichment complete — {enriched}/{len(findings)} findings annotated",
        data={"enriched": enriched, "total": len(findings)},
    ))

    return state
