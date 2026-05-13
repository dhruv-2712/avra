"""
Scanner Agent
─────────────
Orchestrates static analysis tools (Semgrep, Bandit).
Normalises all tool output into a unified Finding schema.
"""
import subprocess
import json
import os
from datetime import datetime
from pathlib import Path

from models.scan import ScanState, AgentStep, Finding, Severity, ScanStatus

SEVERITY_MAP_SEMGREP = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}

SEVERITY_MAP_BANDIT = {
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}

CONFIDENCE_MAP = {
    "HIGH": 0.9,
    "MEDIUM": 0.6,
    "LOW": 0.3,
}


def _step(agent: str, status: str, message: str, data=None) -> AgentStep:
    return AgentStep(
        agent=agent,
        status=status,
        message=message,
        timestamp=datetime.utcnow().isoformat(),
        data=data,
    )


def _parse_semgrep_output(stdout: str, local_path: str) -> list[Finding]:
    data = json.loads(stdout)
    findings = []
    for r in data.get("results", []):
        severity_str = r.get("extra", {}).get("severity", "WARNING").upper()
        severity = SEVERITY_MAP_SEMGREP.get(severity_str, Severity.MEDIUM)
        findings.append(Finding(
            rule_id=r.get("check_id", "unknown"),
            title=r.get("check_id", "Unknown Rule").split(".")[-1].replace("-", " ").title(),
            description=r.get("extra", {}).get("message", "No description"),
            file_path=os.path.relpath(r.get("path", ""), local_path),
            line_start=r.get("start", {}).get("line", 0),
            line_end=r.get("end", {}).get("line", None),
            code_snippet=r.get("extra", {}).get("lines", ""),
            severity=severity,
            tool="semgrep",
            cwe=_extract_cwe(r.get("extra", {}).get("metadata", {})),
        ))
    return findings


_EXCLUDE_DIRS = [
    "node_modules", "vendor", "build", "dist", ".next", ".nuxt",
    "venv", ".venv", "__pycache__", "coverage", "target", "out",
]

def _semgrep_binary() -> str:
    """Return the semgrep binary path, searching common install locations."""
    import shutil
    if path := shutil.which("semgrep"):
        return path
    candidates = [
        os.path.expanduser("~/.local/bin/semgrep"),
        "/usr/local/bin/semgrep",
        "/usr/bin/semgrep",
    ]
    # Windows: check Python user Scripts dir
    import site
    try:
        scripts = os.path.join(os.path.dirname(site.getusersitepackages()), "Scripts")
        candidates.insert(0, os.path.join(scripts, "semgrep.exe"))
    except Exception:
        pass
    for c in candidates:
        if os.path.isfile(c):
            return c
    return "semgrep"  # fallback — will raise FileNotFoundError if truly missing


def _run_semgrep_cmd(configs: list[str], local_path: str, timeout: int) -> subprocess.CompletedProcess:
    exclude_args = []
    for d in _EXCLUDE_DIRS:
        exclude_args += ["--exclude", d]
    env = os.environ.copy()
    result = subprocess.run(
        [_semgrep_binary()]
        + [f"--config={c}" for c in configs]
        + ["--json", "--no-git-ignore", "--timeout=60", "--max-memory=512"]
        + exclude_args
        + [local_path],
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
    )
    return result


def run_semgrep(local_path: str) -> tuple[list[Finding], str | None]:
    """Run Semgrep with --config=auto (community rules, no auth required)."""
    try:
        result = _run_semgrep_cmd(["auto"], local_path, timeout=300)
        stderr = (result.stderr or "").strip()
        print(f"[semgrep] exit={result.returncode} stdout_len={len(result.stdout or '')} stderr={stderr[:300]}", flush=True)

        if (result.stdout or "").strip():
            findings = _parse_semgrep_output(result.stdout, local_path)
            return findings, None

        return [], stderr or "semgrep produced no output"

    except subprocess.TimeoutExpired:
        return [], "semgrep timed out"
    except Exception as e:
        return [], str(e)


def run_bandit(local_path: str) -> list[Finding]:
    """Run Bandit on Python code and parse JSON output."""
    findings = []
    try:
        result = subprocess.run(
            ["bandit", "-r", local_path, "-f", "json", "-q"],
            capture_output=True,
            text=True,
            timeout=90,
        )

        output = result.stdout.strip()
        if not output:
            return findings

        data = json.loads(output)
        results = data.get("results", [])

        for r in results:
            sev_str = r.get("issue_severity", "MEDIUM").upper()
            conf_str = r.get("issue_confidence", "MEDIUM").upper()
            severity = SEVERITY_MAP_BANDIT.get(sev_str, Severity.MEDIUM)
            confidence = CONFIDENCE_MAP.get(conf_str, 0.6)

            finding = Finding(
                rule_id=r.get("test_id", "unknown"),
                title=r.get("test_name", "Unknown").replace("_", " ").title(),
                description=r.get("issue_text", "No description"),
                file_path=os.path.relpath(r.get("filename", ""), local_path),
                line_start=r.get("line_number", 0),
                line_end=r.get("line_range", [None])[-1] if r.get("line_range") else None,
                code_snippet=r.get("code", ""),
                severity=severity,
                confidence=confidence,
                tool="bandit",
                cwe=r.get("issue_cwe", {}).get("id", None),
            )
            findings.append(finding)

    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass

    return findings


def _extract_cwe(metadata: dict) -> str | None:
    """Extract CWE from Semgrep metadata."""
    cwe = metadata.get("cwe")
    if isinstance(cwe, list) and cwe:
        return str(cwe[0])
    if isinstance(cwe, str):
        return cwe
    return None


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """Remove near-duplicate findings by file + line + rule."""
    seen = set()
    unique = []
    for f in findings:
        key = (f.file_path, f.line_start, f.rule_id)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def scanner_agent(state: ScanState) -> ScanState:
    """
    LangGraph node: Scanner Agent
    Input:  state with local_path + language
    Output: state with raw_findings (normalized, deduplicated)
    """
    agent_name = "Scanner Agent"

    if state.error:
        return state

    if not state.local_path:
        state.error = "No local path — ingestion may have failed"
        state.status = ScanStatus.FAILED
        state.steps.append(_step(agent_name, "error", state.error))
        return state

    try:
        all_findings: list[Finding] = []
        bandit_findings: list[Finding] = []

        # Semgrep — works on most languages
        state.steps.append(_step(agent_name, "running", "Running Semgrep (--config=auto)..."))
        semgrep_findings, semgrep_err = run_semgrep(state.local_path)
        all_findings.extend(semgrep_findings)
        semgrep_status = "error" if semgrep_err and not semgrep_findings else "running"
        semgrep_msg = f"Semgrep complete — {len(semgrep_findings)} raw findings"
        if semgrep_err:
            semgrep_msg += f" [warning: {semgrep_err[:200]}]"
        state.steps.append(_step(agent_name, semgrep_status, semgrep_msg))

        # Bandit — Python only
        if state.language == "Python":
            state.steps.append(_step(agent_name, "running", "Running Bandit (Python AST analysis)..."))
            bandit_findings = run_bandit(state.local_path)
            all_findings.extend(bandit_findings)
            state.steps.append(_step(
                agent_name, "running",
                f"Bandit complete — {len(bandit_findings)} raw findings"
            ))

        # Deduplicate
        unique_findings = deduplicate_findings(all_findings)

        state.raw_findings = unique_findings
        state.steps.append(_step(
            agent_name, "complete",
            f"Scan complete — {len(unique_findings)} unique findings "
            f"({len(all_findings) - len(unique_findings)} duplicates removed)",
            data={
                "total": len(unique_findings),
                "by_tool": {
                    "semgrep": len(semgrep_findings),
                    "bandit": len(bandit_findings) if state.language == "Python" else 0,
                },
                "by_severity": {
                    sev.value: sum(1 for f in unique_findings if f.severity == sev)
                    for sev in Severity
                },
            }
        ))

    except Exception as e:
        state.error = str(e)
        state.status = ScanStatus.FAILED
        state.steps.append(_step(agent_name, "error", f"Scanner failed: {e}"))

    return state
