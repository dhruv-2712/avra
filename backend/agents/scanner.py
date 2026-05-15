"""
Scanner Agent
─────────────
Orchestrates static analysis tools (Semgrep, Bandit).
Normalises all tool output into a unified Finding schema.
"""
import logging
import subprocess
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from models.scan import ScanState, AgentStep, Finding, Severity, ScanStatus
import shutil
import tempfile
from core.config import SEMGREP_TIMEOUT, BANDIT_TIMEOUT, GITLEAKS_TIMEOUT, OSV_TIMEOUT, SEMGREP_MAX_MEMORY

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
        timestamp=datetime.now(timezone.utc).isoformat(),
        data=data,
    )


def _parse_semgrep_output(stdout: str, local_path: str) -> list[Finding]:
    try:
        data = json.loads(stdout)
    except (json.JSONDecodeError, ValueError):
        raise ValueError("semgrep output truncated or invalid")
    findings = []
    for r in data.get("results", []):
        severity_str = r.get("extra", {}).get("severity", "WARNING").upper()
        severity = SEVERITY_MAP_SEMGREP.get(severity_str, Severity.MEDIUM)
        try:
            fp = os.path.relpath(r.get("path", ""), local_path)
        except ValueError:
            fp = r.get("path", "")
        findings.append(Finding(
            rule_id=r.get("check_id", "unknown"),
            title=r.get("check_id", "Unknown Rule").split(".")[-1].replace("-", " ").title(),
            description=r.get("extra", {}).get("message", "No description"),
            file_path=fp,
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
    "test", "tests", "__tests__", "spec", "specs",
    "docs", "doc", "documentation", "examples", "fixtures", "mocks",
]

_LANGUAGE_CONFIGS: dict[str, list[str]] = {
    "JavaScript": ["p/javascript", "p/nodejs"],
    "TypeScript": ["p/typescript", "p/nodejs"],
    "Python":     ["p/python"],
    "Java":       ["p/java"],
    "Go":         ["p/golang"],
    "Ruby":       ["p/ruby"],
    "PHP":        ["p/php"],
    "C":          ["p/c"],
    "C++":        ["p/cpp"],
    "Kotlin":     ["p/kotlin"],
    "Scala":      ["p/scala"],
}

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
        + ["--json", "--no-git-ignore",
           f"--timeout={SEMGREP_TIMEOUT}",
           f"--max-memory={SEMGREP_MAX_MEMORY}"]
        + exclude_args
        + [local_path],
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
    )
    return result


def run_semgrep(local_path: str, language: str | None = None) -> tuple[list[Finding], str | None]:
    """Run Semgrep with language-specific rules, falling back to auto."""
    configs = _LANGUAGE_CONFIGS.get(language or "", ["auto"])
    try:
        result = _run_semgrep_cmd(configs, local_path, timeout=SEMGREP_TIMEOUT * 3)
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


def run_bandit(local_path: str) -> tuple[list[Finding], str | None]:
    """Run Bandit on Python code and parse JSON output."""
    findings = []
    try:
        result = subprocess.run(
            ["bandit", "-r", local_path, "-f", "json", "-q"],
            capture_output=True,
            text=True,
            timeout=BANDIT_TIMEOUT,
        )

        output = result.stdout.strip()
        if not output:
            return findings, None

        data = json.loads(output)
        results = data.get("results", [])

        for r in results:
            sev_str = r.get("issue_severity", "MEDIUM").upper()
            conf_str = r.get("issue_confidence", "MEDIUM").upper()
            severity = SEVERITY_MAP_BANDIT.get(sev_str, Severity.MEDIUM)
            confidence = CONFIDENCE_MAP.get(conf_str, 0.6)
            try:
                fp = os.path.relpath(r.get("filename", ""), local_path)
            except ValueError:
                fp = r.get("filename", "")

            finding = Finding(
                rule_id=r.get("test_id", "unknown"),
                title=r.get("test_name", "Unknown").replace("_", " ").title(),
                description=r.get("issue_text", "No description"),
                file_path=fp,
                line_start=r.get("line_number", 0),
                line_end=r.get("line_range", [None])[-1] if r.get("line_range") else None,
                code_snippet=r.get("code", ""),
                severity=severity,
                confidence=confidence,
                tool="bandit",
                cwe=r.get("issue_cwe", {}).get("id", None),
            )
            findings.append(finding)

        return findings, None

    except subprocess.TimeoutExpired:
        logging.warning("bandit timed out on %s", local_path)
        return [], "bandit timed out"
    except Exception as e:
        logging.warning("bandit failed: %s", e)
        return [], str(e)


def _extract_cwe(metadata: dict) -> str | None:
    """Extract CWE from Semgrep metadata."""
    cwe = metadata.get("cwe")
    if isinstance(cwe, list) and cwe:
        return str(cwe[0])
    if isinstance(cwe, str):
        return cwe
    return None


def run_gitleaks(local_path: str) -> tuple[list[Finding], str | None]:
    """Run gitleaks to detect hardcoded secrets."""
    if not shutil.which("gitleaks"):
        return [], "gitleaks not installed"
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            tmp_path = tmp.name
        result = subprocess.run(
            ["gitleaks", "detect", "--source", local_path,
             "--report-format", "json", "--no-git", "--no-banner",
             "--report-path", tmp_path],
            capture_output=True, text=True, timeout=GITLEAKS_TIMEOUT,
        )
        if result.returncode not in (0, 1):
            return [], f"gitleaks error: {result.stderr[:200]}"
        with open(tmp_path) as f:
            content = f.read().strip()
        if not content:
            return [], None
        data = json.loads(content)
        if not isinstance(data, list):
            return [], None
        findings = []
        for r in data:
            try:
                fp = os.path.relpath(r.get("File", ""), local_path)
            except ValueError:
                fp = r.get("File", "")
            findings.append(Finding(
                rule_id=f"gitleaks.{r.get('RuleID', 'unknown')}",
                title=r.get("Description", r.get("RuleID", "Secret Detected")).title(),
                description=f"Hardcoded secret detected ({r.get('RuleID', 'unknown')}). Remove and rotate this credential immediately.",
                file_path=fp,
                line_start=r.get("StartLine", 0),
                line_end=r.get("EndLine") or None,
                code_snippet="[REDACTED]",
                severity=Severity.HIGH,
                tool="gitleaks",
                cwe="CWE-798",
                confidence=0.85,
            ))
        return findings, None
    except subprocess.TimeoutExpired:
        return [], "gitleaks timed out"
    except Exception as e:
        return [], str(e)
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)


def _osv_severity(vuln: dict) -> Severity:
    sev = vuln.get("database_specific", {}).get("severity", "").upper()
    return {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
            "MODERATE": Severity.MEDIUM, "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW}.get(sev, Severity.MEDIUM)


def run_osv_scanner(local_path: str) -> tuple[list[Finding], str | None]:
    """Run osv-scanner to detect vulnerable dependencies."""
    if not shutil.which("osv-scanner"):
        return [], "osv-scanner not installed"
    try:
        result = subprocess.run(
            ["osv-scanner", "--format", "json", local_path],
            capture_output=True, text=True, timeout=OSV_TIMEOUT,
        )
        if result.returncode not in (0, 1):
            return [], f"osv-scanner error: {result.stderr[:200]}"
        output = result.stdout.strip()
        if not output:
            return [], None
        data = json.loads(output)
        findings = []
        for result_item in data.get("results", []):
            source_path = result_item.get("source", {}).get("path", "")
            try:
                fp = os.path.relpath(source_path, local_path)
            except ValueError:
                fp = source_path
            for pkg in result_item.get("packages", []):
                package = pkg.get("package", {})
                pkg_name = package.get("name", "unknown")
                pkg_version = package.get("version", "unknown")
                pkg_ecosystem = package.get("ecosystem", "")
                for vuln in pkg.get("vulnerabilities", []):
                    vuln_id = vuln.get("id", "unknown")
                    aliases = vuln.get("aliases", [])
                    cve = next((a for a in aliases if a.startswith("CVE-")), None)
                    summary = vuln.get("summary", f"Vulnerability in {pkg_name}")
                    findings.append(Finding(
                        rule_id=f"osv.{vuln_id}",
                        title=f"{pkg_name}@{pkg_version}: {summary[:80]}",
                        description=(
                            f"{pkg_ecosystem} package `{pkg_name}` version `{pkg_version}` "
                            f"has a known vulnerability ({cve or vuln_id}). {summary}"
                        ),
                        file_path=fp,
                        line_start=0,
                        severity=_osv_severity(vuln),
                        tool="osv-scanner",
                        cwe=cve,
                        confidence=0.95,
                    ))
        return findings, None
    except subprocess.TimeoutExpired:
        return [], "osv-scanner timed out"
    except Exception as e:
        return [], str(e)


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
        configs = _LANGUAGE_CONFIGS.get(state.language or "", ["auto"])
        state.steps.append(_step(agent_name, "running", f"Running Semgrep ({', '.join(configs)})..."))
        semgrep_findings, semgrep_err = run_semgrep(state.local_path, state.language)
        all_findings.extend(semgrep_findings)
        semgrep_status = "error" if semgrep_err and not semgrep_findings else "running"
        semgrep_msg = f"Semgrep complete — {len(semgrep_findings)} raw findings"
        if semgrep_err:
            semgrep_msg += f" [warning: {semgrep_err[:200]}]"
        state.steps.append(_step(agent_name, semgrep_status, semgrep_msg))

        # Bandit — Python only
        if state.language == "Python":
            state.steps.append(_step(agent_name, "running", "Running Bandit (Python AST analysis)..."))
            bandit_findings, bandit_err = run_bandit(state.local_path)
            all_findings.extend(bandit_findings)
            bandit_msg = f"Bandit complete — {len(bandit_findings)} raw findings"
            if bandit_err:
                bandit_msg += f" [warning: {bandit_err[:200]}]"
            state.steps.append(_step(agent_name, "running", bandit_msg))

        # Gitleaks — secrets detection (all languages)
        state.steps.append(_step(agent_name, "running", "Running Gitleaks (secrets detection)..."))
        gitleaks_findings, gitleaks_err = run_gitleaks(state.local_path)
        all_findings.extend(gitleaks_findings)
        gitleaks_msg = f"Gitleaks complete — {len(gitleaks_findings)} secrets found"
        if gitleaks_err:
            gitleaks_msg += f" [warning: {gitleaks_err[:200]}]"
        state.steps.append(_step(agent_name, "running", gitleaks_msg))

        # OSV-scanner — dependency vulnerabilities (all languages)
        state.steps.append(_step(agent_name, "running", "Running OSV-Scanner (dependency vulnerabilities)..."))
        osv_findings, osv_err = run_osv_scanner(state.local_path)
        all_findings.extend(osv_findings)
        osv_msg = f"OSV-Scanner complete — {len(osv_findings)} vulnerable dependencies found"
        if osv_err:
            osv_msg += f" [warning: {osv_err[:200]}]"
        state.steps.append(_step(agent_name, "running", osv_msg))

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
                    "gitleaks": len(gitleaks_findings),
                    "osv-scanner": len(osv_findings),
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
