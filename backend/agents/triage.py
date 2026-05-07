"""
Triage Agent
────────────
Batches findings (5 at a time) to Groq LLM for true/false-positive
classification, exploitability reasoning, and attack vector annotation.
Degrades gracefully if GROQ_API_KEY is unset or LLM fails.
"""
import os
import json
import time
from datetime import datetime

from models.scan import ScanState, AgentStep, Finding, ScanStatus

BATCH_SIZE = 5
MAX_TRIAGE = 50  # cap to avoid runaway latency on noisy repos

TRIAGE_SYSTEM = """You are a senior application security engineer performing code vulnerability triage.
You will receive a numbered list of static analysis findings and must assess each one.

Respond ONLY with a valid JSON array, one object per finding, in the same order:
[
  {
    "is_false_positive": boolean,
    "confidence": float (0.0-1.0),
    "reasoning": "concise 1-2 sentence explanation",
    "attack_vector": "how this could be exploited, or null if false positive"
  }
]"""


def _step(agent: str, status: str, message: str, data=None) -> AgentStep:
    return AgentStep(
        agent=agent,
        status=status,
        message=message,
        timestamp=datetime.utcnow().isoformat(),
        data=data,
    )


def _get_llm():
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        return None
    try:
        from langchain_groq import ChatGroq
        return ChatGroq(
            model="llama-3.3-70b-versatile",
            api_key=api_key,
            temperature=0.1,
            max_tokens=1024,
        )
    except Exception:
        return None


def _format_batch(findings: list[Finding]) -> str:
    parts = []
    for i, f in enumerate(findings, 1):
        parts.append(
            f"Finding {i}:\n"
            f"  Rule: {f.rule_id}\n"
            f"  File: {f.file_path}:{f.line_start}\n"
            f"  Severity: {f.severity.value}  Tool: {f.tool}\n"
            f"  Description: {f.description}\n"
            f"  Code: {f.code_snippet or '(none)'}"
        )
    return "\n\n".join(parts)


def _triage_batch(llm, findings: list[Finding], language: str) -> list[dict]:
    """Send one batch to Groq; returns list of result dicts (same length as findings)."""
    fallback = [
        {"is_false_positive": False, "confidence": 0.5,
         "reasoning": "Automated triage unavailable.", "attack_vector": None}
    ] * len(findings)

    prompt = f"Language: {language}\n\n{_format_batch(findings)}\n\nTriage each finding."
    try:
        from langchain_core.messages import HumanMessage, SystemMessage
        response = llm.invoke([
            SystemMessage(content=TRIAGE_SYSTEM),
            HumanMessage(content=prompt),
        ])
        text = response.content.strip()
        # Strip markdown fences if present
        if "```json" in text:
            text = text.split("```json")[1].split("```")[0].strip()
        elif "```" in text:
            text = text.split("```")[1].split("```")[0].strip()
        results = json.loads(text)
        if isinstance(results, list) and len(results) == len(findings):
            return results
    except Exception:
        pass
    return fallback


def triage_agent(state: ScanState) -> ScanState:
    """
    LangGraph node: Triage Agent
    Input:  state with raw_findings
    Output: state with triaged_findings (false positives removed, LLM reasoning annotated)
    """
    agent_name = "Triage Agent"

    if state.error:
        return state

    if not state.raw_findings:
        state.steps.append(_step(agent_name, "complete", "No findings to triage — skipping"))
        state.triaged_findings = []
        return state

    llm = _get_llm()
    if not llm:
        state.steps.append(_step(
            agent_name, "complete",
            f"GROQ_API_KEY not configured — {len(state.raw_findings)} findings passed through untriaged",
        ))
        state.triaged_findings = state.raw_findings
        return state

    try:
        candidates = state.raw_findings[:MAX_TRIAGE]
        overflow = state.raw_findings[MAX_TRIAGE:]

        state.steps.append(_step(
            agent_name, "running",
            f"Triaging {len(candidates)} findings via Groq "
            f"({'+ ' + str(len(overflow)) + ' passed through' if overflow else ''})..."
        ))

        triaged: list[Finding] = []
        false_positives = 0

        for batch_start in range(0, len(candidates), BATCH_SIZE):
            batch = candidates[batch_start: batch_start + BATCH_SIZE]
            results = _triage_batch(llm, batch, state.language or "Unknown")

            for finding, result in zip(batch, results):
                finding.is_false_positive = result.get("is_false_positive", False)
                finding.confidence = result.get("confidence", finding.confidence)
                finding.llm_reasoning = result.get("reasoning")
                finding.attack_vector = result.get("attack_vector")

                if not finding.is_false_positive:
                    triaged.append(finding)
                else:
                    false_positives += 1

            # Brief pause between batches to respect rate limits
            if batch_start + BATCH_SIZE < len(candidates):
                time.sleep(0.5)

            done = min(batch_start + BATCH_SIZE, len(candidates))
            if done % 20 == 0 or done == len(candidates):
                state.steps.append(_step(
                    agent_name, "running",
                    f"Triaged {done}/{len(candidates)}..."
                ))

        # Overflow findings pass through without LLM triage
        triaged.extend(overflow)

        state.triaged_findings = triaged
        state.steps.append(_step(
            agent_name, "complete",
            f"Triage complete — {len(triaged)} confirmed, {false_positives} false positives removed",
            data={
                "total_raw": len(state.raw_findings),
                "confirmed": len(triaged),
                "false_positives": false_positives,
            },
        ))

    except Exception as e:
        # Never fail the pipeline — pass findings through
        state.steps.append(_step(
            agent_name, "complete",
            f"Triage error ({e}) — all findings passed through unmodified",
        ))
        state.triaged_findings = state.raw_findings

    return state
