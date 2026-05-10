"""
AVRA LangGraph Pipeline
───────────────────────
6-node graph: Ingestion → Scanner → Triage → Context → RAG → Report
Each edge is conditional: error short-circuits to END.
"""
from langgraph.graph import StateGraph, END
from typing import TypedDict, List, Optional, Any

from models.scan import ScanState, ScanStatus, AgentStep, Finding, Report
from agents.ingestion import ingestion_agent
from agents.scanner import scanner_agent
from agents.triage import triage_agent
from agents.context_agent import context_agent
from agents.rag_agent import rag_agent
from agents.report_agent import report_agent


class GraphState(TypedDict):
    scan_id: str
    repo_url: str
    local_path: Optional[str]
    language: Optional[str]
    frameworks: List[str]
    file_tree: List[str]
    entry_points: List[str]
    raw_findings: List[Any]
    triaged_findings: List[Any]
    findings_with_context: List[Any]
    report: Optional[Any]
    steps: List[Any]
    error: Optional[str]
    status: str


def _to_graph_state(s: ScanState) -> GraphState:
    return GraphState(
        scan_id=s.scan_id,
        repo_url=s.repo_url,
        local_path=s.local_path,
        language=s.language,
        frameworks=s.frameworks,
        file_tree=s.file_tree,
        entry_points=s.entry_points,
        raw_findings=[f.model_dump() for f in s.raw_findings],
        triaged_findings=[f.model_dump() for f in s.triaged_findings],
        findings_with_context=[f.model_dump() for f in s.findings_with_context],
        report=s.report.model_dump() if s.report else None,
        steps=[step.model_dump() for step in s.steps],
        error=s.error,
        status=s.status.value,
    )


def _from_graph_state(gs: GraphState) -> ScanState:
    return ScanState(
        scan_id=gs["scan_id"],
        repo_url=gs["repo_url"],
        local_path=gs.get("local_path"),
        language=gs.get("language"),
        frameworks=gs.get("frameworks", []),
        file_tree=gs.get("file_tree", []),
        entry_points=gs.get("entry_points", []),
        raw_findings=[Finding(**f) for f in gs.get("raw_findings", [])],
        triaged_findings=[Finding(**f) for f in gs.get("triaged_findings", [])],
        findings_with_context=[Finding(**f) for f in gs.get("findings_with_context", [])],
        report=Report(**gs["report"]) if gs.get("report") else None,
        steps=[AgentStep(**s) for s in gs.get("steps", [])],
        error=gs.get("error"),
        status=ScanStatus(gs.get("status", "pending")),
    )


def _wrap(agent_fn):
    """Adapter: converts GraphState ↔ ScanState so agents stay Pydantic-native."""
    def node(state: GraphState) -> GraphState:
        return _to_graph_state(agent_fn(_from_graph_state(state)))
    return node


def _should_continue(state: GraphState) -> str:
    return "end" if state.get("error") else "continue"


def build_pipeline():
    graph = StateGraph(GraphState)

    graph.add_node("ingestion",  _wrap(ingestion_agent))
    graph.add_node("scanner",    _wrap(scanner_agent))
    graph.add_node("triage",     _wrap(triage_agent))
    graph.add_node("context",    _wrap(context_agent))
    graph.add_node("rag",        _wrap(rag_agent))
    graph.add_node("reporting",  _wrap(report_agent))

    graph.set_entry_point("ingestion")

    for src, dst in [
        ("ingestion", "scanner"),
        ("scanner",   "triage"),
        ("triage",    "context"),
        ("context",   "rag"),
        ("rag",       "reporting"),
    ]:
        graph.add_conditional_edges(
            src, _should_continue, {"continue": dst, "end": END}
        )

    graph.add_edge("reporting", END)

    return graph.compile()


PIPELINE = build_pipeline()


def run_pipeline(scan_state: ScanState) -> ScanState:
    """Execute the full 6-node AVRA pipeline synchronously."""
    result = PIPELINE.invoke(_to_graph_state(scan_state))
    return _from_graph_state(result)
