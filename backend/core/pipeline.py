"""
AVRA LangGraph Pipeline
───────────────────────
Defines the agent graph and execution order.
Phase 1: Ingestion → Scanner (Triage + Context coming in Phase 2)
"""
from langgraph.graph import StateGraph, END
from typing import TypedDict, List, Optional, Any

from models.scan import ScanState, ScanStatus, AgentStep, Finding
from agents.ingestion import ingestion_agent
from agents.scanner import scanner_agent


# LangGraph requires TypedDict for state
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
    steps: List[Any]
    error: Optional[str]
    status: str


def _to_graph_state(scan_state: ScanState) -> GraphState:
    return GraphState(
        scan_id=scan_state.scan_id,
        repo_url=scan_state.repo_url,
        local_path=scan_state.local_path,
        language=scan_state.language,
        frameworks=scan_state.frameworks,
        file_tree=scan_state.file_tree,
        entry_points=scan_state.entry_points,
        raw_findings=[f.model_dump() for f in scan_state.raw_findings],
        triaged_findings=[f.model_dump() for f in scan_state.triaged_findings],
        steps=[s.model_dump() for s in scan_state.steps],
        error=scan_state.error,
        status=scan_state.status.value,
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
        steps=[AgentStep(**s) for s in gs.get("steps", [])],
        error=gs.get("error"),
        status=ScanStatus(gs.get("status", "pending")),
    )


def _wrap_ingestion(state: GraphState) -> GraphState:
    scan_state = _from_graph_state(state)
    result = ingestion_agent(scan_state)
    return _to_graph_state(result)


def _wrap_scanner(state: GraphState) -> GraphState:
    scan_state = _from_graph_state(state)
    result = scanner_agent(scan_state)
    return _to_graph_state(result)


def _should_continue(state: GraphState) -> str:
    """Route: if error occurred, end early."""
    if state.get("error"):
        return "end"
    return "continue"


def build_pipeline():
    """Build and compile the AVRA LangGraph pipeline."""
    graph = StateGraph(GraphState)

    # Phase 1 nodes
    graph.add_node("ingestion", _wrap_ingestion)
    graph.add_node("scanner", _wrap_scanner)

    # Edges
    graph.set_entry_point("ingestion")

    graph.add_conditional_edges(
        "ingestion",
        _should_continue,
        {"continue": "scanner", "end": END},
    )

    graph.add_edge("scanner", END)

    return graph.compile()


# Singleton compiled pipeline
PIPELINE = build_pipeline()


def run_pipeline(scan_state: ScanState) -> ScanState:
    """Execute the full AVRA pipeline synchronously."""
    graph_state = _to_graph_state(scan_state)
    result = PIPELINE.invoke(graph_state)
    return _from_graph_state(result)
