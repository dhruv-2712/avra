"""
RAG Agent
─────────
Queries ChromaDB for each confirmed finding to retrieve the top-3
most semantically similar CVEs from the NVD corpus.
Annotates finding.cve_matches so the Report agent can cite real CVE IDs.
Degrades gracefully if ChromaDB is unavailable or corpus is empty.
"""
from datetime import datetime

from models.scan import ScanState, AgentStep, CVEMatch


def _step(agent: str, status: str, message: str, data=None) -> AgentStep:
    return AgentStep(
        agent=agent,
        status=status,
        message=message,
        timestamp=datetime.utcnow().isoformat(),
        data=data,
    )


def _build_query(finding) -> str:
    """Combine rule + description + snippet into a single embedding query."""
    parts = [finding.rule_id, finding.description]
    if finding.code_snippet:
        parts.append(finding.code_snippet[:300])
    if finding.cwe:
        parts.append(finding.cwe)
    return " ".join(parts)


def _parse_matches(results: dict, n: int = 3) -> list[CVEMatch]:
    """Convert ChromaDB query results into CVEMatch objects."""
    matches = []
    ids = results.get("ids", [[]])[0]
    docs = results.get("documents", [[]])[0]
    metas = results.get("metadatas", [[]])[0]
    distances = results.get("distances", [[]])[0]

    for i in range(min(n, len(ids))):
        meta = metas[i] if i < len(metas) else {}
        distance = distances[i] if i < len(distances) else 1.0
        # Cosine space: distance 0=identical, 1=orthogonal — convert to similarity
        similarity = round(max(0.0, 1.0 - distance), 4)

        cwe_raw = meta.get("cwe_ids", "")
        cwe_ids = [c for c in cwe_raw.split(",") if c] if cwe_raw else []

        matches.append(CVEMatch(
            cve_id=ids[i],
            description=meta.get("description", docs[i] if i < len(docs) else "")[:500],
            cvss_score=meta.get("cvss_score") or None,
            cvss_severity=meta.get("cvss_severity") or None,
            cwe_ids=cwe_ids,
            published=meta.get("published") or None,
            similarity=similarity,
        ))

    return matches


def rag_agent(state: ScanState) -> ScanState:
    """
    LangGraph node: RAG Agent
    Input:  state with findings_with_context
    Output: findings annotated with cve_matches from NVD corpus
    """
    agent_name = "RAG Agent"

    if state.error:
        return state

    findings = state.findings_with_context
    if not findings:
        state.steps.append(_step(agent_name, "complete", "No findings to enrich — skipping"))
        return state

    # Check ChromaDB availability
    try:
        from core.rag import get_collection, is_available
        if not is_available():
            raise RuntimeError("ChromaDB not reachable")
        collection = get_collection()
        if collection.count() == 0:
            state.steps.append(_step(
                agent_name, "complete",
                "ChromaDB corpus is empty — run scripts/ingest_nvd.py first",
            ))
            return state
    except Exception as e:
        state.steps.append(_step(
            agent_name, "complete",
            f"ChromaDB unavailable ({e}) — skipping CVE matching",
        ))
        return state

    try:
        state.steps.append(_step(
            agent_name, "running",
            f"Querying NVD corpus for {len(findings)} findings..."
        ))

        matched = 0
        for finding in findings:
            query = _build_query(finding)
            try:
                results = collection.query(
                    query_texts=[query],
                    n_results=3,
                    include=["documents", "metadatas", "distances"],
                )
                cve_matches = _parse_matches(results)
                # Only attach matches above a minimum similarity threshold
                finding.cve_matches = [m for m in cve_matches if m.similarity >= 0.3]
                if finding.cve_matches:
                    matched += 1
            except Exception:
                finding.cve_matches = []

        state.findings_with_context = findings
        state.steps.append(_step(
            agent_name, "complete",
            f"CVE matching complete — {matched}/{len(findings)} findings matched to NVD entries",
            data={
                "findings_queried": len(findings),
                "findings_matched": matched,
                "corpus_size": collection.count(),
            },
        ))

    except Exception as e:
        state.steps.append(_step(
            agent_name, "complete",
            f"RAG error ({e}) — continuing without CVE matches",
        ))

    return state
