# ◈ AVRA — Agentic Vulnerability Research Assistant

> AI pipeline that audits codebases, reasons about exploitability, and generates structured security reports.

**Current state** — 6-node LangGraph pipeline: static analysis → LLM triage → context reasoning → RAG CVE lookup → report generation, with SSE streaming and React frontend.

---

## Architecture

```
GitHub URL
    │
    ▼
┌──────────────────────────────────────────────────────────────────┐
│                        LangGraph Pipeline                        │
│                                                                  │
│  Ingestion → Scanner → Triage → Context → RAG → Reporting       │
│  (clone,     (semgrep, (Groq    (Groq     (NVD   (Groq           │
│   detect)     bandit)   LLM)     LLM)     CVE    LLM)            │
│                                           chroma)                │
└──────────────────────────────────────────────────────────────────┘
    │
    ▼ SSE stream
React Frontend (live agent steps + findings table)
    │
    ▼
FastAPI + SQLite (scan history, findings, steps, reports)
```

## Stack

| Layer | Tech |
|-------|------|
| Backend | FastAPI + Uvicorn |
| Agent Orchestration | LangGraph (6-node graph) |
| LLM Inference | Groq (llama-3.3-70b) |
| Static Analysis | Semgrep (osemgrep binary) + Bandit |
| RAG / CVE Corpus | ChromaDB + NVD NVD dataset |
| Database | SQLite (aiosqlite) |
| Frontend | React + Vite + SSE |
| Deployment | Docker Compose |

## Quick Start

```bash
# 1. Clone
git clone https://github.com/dhruv-2712/avra
cd avra

# 2. Set env vars
cp .env.example .env
# Fill in your GROQ_API_KEY

# 3. Docker (recommended)
docker-compose up --build

# OR run manually:
# Backend
cd backend
pip install -r requirements.txt
uvicorn main:app --reload

# Frontend
cd frontend
npm install
npm run dev
```

Open http://localhost:5173

## API

```
POST /api/scans                  — start a scan
GET  /api/scans/{id}             — get scan result (findings + steps + report)
GET  /api/scans/{id}/stream      — SSE stream of live agent steps
GET  /api/scans/{id}/report.md   — download Markdown report
GET  /api/scans/{id}/report.pdf  — download PDF report
GET  /api/scans                  — list recent scans
GET  /health                     — health check
```

## Phase Roadmap

- [x] **Day 1** — FastAPI scaffold, Docker, LangGraph pipeline, GitHub cloning, language detection, Semgrep + Bandit integration, normalized `Finding` schema, SSE streaming, SQLite persistence
- [x] **Day 2** — LLM triage agent (Groq llama-3.3-70b), context analysis agent, exploitability reasoning, false-positive filtering, structured report generation (5-node graph)
- [x] **Day 3** — NVD CVE corpus ingested into ChromaDB, RAG agent for CVE enrichment, 6-node graph, steps persistence (`steps_raw`), Semgrep binary via multi-stage Docker build, dep stabilization
- [x] **Day 4** — Live per-step SSE streaming (queue-drain pattern), Report Writer: JSON → Markdown → PDF (fpdf2), `/report.md` + `/report.pdf` download endpoints, executive summary card in UI
- [x] **Day 5** — Findings table (sortable by severity/title, inline expand with code + CVE badges), clickable scan history loads past results, severity filter, scan list auto-refresh

## Test Targets

```bash
# Vulnerable-by-design repos
https://github.com/WebGoat/WebGoat
https://github.com/OWASP/NodeGoat
https://github.com/ethicalhack3r/DVWA
```

---
