# ◈ AVRA — Agentic Vulnerability Research Assistant

> AI pipeline that audits codebases, reasons about exploitability, and generates structured security reports.

**Phase 1** — Static analysis core with LangGraph pipeline, SSE streaming, and React frontend.

---

## Architecture

```
GitHub URL
    │
    ▼
┌─────────────────────────────────────────────────────┐
│                  LangGraph Pipeline                  │
│                                                     │
│  Ingestion Agent → Scanner Agent → [Phase 2: LLM]  │
│  (clone, detect)   (semgrep, bandit)               │
└─────────────────────────────────────────────────────┘
    │
    ▼ SSE stream
React Frontend (live agent steps + findings table)
    │
    ▼
FastAPI + SQLite (scan history + raw findings)
```

## Stack

| Layer | Tech |
|-------|------|
| Backend | FastAPI + Uvicorn |
| Agent Orchestration | LangGraph |
| LLM Inference | Groq (llama-3.3-70b) — Phase 2 |
| Static Analysis | Semgrep + Bandit (Slither — Phase 3) |
| Database | SQLite → Postgres |
| Frontend | React + Vite + SSE |
| Deployment | Docker + Render |

## Quick Start

```bash
# 1. Clone
git clone https://github.com/yourusername/avra
cd avra

# 2. Set env vars
cp .env.example .env
# Add your GROQ_API_KEY

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
POST /api/scans              — start a scan
GET  /api/scans/{id}         — get scan result
GET  /api/scans/{id}/stream  — SSE stream of agent steps
GET  /api/scans              — list recent scans
GET  /health                 — health check
```

## Phase Roadmap

- [x] **Day 1** — FastAPI scaffold, Docker, LangGraph pipeline, GitHub cloning, language detection, Semgrep + Bandit integration, normalized `Finding` schema, SSE streaming, SQLite persistence
- [ ] **Day 2** — LLM triage agent (Groq), context analysis, exploitability reasoning, false-positive filtering
- [ ] **Day 3** — CVE/NVD lookup, ChromaDB vector store, Slither (Solidity), React findings UI
- [ ] **Day 4** — PDF/SARIF report generation, GitHub Actions CI/CD gate, Render deploy

## Test Targets

```bash
# Vulnerable-by-design repos
https://github.com/WebGoat/WebGoat
https://github.com/OWASP/NodeGoat
https://github.com/ethicalhack3r/DVWA
```

---

*AVRA // Flagship Project // NIE Mysore 2026*
