# ◈ AVRA — Agentic Vulnerability Research Assistant

> Point it at a GitHub repo. Get a structured security report in minutes.

AVRA is a 6-node LangGraph pipeline that clones a codebase, runs static analysis, triages findings with an LLM, looks up matching CVEs, and generates a downloadable report — all streamed live to a React frontend.

---

## Architecture

```
                    ┌─────────────────────────────────────────┐
GitHub URL ──────▶  │            LangGraph Pipeline            │
                    │                                         │
                    │  ① Ingestion   clone + language detect  │
                    │       ↓                                 │
                    │  ② Scanner     Semgrep + Bandit         │
                    │       ↓                                 │
                    │  ③ Triage      Groq LLM false-pos filter│
                    │       ↓                                 │
                    │  ④ Context     reachability + snippets  │
                    │       ↓                                 │
                    │  ⑤ RAG         ChromaDB NVD CVE lookup  │
                    │       ↓                                 │
                    │  ⑥ Report      Groq LLM exec summary    │
                    └──────────────┬──────────────────────────┘
                                   │ SSE stream
                    ┌──────────────▼──────────────────────────┐
                    │  React Frontend                          │
                    │  • live agent step log                  │
                    │  • findings table (sort / filter)       │
                    │  • download .md + .pdf report           │
                    └──────────────┬──────────────────────────┘
                                   │
                    ┌──────────────▼──────────────────────────┐
                    │  FastAPI + SQLite                        │
                    │  • scan history  • findings  • steps    │
                    └─────────────────────────────────────────┘
```

## Stack

| Layer | Tech |
|---|---|
| Agent orchestration | LangGraph 0.2 |
| LLM inference | Groq (llama-3.3-70b-versatile) |
| Static analysis | Semgrep 1.x + Bandit |
| CVE corpus | ChromaDB + NVD dataset (RAG) |
| Backend | FastAPI + Uvicorn |
| Database | SQLite (aiosqlite) |
| Frontend | React 18 + Vite + SSE |
| PDF reports | fpdf2 |
| Deployment | Docker / Render |

---

## Quick Start

### Docker (recommended)

```bash
git clone https://github.com/dhruv-2712/avra
cd avra
cp .env.example .env        # add your GROQ_API_KEY
docker compose up --build
```

Open **http://localhost:5173**

### Manual

```bash
# Backend
cd backend
pip install -r requirements.txt
pip install semgrep
export GROQ_API_KEY=your_key
uvicorn main:app --reload

# Frontend (separate terminal)
cd frontend
npm install
npm run dev
```

---

## Deploy to Render

The repo ships a `render.yaml` for one-click deploy:

1. Fork this repo
2. Go to [dashboard.render.com](https://dashboard.render.com) → **New** → **Blueprint**
3. Connect your fork — Render reads `render.yaml` and creates the service
4. Set `GROQ_API_KEY` in the backend service's environment variables
5. Set `ALLOWED_ORIGINS` to your frontend's origin (e.g. `https://avra.onrender.com`)

> **Note:** Free tier Render spins down after inactivity. First scan after wake-up takes ~30s.  
> ChromaDB / CVE matching requires a separate Chroma instance — the pipeline degrades gracefully without it.

---

## API

Only **public GitHub HTTPS URLs** are accepted (`https://github.com/<owner>/<repo>`).

```
POST /api/scans                   start a scan
GET  /api/scans/{id}/stream       SSE: live agent steps → findings → report
GET  /api/scans/{id}              full scan result (findings + steps + report)
GET  /api/scans/{id}/report.md    download Markdown report
GET  /api/scans/{id}/report.pdf   download PDF report
GET  /api/scans                   list recent scans (last 20)
GET  /health                      health check
DELETE /api/scans/{id}            cancel a running scan
```

### Example

```bash
# Start a scan
curl -X POST https://avra-backend.onrender.com/api/scans \
  -H "Content-Type: application/json" \
  -d '{"repo_url":"https://github.com/we45/Vulnerable-Flask-App"}'

# Stream results
curl -N https://avra-backend.onrender.com/api/scans/{id}/stream
```

---

## Verified Against Real Repos

| Repo | Language | Findings | Notable |
|---|---|---|---|
| [ethicalhack3r/DVWA](https://github.com/ethicalhack3r/DVWA) | PHP | 62 | SQLi, XSS, command injection |
| [OWASP/NodeGoat](https://github.com/OWASP/NodeGoat) | JavaScript | 23 | prototype pollution, SSRF |
| [we45/Vulnerable-Flask-App](https://github.com/we45/Vulnerable-Flask-App) | Python | 15 | SQLi, SSTI, insecure deserialization |
| [tinchoabbate/damn-vulnerable-defi](https://github.com/tinchoabbate/damn-vulnerable-defi) | Solidity | 2 | reentrancy, proxy storage collision |

---

## Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `GROQ_API_KEY` | Yes | — | Groq API key for LLM triage + report |
| `DATABASE_URL` | No | `sqlite+aiosqlite:///./avra.db` | SQLAlchemy DB URL |
| `ALLOWED_ORIGINS` | No | `http://localhost:5173` | Comma-separated CORS origins |
| `REDIS_URL` | No | — | Redis URL for shared rate-limit storage (recommended in production) |
| `CHROMA_HOST` | No | `localhost` | ChromaDB host (RAG optional) |
| `CHROMA_PORT` | No | `8001` | ChromaDB port |
| `VITE_API_URL` | No | `http://localhost:8000` | Backend URL for frontend build |
| `SEMGREP_TIMEOUT` | No | `60` | Per-rule Semgrep timeout (seconds) |
| `BANDIT_TIMEOUT` | No | `90` | Bandit subprocess timeout (seconds) |
| `SCAN_TIMEOUT` | No | `600` | Total SSE stream timeout (seconds) |
| `MAX_REPO_MB` | No | `150` | Maximum repository size to scan (MB) |
| `SEMGREP_MAX_MEMORY` | No | `512` | Semgrep memory cap (MB) |
| `SSE_GRACE_SECONDS` | No | `60` | How long to keep scan state after stream ends |

---

## Security

- **URL allowlist** — only `https://github.com/<owner>/<repo>` is accepted; `file://`, `ssh://`, `git://`, and internal hostnames are rejected at request validation
- **Non-root container** — Docker image runs as user `avra` (UID 1000)
- **CORS lockdown** — wildcard origin removed; configure `ALLOWED_ORIGINS` for your deployment
- **Proxy-aware rate limiting** — reads `X-Forwarded-For`; optionally backed by Redis for multi-instance deployments
- **Repo size guard** — repos over `MAX_REPO_MB` are rejected before cloning
- **SSE state cleanup** — per-scan memory is evicted 60s after stream ends

---

## Build Log

- **Day 1** — scaffold, Docker, LangGraph pipeline, GitHub clone, Semgrep + Bandit, `Finding` schema, SSE, SQLite
- **Day 2** — LLM triage (Groq), context agent, exploitability reasoning, false-positive filtering
- **Day 3** — NVD CVE corpus → ChromaDB, RAG agent, 6-node graph, Semgrep multi-stage Docker build
- **Day 4** — per-step SSE streaming, Report Writer (JSON → Markdown → PDF), download endpoints
- **Day 5** — React frontend: live agent log, findings table, severity filter, scan history, MD + PDF download
- **Day 6** — integration tested against 4 real repos; fixed semgrep binary resolution, `--exclude` flags, timeout tuning
- **Day 7** — Render deploy, render.yaml, README
- **Day 8** — security hardening: SSRF protection, non-root Docker, CORS lockdown, SSE Queue + memory eviction, proxy-aware rate limiting, config extraction, React perf (memo + useMemo)
