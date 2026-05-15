import React, { useState, useEffect, useRef, useMemo, memo } from "react";

const API = import.meta.env.VITE_API_URL ?? "";

const SEVERITY_CONFIG = {
  critical: { color: "#ff2d55", bg: "rgba(255,45,85,0.12)", label: "CRITICAL", order: 0 },
  high:     { color: "#ff6b35", bg: "rgba(255,107,53,0.12)", label: "HIGH",     order: 1 },
  medium:   { color: "#ffd60a", bg: "rgba(255,214,10,0.10)", label: "MEDIUM",   order: 2 },
  low:      { color: "#30d158", bg: "rgba(48,209,88,0.10)",  label: "LOW",      order: 3 },
  info:     { color: "#8b949e", bg: "rgba(99,99,102,0.10)",  label: "INFO",     order: 4 },
};

const TOOL_CONFIG = {
  semgrep:       { color: "#bf5af2", label: "SEMGREP" },
  bandit:        { color: "#0a84ff", label: "BANDIT" },
  gitleaks:      { color: "#ff9f0a", label: "GITLEAKS" },
  "osv-scanner": { color: "#32d74b", label: "OSV" },
  slither:       { color: "#ff6b35", label: "SLITHER" },
};

const PIPELINE_AGENTS = ["Ingestion Agent","Scanner Agent","Triage Agent","Context Agent","RAG Agent","Report Writer"];

// ── Atoms ─────────────────────────────────────────────────────────────────────

function SeverityBadge({ severity }) {
  const cfg = SEVERITY_CONFIG[severity] || SEVERITY_CONFIG.info;
  return (
    <span style={{
      background: cfg.bg, color: cfg.color,
      border: `1px solid ${cfg.color}40`, borderRadius: "3px",
      padding: "2px 7px", fontSize: "10px", fontFamily: "monospace",
      fontWeight: 700, letterSpacing: "0.08em", whiteSpace: "nowrap",
    }}>{cfg.label}</span>
  );
}

function ToolBadge({ tool }) {
  const cfg = TOOL_CONFIG[tool] || { color: "#8b949e", label: tool?.toUpperCase() };
  return <span style={{ color: cfg.color, fontSize: "9px", fontFamily: "monospace", fontWeight: 700, letterSpacing: "0.1em" }}>{cfg.label}</span>;
}

function CopyButton({ text }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      onClick={() => { navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 2000); }}
      style={{
        background: copied ? "rgba(48,209,88,0.1)" : "rgba(255,255,255,0.04)",
        border: `1px solid ${copied ? "rgba(48,209,88,0.3)" : "#3d444d"}`,
        borderRadius: "3px", color: copied ? "#30d158" : "#8b949e",
        fontSize: "10px", fontFamily: "monospace", padding: "2px 8px",
        cursor: "pointer", transition: "all 0.2s",
      }}
    >{copied ? "✓ copied" : "copy"}</button>
  );
}

function FilePath({ path, lineStart, lineEnd }) {
  if (!path) return null;
  const parts = path.split(/[/\\]/);
  const file = parts[parts.length - 1];
  const dir = parts.slice(-2, -1)[0];
  return (
    <span style={{ fontFamily: "monospace", fontSize: "11px" }}>
      {dir && <span style={{ color: "#545d68" }}>{dir}/</span>}
      <span style={{ color: "#adbac7" }}>{file}</span>
      <span style={{ color: "#545d68" }}>:{lineStart}{lineEnd && lineEnd !== lineStart ? `–${lineEnd}` : ""}</span>
    </span>
  );
}

// ── Severity Donut ────────────────────────────────────────────────────────────

function SeverityDonut({ findings }) {
  const sevOrder = ["critical","high","medium","low","info"];
  const counts = Object.fromEntries(sevOrder.map(s => [s, findings.filter(f => f.severity === s).length]));
  const total = findings.length;
  if (total === 0) return null;

  const r = 38, cx = 56, cy = 56;
  const circ = 2 * Math.PI * r;

  let cumPct = 0;
  const segments = sevOrder.filter(s => counts[s] > 0).map(s => {
    const pct = counts[s] / total;
    const seg = { s, pct, cumPct };
    cumPct += pct;
    return seg;
  });

  return (
    <svg width={112} height={112} viewBox="0 0 112 112" style={{ flexShrink: 0 }}>
      <circle cx={cx} cy={cy} r={r} fill="none" stroke="#30363d" strokeWidth={12} />
      {segments.map(({ s, pct, cumPct: cum }) => (
        <circle key={s} cx={cx} cy={cy} r={r} fill="none"
          stroke={SEVERITY_CONFIG[s].color} strokeWidth={12}
          strokeDasharray={`${pct * circ} ${circ - pct * circ}`}
          transform={`rotate(${cum * 360 - 90}, ${cx}, ${cy})`}
        />
      ))}
      <circle cx={cx} cy={cy} r={30} fill="#161b22" />
      <text x={cx} y={cy - 5} textAnchor="middle" fill="#e6edf3" fontSize="18" fontWeight="600" fontFamily="monospace">{total}</text>
      <text x={cx} y={cy + 11} textAnchor="middle" fill="#545d68" fontSize="8" fontFamily="monospace" letterSpacing="0.08em">TOTAL</text>
    </svg>
  );
}

// ── Progress Bar ──────────────────────────────────────────────────────────────

function ScanProgress({ steps, isScanning }) {
  const doneAgents = useMemo(() =>
    new Set(steps.filter(s => s.status === "complete").map(s => s.agent)),
    [steps]
  );
  const pct = (doneAgents.size / PIPELINE_AGENTS.length) * 100;
  if (!isScanning && doneAgents.size === 0) return null;

  return (
    <div style={{ marginBottom: "12px" }}>
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "6px" }}>
        <span style={{ color: "#8b949e", fontSize: "10px", fontFamily: "monospace", letterSpacing: "0.08em" }}>PIPELINE</span>
        <span style={{ color: "#545d68", fontSize: "10px", fontFamily: "monospace" }}>{doneAgents.size}/{PIPELINE_AGENTS.length}</span>
      </div>
      <div style={{ height: "2px", background: "#30363d", borderRadius: "1px", marginBottom: "8px" }}>
        <div style={{
          height: "100%", width: `${pct}%`, borderRadius: "1px",
          background: pct >= 100 ? "#30d158" : "linear-gradient(90deg, #bf5af2, #ff2d55)",
          transition: "width 0.5s ease",
        }} />
      </div>
      <div style={{ display: "flex", gap: "4px", flexWrap: "wrap" }}>
        {PIPELINE_AGENTS.map(agent => {
          const short = agent.replace(" Agent","").replace(" Writer","");
          const done = doneAgents.has(agent);
          const running = !done && steps.some(s => s.agent === agent && s.status === "running");
          const errored = steps.some(s => s.agent === agent && s.status === "error");
          const c = errored ? "#ff2d55" : done ? "#30d158" : running ? "#ffd60a" : "#3d444d";
          return (
            <span key={agent} style={{
              fontSize: "9px", fontFamily: "monospace", padding: "2px 6px", borderRadius: "2px",
              background: `${c}15`, border: `1px solid ${c}35`,
              color: (done || running || errored) ? c : "#545d68",
              transition: "all 0.3s",
            }}>
              {errored ? "✗" : done ? "✓" : running ? "›" : "·"} {short}
            </span>
          );
        })}
      </div>
    </div>
  );
}

// ── Agent Log ─────────────────────────────────────────────────────────────────

function AgentLog({ steps }) {
  const endRef = useRef(null);
  const containerRef = useRef(null);
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    if (el.scrollHeight - el.scrollTop - el.clientHeight < 100)
      endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [steps]);

  return (
    <div ref={containerRef} style={{
      background: "#0d1117", border: "1px solid #30363d", borderRadius: "6px",
      padding: "12px 14px", fontFamily: "monospace", fontSize: "11px",
      height: "160px", overflowY: "auto", lineHeight: 1.7,
    }}>
      {steps.length === 0 && <span style={{ color: "#3d444d" }}>// awaiting scan...</span>}
      {steps.map((step, i) => {
        const c = step.status === "error" ? "#ff2d55" : step.status === "complete" ? "#30d158" : "#ffd60a";
        const icon = step.status === "error" ? "✗" : step.status === "complete" ? "✓" : "›";
        return (
          <div key={i} style={{ marginBottom: "1px" }}>
            <span style={{ color: "#3d444d" }}>[{step.timestamp?.slice(11,19)}] </span>
            <span style={{ color: "#bf5af2" }}>{step.agent} </span>
            <span style={{ color: c }}>{icon} </span>
            <span style={{ color: "#e6edf3" }}>{step.message}</span>
          </div>
        );
      })}
      <div ref={endRef} />
    </div>
  );
}

// ── Finding Side Panel ────────────────────────────────────────────────────────

function FindingPanel({ finding, onClose }) {
  useEffect(() => {
    const h = (e) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [onClose]);

  const sev = SEVERITY_CONFIG[finding.severity] || SEVERITY_CONFIG.info;

  return (
    <>
      <div onClick={onClose} style={{
        position: "fixed", inset: 0, background: "rgba(0,0,0,0.5)",
        zIndex: 200, animation: "fadeIn 0.15s ease",
      }} />
      <div style={{
        position: "fixed", top: 0, right: 0,
        width: "min(480px, 100vw)", height: "100vh",
        background: "#161b22", borderLeft: "1px solid #3d444d",
        zIndex: 201, overflowY: "auto", display: "flex", flexDirection: "column",
        animation: "slideIn 0.2s ease",
      }}>
        {/* Header */}
        <div style={{
          padding: "18px 20px 14px", borderBottom: "1px solid #30363d",
          position: "sticky", top: 0, background: "#161b22", zIndex: 1,
        }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
              <SeverityBadge severity={finding.severity} />
              <ToolBadge tool={finding.tool} />
            </div>
            <button onClick={onClose} style={{
              background: "none", border: "1px solid #3d444d", borderRadius: "4px",
              color: "#8b949e", fontSize: "13px", width: "26px", height: "26px",
              cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center",
            }}>✕</button>
          </div>
          <h2 style={{
            color: "#f0f6fc", fontSize: "14px", fontWeight: 600,
            lineHeight: 1.4, margin: "10px 0 6px", fontFamily: "monospace",
          }}>{finding.title}</h2>
          <FilePath path={finding.file_path} lineStart={finding.line_start} lineEnd={finding.line_end} />
        </div>

        {/* Body */}
        <div style={{ padding: "18px 20px", flex: 1, display: "flex", flexDirection: "column", gap: "18px" }}>

          <div>
            <div style={{ color: "#545d68", fontSize: "9px", letterSpacing: "0.1em", marginBottom: "5px" }}>RULE</div>
            <code style={{ color: "#bf5af2", fontSize: "11px" }}>{finding.rule_id}</code>
          </div>

          <div>
            <div style={{ color: "#545d68", fontSize: "9px", letterSpacing: "0.1em", marginBottom: "6px" }}>DESCRIPTION</div>
            <p style={{ color: "#adbac7", fontSize: "13px", lineHeight: 1.7, margin: 0 }}>{finding.description}</p>
          </div>

          {finding.code_snippet && (
            <div>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "6px" }}>
                <div style={{ color: "#545d68", fontSize: "9px", letterSpacing: "0.1em" }}>CODE</div>
                <CopyButton text={finding.code_snippet} />
              </div>
              <pre style={{
                background: "#0d1117", border: "1px solid #30363d", borderRadius: "5px",
                padding: "10px 12px", fontSize: "11px", color: "#e6edf3", margin: 0,
                overflowX: "auto", whiteSpace: "pre-wrap", wordBreak: "break-all", lineHeight: 1.6,
              }}>{finding.code_snippet.trim()}</pre>
            </div>
          )}

          {finding.llm_reasoning && (
            <div>
              <div style={{ color: "#545d68", fontSize: "9px", letterSpacing: "0.1em", marginBottom: "6px" }}>AI ANALYSIS</div>
              <div style={{
                background: "rgba(191,90,242,0.05)", border: "1px solid rgba(191,90,242,0.12)",
                borderRadius: "5px", padding: "10px 12px",
                color: "#adbac7", fontSize: "12px", lineHeight: 1.6, fontStyle: "italic",
              }}>{finding.llm_reasoning}</div>
            </div>
          )}

          <div style={{ display: "flex", gap: "20px", flexWrap: "wrap" }}>
            {finding.cwe && (
              <div>
                <div style={{ color: "#545d68", fontSize: "9px", letterSpacing: "0.1em", marginBottom: "4px" }}>CWE</div>
                <code style={{ color: "#8b949e", fontSize: "11px" }}>{finding.cwe}</code>
              </div>
            )}
            {finding.confidence != null && (
              <div>
                <div style={{ color: "#545d68", fontSize: "9px", letterSpacing: "0.1em", marginBottom: "4px" }}>CONFIDENCE</div>
                <span style={{ color: "#8b949e", fontSize: "11px", fontFamily: "monospace" }}>{Math.round(finding.confidence * 100)}%</span>
              </div>
            )}
            {finding.owasp_category && (
              <div>
                <div style={{ color: "#545d68", fontSize: "9px", letterSpacing: "0.1em", marginBottom: "4px" }}>OWASP</div>
                <span style={{ color: "#8b949e", fontSize: "11px", fontFamily: "monospace" }}>{finding.owasp_category}</span>
              </div>
            )}
          </div>

          {finding.cve_matches?.length > 0 && (
            <div>
              <div style={{ color: "#545d68", fontSize: "9px", letterSpacing: "0.1em", marginBottom: "8px" }}>CVE MATCHES</div>
              <div style={{ display: "flex", flexDirection: "column", gap: "5px" }}>
                {finding.cve_matches.slice(0, 5).map(cve => (
                  <div key={cve.cve_id} style={{
                    background: "rgba(255,107,53,0.05)", border: "1px solid rgba(255,107,53,0.12)",
                    borderRadius: "4px", padding: "7px 10px",
                    display: "flex", justifyContent: "space-between", alignItems: "center",
                  }}>
                    <span style={{ color: "#ff6b35", fontSize: "11px", fontFamily: "monospace", fontWeight: 700 }}>{cve.cve_id}</span>
                    {cve.cvss_score && <span style={{ color: "#8b949e", fontSize: "10px", fontFamily: "monospace" }}>CVSS {cve.cvss_score}</span>}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </>
  );
}

// ── Skeleton Rows ─────────────────────────────────────────────────────────────

function SkeletonRows({ count = 6 }) {
  return Array.from({ length: count }).map((_, i) => (
    <tr key={i} style={{ borderTop: "1px solid #30363d", opacity: 1 - i * 0.13 }}>
      {[28, 60, 160 + (i % 3) * 50, 90, 50, 40].map((w, j) => (
        <td key={j} style={{ padding: "10px 12px" }}>
          <div style={{ width: w, height: j === 0 ? 12 : j === 1 ? 18 : 13, background: "#30363d", borderRadius: "2px", animation: "pulse 1.5s ease-in-out infinite" }} />
        </td>
      ))}
    </tr>
  ));
}

// ── Findings Table ────────────────────────────────────────────────────────────

const FindingsTable = memo(function FindingsTable({ findings, severityFilter, setSeverityFilter, isScanning }) {
  const [selected, setSelected] = useState(null);
  const [sort, setSort] = useState({ col: "severity", dir: "asc" });
  const [search, setSearch] = useState("");

  const cycleSort = col => setSort(prev => prev.col === col ? { col, dir: prev.dir === "asc" ? "desc" : "asc" } : { col, dir: "asc" });

  const sorted = useMemo(() => {
    let f = severityFilter === "all" ? findings : findings.filter(x => x.severity === severityFilter);
    if (search.trim()) {
      const q = search.toLowerCase();
      f = f.filter(x => x.title?.toLowerCase().includes(q) || x.file_path?.toLowerCase().includes(q) || x.description?.toLowerCase().includes(q) || x.rule_id?.toLowerCase().includes(q));
    }
    return [...f].sort((a, b) => {
      let cmp = sort.col === "severity"
        ? (SEVERITY_CONFIG[a.severity]?.order ?? 5) - (SEVERITY_CONFIG[b.severity]?.order ?? 5)
        : sort.col === "title" ? a.title.localeCompare(b.title) : 0;
      return sort.dir === "desc" ? -cmp : cmp;
    });
  }, [findings, severityFilter, sort, search]);

  const SortIcon = ({ col }) => sort.col === col
    ? <span style={{ color: "#bf5af2", marginLeft: "4px" }}>{sort.dir === "asc" ? "↑" : "↓"}</span>
    : <span style={{ color: "#3d444d", marginLeft: "4px" }}>⇅</span>;

  const th = col => ({
    padding: "8px 12px", textAlign: "left", fontSize: "10px", fontWeight: 700,
    letterSpacing: "0.08em", cursor: col ? "pointer" : "default", userSelect: "none",
    whiteSpace: "nowrap", borderBottom: "1px solid #30363d",
    color: sort.col === col ? "#adbac7" : "#545d68",
  });

  return (
    <>
      {/* Controls */}
      <div style={{ display: "flex", gap: "8px", marginBottom: "10px", alignItems: "center", flexWrap: "wrap" }}>
        <div style={{
          flex: 1, minWidth: 160, background: "#161b22", border: "1px solid #30363d",
          borderRadius: "5px", display: "flex", alignItems: "center", padding: "0 10px", gap: "6px",
        }}>
          <span style={{ color: "#545d68", fontSize: "12px" }}>⌕</span>
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="search findings..."
            style={{ flex: 1, background: "none", border: "none", color: "#e6edf3", fontSize: "11px", fontFamily: "monospace", padding: "6px 0", outline: "none" }} />
          {search && <button onClick={() => setSearch("")} style={{ background: "none", border: "none", color: "#545d68", cursor: "pointer", fontSize: "12px", padding: 0 }}>✕</button>}
        </div>
        <div style={{ display: "flex", gap: "4px" }}>
          {["all","critical","high","medium","low"].map(s => {
            const active = severityFilter === s;
            const cfg = SEVERITY_CONFIG[s] || { color: "#8b949e" };
            const cnt = s === "all" ? findings.length : findings.filter(f => f.severity === s).length;
            return (
              <button key={s} onClick={() => setSeverityFilter(s)} style={{
                background: active ? (s === "all" ? "#30363d" : cfg.bg) : "none",
                border: `1px solid ${active ? (s === "all" ? "#545d68" : cfg.color + "50") : "#30363d"}`,
                borderRadius: "3px", color: active ? (s === "all" ? "#e6edf3" : cfg.color) : "#545d68",
                fontSize: "10px", fontFamily: "monospace", padding: "3px 7px", cursor: "pointer",
              }}>
                {s === "all" ? "ALL" : s.slice(0,3).toUpperCase()}
                <span style={{ marginLeft: "3px", opacity: 0.55 }}>{cnt}</span>
              </button>
            );
          })}
        </div>
        <span style={{ color: "#545d68", fontSize: "10px", fontFamily: "monospace", flexShrink: 0 }}>{sorted.length} shown</span>
      </div>

      {/* Table */}
      <div style={{ border: "1px solid #30363d", borderRadius: "8px", overflow: "hidden" }}>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ background: "#0d1117" }}>
              <th style={{ ...th(null), width: 40 }}>#</th>
              <th style={th("severity")} onClick={() => cycleSort("severity")}>SEV <SortIcon col="severity" /></th>
              <th style={th("title")} onClick={() => cycleSort("title")}>TITLE <SortIcon col="title" /></th>
              <th style={th(null)}>FILE</th>
              <th style={th(null)}>TOOL</th>
              <th style={th(null)}>CWE</th>
            </tr>
          </thead>
          <tbody>
            {isScanning && findings.length === 0
              ? <SkeletonRows />
              : sorted.map((f, i) => {
                  const isSel = selected?.id === f.id;
                  const sevColor = SEVERITY_CONFIG[f.severity]?.color || "#8b949e";
                  return (
                    <tr key={f.id} onClick={() => setSelected(isSel ? null : f)}
                      style={{
                        borderTop: "1px solid #30363d", cursor: "pointer", transition: "background 0.1s",
                        background: isSel ? "#1c2128" : "transparent",
                        borderLeft: `2px solid ${isSel ? sevColor : "transparent"}`,
                      }}
                      onMouseEnter={e => { if (!isSel) e.currentTarget.style.background = "#1a1f28"; }}
                      onMouseLeave={e => { if (!isSel) e.currentTarget.style.background = "transparent"; }}
                    >
                      <td style={{ padding: "9px 12px", color: "#3d444d", fontSize: "11px", fontFamily: "monospace" }}>{String(i+1).padStart(3,"0")}</td>
                      <td style={{ padding: "9px 12px" }}><SeverityBadge severity={f.severity} /></td>
                      <td style={{ padding: "9px 12px", color: "#e6edf3", fontSize: "12px", maxWidth: 300 }}>
                        <div style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{f.title}</div>
                      </td>
                      <td style={{ padding: "9px 12px" }}><FilePath path={f.file_path} lineStart={f.line_start} /></td>
                      <td style={{ padding: "9px 12px" }}><ToolBadge tool={f.tool} /></td>
                      <td style={{ padding: "9px 12px", color: "#545d68", fontSize: "10px", fontFamily: "monospace" }}>{f.cwe || "—"}</td>
                    </tr>
                  );
                })
            }
          </tbody>
        </table>
        {!isScanning && sorted.length === 0 && (
          <div style={{ padding: "28px", textAlign: "center", color: "#545d68", fontSize: "11px", fontFamily: "monospace" }}>
            {findings.length === 0 ? "No findings." : `No findings match "${search || severityFilter}".`}
          </div>
        )}
      </div>

      {selected && <FindingPanel finding={selected} onClose={() => setSelected(null)} />}
    </>
  );
});

// ── Severity Summary ──────────────────────────────────────────────────────────

function SeveritySummary({ findings }) {
  const sevOrder = ["critical","high","medium","low","info"];
  const counts = Object.fromEntries(sevOrder.map(s => [s, findings.filter(f => f.severity === s).length]));
  return (
    <div style={{
      background: "#161b22", border: "1px solid #30363d", borderRadius: "10px",
      padding: "18px 20px", display: "flex", alignItems: "center", gap: "24px",
      marginBottom: "20px", flexWrap: "wrap",
    }}>
      <SeverityDonut findings={findings} />
      <div>
        <div style={{ fontSize: "26px", fontWeight: 600, fontFamily: "monospace", marginBottom: "10px", color: counts.critical > 0 ? "#ff2d55" : "#ffd60a" }}>
          {findings.length} <span style={{ fontSize: "13px", color: "#8b949e", fontWeight: 400 }}>findings</span>
        </div>
        <div style={{ display: "flex", gap: "12px", flexWrap: "wrap" }}>
          {sevOrder.filter(s => counts[s] > 0).map(s => {
            const c = SEVERITY_CONFIG[s].color;
            return (
              <div key={s} style={{ display: "flex", alignItems: "center", gap: "5px" }}>
                <div style={{ width: 6, height: 6, borderRadius: "50%", background: c }} />
                <span style={{ color: c, fontWeight: 700, fontSize: "13px", fontFamily: "monospace" }}>{counts[s]}</span>
                <span style={{ color: "#545d68", fontSize: "11px" }}>{s}</span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

// ── Report Card ───────────────────────────────────────────────────────────────

function ReportCard({ report, scanId }) {
  return (
    <div style={{ background: "#161b22", border: "1px solid #3d444d", borderRadius: "10px", padding: "18px 20px", marginBottom: "20px" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "10px" }}>
        <span style={{ color: "#8b949e", fontSize: "10px", letterSpacing: "0.08em" }}>EXECUTIVE SUMMARY</span>
        <div style={{ display: "flex", gap: "6px" }}>
          <a href={`${API}/api/scans/${scanId}/report.md`} download style={{ background: "#30363d", border: "1px solid #3d444d", borderRadius: "4px", color: "#adbac7", fontSize: "10px", fontFamily: "monospace", padding: "3px 9px", textDecoration: "none" }}>↓ MD</a>
          <a href={`${API}/api/scans/${scanId}/report.pdf`} download style={{ background: "rgba(191,90,242,0.08)", border: "1px solid rgba(191,90,242,0.2)", borderRadius: "4px", color: "#bf5af2", fontSize: "10px", fontFamily: "monospace", padding: "3px 9px", textDecoration: "none" }}>↓ PDF</a>
        </div>
      </div>
      <p style={{ color: "#adbac7", fontSize: "13px", lineHeight: 1.7, margin: 0 }}>{report.executive_summary}</p>
    </div>
  );
}

// ── App ───────────────────────────────────────────────────────────────────────

export default function App() {
  const [repoUrl, setRepoUrl] = useState("");
  const [scanId, setScanId] = useState(null);
  const [status, setStatus] = useState("idle");
  const [steps, setSteps] = useState([]);
  const [findings, setFindings] = useState([]);
  const [report, setReport] = useState(null);
  const [severityFilter, setSeverityFilter] = useState("all");
  const [error, setError] = useState(null);
  const [recentScans, setRecentScans] = useState([]);
  const esRef = useRef(null);

  useEffect(() => {
    fetch(`${API}/api/scans`).then(r => r.json()).then(setRecentScans).catch(() => {});
  }, []);

  const reset = () => { setSteps([]); setFindings([]); setReport(null); setError(null); setSeverityFilter("all"); };

  const startScan = async () => {
    if (!repoUrl.trim()) return;
    setStatus("scanning"); reset();
    try {
      const res = await fetch(`${API}/api/scans`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ repo_url: repoUrl }) });
      if (!res.ok) { const e = await res.json().catch(() => ({})); throw new Error(e.detail || `HTTP ${res.status}`); }
      const data = await res.json();
      setScanId(data.scan_id);
      if (esRef.current) esRef.current.close();
      const es = new EventSource(`${API}/api/scans/${data.scan_id}/stream`);
      esRef.current = es;
      es.onmessage = (e) => {
        const ev = JSON.parse(e.data);
        if (ev.type === "step") setSteps(p => [...p, ev.data]);
        else if (ev.type === "findings") setFindings(ev.data);
        else if (ev.type === "report") setReport(ev.data);
        else if (ev.type === "done") { setStatus(ev.data.status === "complete" ? "complete" : "error"); es.close(); fetch(`${API}/api/scans`).then(r => r.json()).then(setRecentScans).catch(() => {}); }
        else if (ev.type === "error") { setError(ev.data.message); setStatus("error"); es.close(); }
      };
      es.onerror = () => es.close();
    } catch (err) { setError(err.message); setStatus("error"); }
  };

  const loadScan = async (scan) => {
    if (esRef.current) esRef.current.close();
    reset(); setRepoUrl(scan.repo_url); setScanId(scan.scan_id); setStatus("scanning");
    try {
      const data = await fetch(`${API}/api/scans/${scan.scan_id}`).then(r => r.json());
      setFindings(data.findings || []); setSteps(data.steps || []);
      if (data.report) setReport(data.report);
      setStatus(data.status === "complete" ? "complete" : data.status === "failed" ? "error" : "idle");
    } catch { setStatus("error"); setError("Failed to load scan."); }
  };

  const cancelScan = async () => {
    if (esRef.current) esRef.current.close();
    try { await fetch(`${API}/api/scans/${scanId}`, { method: "DELETE" }); } catch {}
    setStatus("error"); setError("Scan cancelled.");
  };

  return (
    <div style={{ minHeight: "100vh", background: "#0d1117", color: "#e6edf3", fontFamily: "'IBM Plex Mono', 'Courier New', monospace" }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@300;400;500;600;700&family=IBM+Plex+Sans:wght@300;400;500;600&display=swap');
        * { box-sizing: border-box; margin: 0; padding: 0; }
        ::-webkit-scrollbar { width: 4px; height: 4px; }
        ::-webkit-scrollbar-track { background: #161b22; }
        ::-webkit-scrollbar-thumb { background: #3d444d; border-radius: 2px; }
        input:focus { outline: none; }
        button:hover { opacity: 0.82; }
        a:hover { opacity: 0.78; }
        @keyframes fadeIn { from { opacity:0 } to { opacity:1 } }
        @keyframes slideIn { from { transform:translateX(100%) } to { transform:translateX(0) } }
        @keyframes pulse { 0%,100% { opacity:.35 } 50% { opacity:.7 } }
        @keyframes spin { to { transform:rotate(360deg) } }
      `}</style>

      {/* Header */}
      <header style={{ borderBottom: "1px solid #30363d", padding: "0 40px", height: "52px", display: "flex", alignItems: "center", justifyContent: "space-between", position: "sticky", top: 0, background: "#0d1117", zIndex: 100 }}>
        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
          <div style={{ width: 26, height: 26, background: "linear-gradient(135deg,#bf5af2,#ff2d55)", borderRadius: 6, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 11, fontWeight: 700, color: "#fff" }}>◈</div>
          <span style={{ fontWeight: 600, fontSize: "14px", letterSpacing: "0.05em" }}>AVRA</span>
          <span style={{ color: "#3d444d", fontSize: "11px" }}>/ Agentic Vulnerability Research Assistant</span>
        </div>
        <div style={{ display: "flex", gap: "6px" }}>
          <span style={{ background: "rgba(255,214,10,0.07)", color: "#ffd60a", fontSize: "9px", fontFamily: "monospace", padding: "2px 7px", borderRadius: "3px", border: "1px solid rgba(255,214,10,0.12)", letterSpacing: "0.08em" }}>BETA</span>
          <span style={{ background: "rgba(48,209,88,0.07)", color: "#30d158", fontSize: "9px", fontFamily: "monospace", padding: "2px 7px", borderRadius: "3px", border: "1px solid rgba(48,209,88,0.12)" }}>● ONLINE</span>
        </div>
      </header>

      <main style={{ maxWidth: "1100px", margin: "0 auto", padding: "40px" }}>

        {/* Input */}
        <div style={{ marginBottom: "36px" }}>
          <h1 style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: "30px", fontWeight: 300, letterSpacing: "-0.02em", marginBottom: "6px", color: "#f0f6fc" }}>Audit a codebase.</h1>
          <p style={{ color: "#8b949e", fontSize: "12px", marginBottom: "20px" }}>Feed a GitHub URL — AVRA runs static analysis and surfaces vulnerabilities.</p>

          <div style={{ display: "flex", gap: "8px" }}>
            <div style={{ flex: 1, background: "#161b22", border: `1px solid ${status === "scanning" ? "#3d444d" : "#30363d"}`, borderRadius: "8px", display: "flex", alignItems: "center", padding: "0 14px", gap: "10px", transition: "border-color 0.2s" }}>
              <span style={{ color: "#545d68", fontSize: "12px" }}>$</span>
              <input
                value={repoUrl} onChange={e => setRepoUrl(e.target.value)}
                onKeyDown={e => e.key === "Enter" && status !== "scanning" && startScan()}
                placeholder="https://github.com/owner/repo" disabled={status === "scanning"}
                style={{ flex: 1, background: "none", border: "none", color: "#e6edf3", fontSize: "13px", fontFamily: "monospace", padding: "13px 0" }}
              />
              {status === "scanning" && <div style={{ width: 12, height: 12, border: "2px solid #3d444d", borderTopColor: "#bf5af2", borderRadius: "50%", animation: "spin 0.8s linear infinite", flexShrink: 0 }} />}
            </div>
            {status === "scanning"
              ? <button onClick={cancelScan} style={{ background: "rgba(255,45,85,0.07)", border: "1px solid rgba(255,45,85,0.18)", borderRadius: "8px", color: "#ff2d55", fontSize: "12px", fontWeight: 600, padding: "0 20px", cursor: "pointer", whiteSpace: "nowrap" }}>✕ CANCEL</button>
              : <button onClick={startScan} disabled={!repoUrl.trim()} style={{ background: repoUrl.trim() ? "linear-gradient(135deg,#bf5af2,#ff2d55)" : "#111", border: "none", borderRadius: "8px", color: repoUrl.trim() ? "#fff" : "#545d68", fontSize: "13px", fontWeight: 600, padding: "0 24px", cursor: repoUrl.trim() ? "pointer" : "not-allowed", whiteSpace: "nowrap", transition: "all 0.2s" }}>RUN SCAN →</button>
            }
          </div>

          <div style={{ marginTop: "10px", display: "flex", gap: "8px", alignItems: "center", flexWrap: "wrap" }}>
            <span style={{ color: "#3d444d", fontSize: "10px" }}>try:</span>
            {["https://github.com/WebGoat/WebGoat","https://github.com/OWASP/NodeGoat"].map(url => (
              <button key={url} onClick={() => setRepoUrl(url)} style={{ background: "none", border: "1px solid #30363d", borderRadius: "3px", color: "#545d68", fontSize: "10px", fontFamily: "monospace", padding: "2px 8px", cursor: "pointer" }}
                onMouseEnter={e => e.currentTarget.style.borderColor = "#545d68"}
                onMouseLeave={e => e.currentTarget.style.borderColor = "#30363d"}
              >{url.replace("https://github.com/","")}</button>
            ))}
          </div>
        </div>

        {/* Results */}
        {status !== "idle" && (
          <div style={{ marginBottom: "40px" }}>
            {/* Pipeline card */}
            <div style={{ background: "#161b22", border: "1px solid #30363d", borderRadius: "10px", padding: "16px 20px", marginBottom: "16px" }}>
              <ScanProgress steps={steps} isScanning={status === "scanning"} />
              <AgentLog steps={steps} />
              {scanId && <div style={{ textAlign: "right", marginTop: "6px" }}><span style={{ color: "#30363d", fontSize: "9px", fontFamily: "monospace" }}>scan/{scanId.slice(0,8)}</span></div>}
            </div>

            {status === "error" && error && (
              <div style={{ background: "rgba(255,45,85,0.05)", border: "1px solid rgba(255,45,85,0.12)", borderRadius: "8px", padding: "11px 16px", color: "#ff2d55", fontSize: "12px", fontFamily: "monospace", marginBottom: "16px" }}>✗ {error}</div>
            )}

            {report && <ReportCard report={report} scanId={scanId} />}
            {findings.length > 0 && <SeveritySummary findings={findings} />}
            {(findings.length > 0 || status === "scanning") && (
              <FindingsTable findings={findings} severityFilter={severityFilter} setSeverityFilter={setSeverityFilter} isScanning={status === "scanning"} />
            )}
          </div>
        )}

        {/* Recent scans */}
        {recentScans.length > 0 && status === "idle" && (
          <div>
            <div style={{ color: "#545d68", fontSize: "10px", letterSpacing: "0.08em", marginBottom: "10px" }}>RECENT SCANS</div>
            {recentScans.slice(0,8).map(scan => (
              <div key={scan.scan_id} onClick={() => scan.status === "complete" && loadScan(scan)}
                style={{ background: "#161b22", border: "1px solid #30363d", borderRadius: "6px", padding: "11px 16px", marginBottom: "5px", display: "flex", justifyContent: "space-between", alignItems: "center", cursor: scan.status === "complete" ? "pointer" : "default", transition: "border-color 0.15s" }}
                onMouseEnter={e => { if (scan.status === "complete") e.currentTarget.style.borderColor = "#3d444d"; }}
                onMouseLeave={e => { e.currentTarget.style.borderColor = "#30363d"; }}
              >
                <div>
                  <div style={{ color: "#e6edf3", fontSize: "12px", fontFamily: "monospace" }}>{scan.repo_url.replace("https://github.com/","")}</div>
                  <div style={{ color: "#3d444d", fontSize: "10px", marginTop: "2px" }}>{scan.language && `${scan.language} · `}{scan.scan_id.slice(0,8)}</div>
                </div>
                <div style={{ display: "flex", gap: "10px", alignItems: "center" }}>
                  <span style={{ color: "#545d68", fontSize: "11px" }}>{scan.finding_count} findings</span>
                  <span style={{ fontSize: "9px", fontFamily: "monospace", padding: "2px 6px", borderRadius: "2px", color: scan.status === "complete" ? "#30d158" : scan.status === "failed" ? "#ff2d55" : "#ffd60a", background: scan.status === "complete" ? "rgba(48,209,88,0.07)" : scan.status === "failed" ? "rgba(255,45,85,0.07)" : "rgba(255,214,10,0.07)" }}>{scan.status}</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </main>

      <footer style={{ borderTop: "1px solid #30363d", padding: "16px 40px", display: "flex", justifyContent: "space-between", color: "#3d444d", fontSize: "10px", fontFamily: "monospace", marginTop: "60px" }}>
        <span>AVRA v0.7.0 // BETA // Semgrep + Bandit + Gitleaks + OSV + CWE + PDF</span>
        <span>LangGraph · FastAPI · React</span>
      </footer>
    </div>
  );
}
