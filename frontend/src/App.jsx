import { useState, useEffect, useRef } from "react";

const API = import.meta.env.VITE_API_URL || "http://localhost:8000";

const SEVERITY_CONFIG = {
  critical: { color: "#ff2d55", bg: "rgba(255,45,85,0.12)", label: "CRITICAL" },
  high:     { color: "#ff6b35", bg: "rgba(255,107,53,0.12)", label: "HIGH" },
  medium:   { color: "#ffd60a", bg: "rgba(255,214,10,0.10)", label: "MEDIUM" },
  low:      { color: "#30d158", bg: "rgba(48,209,88,0.10)",  label: "LOW" },
  info:     { color: "#636366", bg: "rgba(99,99,102,0.10)",  label: "INFO" },
};

const TOOL_CONFIG = {
  semgrep: { color: "#bf5af2", label: "SEMGREP" },
  bandit:  { color: "#0a84ff", label: "BANDIT" },
  slither: { color: "#ff9f0a", label: "SLITHER" },
};

function SeverityBadge({ severity }) {
  const cfg = SEVERITY_CONFIG[severity] || SEVERITY_CONFIG.info;
  return (
    <span style={{
      background: cfg.bg,
      color: cfg.color,
      border: `1px solid ${cfg.color}40`,
      borderRadius: "3px",
      padding: "2px 7px",
      fontSize: "10px",
      fontFamily: "monospace",
      fontWeight: 700,
      letterSpacing: "0.08em",
    }}>
      {cfg.label}
    </span>
  );
}

function ToolBadge({ tool }) {
  const cfg = TOOL_CONFIG[tool] || { color: "#636366", label: tool?.toUpperCase() };
  return (
    <span style={{
      color: cfg.color,
      fontSize: "9px",
      fontFamily: "monospace",
      fontWeight: 700,
      letterSpacing: "0.1em",
      opacity: 0.8,
    }}>
      {cfg.label}
    </span>
  );
}

function AgentLog({ steps }) {
  const endRef = useRef(null);
  useEffect(() => endRef.current?.scrollIntoView({ behavior: "smooth" }), [steps]);

  return (
    <div style={{
      background: "#0a0a0a",
      border: "1px solid #1c1c1e",
      borderRadius: "8px",
      padding: "16px",
      fontFamily: "monospace",
      fontSize: "12px",
      height: "220px",
      overflowY: "auto",
      lineHeight: 1.7,
    }}>
      {steps.length === 0 && (
        <span style={{ color: "#3a3a3c" }}>// Awaiting scan...</span>
      )}
      {steps.map((step, i) => {
        const color = step.status === "error" ? "#ff2d55"
          : step.status === "complete" ? "#30d158"
          : "#ffd60a";
        const icon = step.status === "error" ? "✗"
          : step.status === "complete" ? "✓"
          : "›";
        return (
          <div key={i} style={{ marginBottom: "2px" }}>
            <span style={{ color: "#3a3a3c" }}>[{step.timestamp?.slice(11, 19)}] </span>
            <span style={{ color: "#bf5af2" }}>{step.agent} </span>
            <span style={{ color }}>{icon} </span>
            <span style={{ color: "#e5e5ea" }}>{step.message}</span>
          </div>
        );
      })}
      <div ref={endRef} />
    </div>
  );
}

function FindingCard({ finding, index }) {
  const [expanded, setExpanded] = useState(false);
  const sev = SEVERITY_CONFIG[finding.severity] || SEVERITY_CONFIG.info;

  return (
    <div
      onClick={() => setExpanded(!expanded)}
      style={{
        background: "#111111",
        border: `1px solid ${expanded ? sev.color + "40" : "#1c1c1e"}`,
        borderLeft: `3px solid ${sev.color}`,
        borderRadius: "6px",
        padding: "12px 16px",
        cursor: "pointer",
        transition: "border-color 0.15s",
        marginBottom: "8px",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: expanded ? "10px" : 0 }}>
        <span style={{ color: "#3a3a3c", fontFamily: "monospace", fontSize: "11px", minWidth: "28px" }}>
          #{String(index + 1).padStart(3, "0")}
        </span>
        <SeverityBadge severity={finding.severity} />
        <ToolBadge tool={finding.tool} />
        <span style={{ color: "#e5e5ea", fontSize: "13px", fontWeight: 500, flex: 1 }}>
          {finding.title}
        </span>
        <span style={{ color: "#3a3a3c", fontSize: "11px", fontFamily: "monospace" }}>
          {expanded ? "▲" : "▼"}
        </span>
      </div>

      {expanded && (
        <div style={{ paddingLeft: "38px" }}>
          <div style={{
            color: "#636366",
            fontFamily: "monospace",
            fontSize: "11px",
            marginBottom: "8px",
          }}>
            {finding.file_path}:{finding.line_start}
          </div>

          <p style={{ color: "#aeaeb2", fontSize: "12px", margin: "0 0 10px 0", lineHeight: 1.6 }}>
            {finding.description}
          </p>

          {finding.code_snippet && (
            <pre style={{
              background: "#0a0a0a",
              border: "1px solid #1c1c1e",
              borderRadius: "4px",
              padding: "10px",
              fontSize: "11px",
              color: "#e5e5ea",
              margin: "0 0 8px 0",
              overflowX: "auto",
              whiteSpace: "pre-wrap",
              wordBreak: "break-all",
            }}>
              {finding.code_snippet.trim()}
            </pre>
          )}

          {finding.cwe && (
            <span style={{
              color: "#636366",
              fontSize: "10px",
              fontFamily: "monospace",
            }}>
              {finding.cwe}
            </span>
          )}
        </div>
      )}
    </div>
  );
}

function SeverityBar({ findings }) {
  const counts = {};
  ["critical", "high", "medium", "low", "info"].forEach(s => {
    counts[s] = findings.filter(f => f.severity === s).length;
  });
  const total = findings.length || 1;

  return (
    <div style={{ display: "flex", gap: "16px", flexWrap: "wrap" }}>
      {Object.entries(counts).map(([sev, count]) => {
        const cfg = SEVERITY_CONFIG[sev];
        return (
          <div key={sev} style={{ display: "flex", alignItems: "center", gap: "6px" }}>
            <div style={{
              width: "8px", height: "8px",
              borderRadius: "50%",
              background: cfg.color,
            }} />
            <span style={{ color: "#aeaeb2", fontSize: "12px" }}>
              <span style={{ color: cfg.color, fontWeight: 700 }}>{count}</span> {sev}
            </span>
          </div>
        );
      })}
    </div>
  );
}

function ReportCard({ report, scanId }) {
  const API = import.meta.env.VITE_API_URL || "http://localhost:8000";
  return (
    <div style={{
      background: "#111",
      border: "1px solid #2c2c2e",
      borderRadius: "8px",
      padding: "20px 24px",
      marginBottom: "24px",
    }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "12px" }}>
        <span style={{ color: "#636366", fontSize: "11px", letterSpacing: "0.08em" }}>
          EXECUTIVE SUMMARY
        </span>
        <div style={{ display: "flex", gap: "8px" }}>
          <a
            href={`${API}/api/scans/${scanId}/report.md`}
            download
            style={{
              background: "#1c1c1e",
              border: "1px solid #2c2c2e",
              borderRadius: "4px",
              color: "#aeaeb2",
              fontSize: "10px",
              fontFamily: "monospace",
              padding: "4px 10px",
              textDecoration: "none",
              letterSpacing: "0.06em",
            }}
          >
            ↓ MD
          </a>
          <a
            href={`${API}/api/scans/${scanId}/report.pdf`}
            download
            style={{
              background: "rgba(191,90,242,0.1)",
              border: "1px solid rgba(191,90,242,0.3)",
              borderRadius: "4px",
              color: "#bf5af2",
              fontSize: "10px",
              fontFamily: "monospace",
              padding: "4px 10px",
              textDecoration: "none",
              letterSpacing: "0.06em",
            }}
          >
            ↓ PDF
          </a>
        </div>
      </div>
      <p style={{ color: "#aeaeb2", fontSize: "13px", lineHeight: 1.7, margin: 0 }}>
        {report.executive_summary}
      </p>
    </div>
  );
}

export default function App() {
  const [repoUrl, setRepoUrl] = useState("");
  const [scanId, setScanId] = useState(null);
  const [status, setStatus] = useState("idle"); // idle | scanning | complete | error
  const [steps, setSteps] = useState([]);
  const [findings, setFindings] = useState([]);
  const [report, setReport] = useState(null);
  const [severityFilter, setSeverityFilter] = useState("all");
  const [error, setError] = useState(null);
  const [recentScans, setRecentScans] = useState([]);
  const esRef = useRef(null);

  useEffect(() => {
    fetch(`${API}/api/scans`)
      .then(r => r.json())
      .then(setRecentScans)
      .catch(() => {});
  }, []);

  const startScan = async () => {
    if (!repoUrl.trim()) return;
    setStatus("scanning");
    setSteps([]);
    setFindings([]);
    setReport(null);
    setError(null);

    try {
      const res = await fetch(`${API}/api/scans`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repo_url: repoUrl }),
      });
      const data = await res.json();
      setScanId(data.scan_id);

      // Open SSE stream
      if (esRef.current) esRef.current.close();
      const es = new EventSource(`${API}/api/scans/${data.scan_id}/stream`);
      esRef.current = es;

      es.onmessage = (e) => {
        const event = JSON.parse(e.data);
        if (event.type === "step") {
          setSteps(prev => [...prev, event.data]);
        } else if (event.type === "findings") {
          setFindings(event.data);
        } else if (event.type === "report") {
          setReport(event.data);
        } else if (event.type === "done") {
          setStatus(event.data.status === "complete" ? "complete" : "error");
          es.close();
        } else if (event.type === "error") {
          setError(event.data.message);
          setStatus("error");
          es.close();
        }
      };

      es.onerror = () => {
        es.close();
      };

    } catch (err) {
      setError(err.message);
      setStatus("error");
    }
  };

  const filteredFindings = severityFilter === "all"
    ? findings
    : findings.filter(f => f.severity === severityFilter);

  const criticalCount = findings.filter(f => f.severity === "critical").length;
  const highCount = findings.filter(f => f.severity === "high").length;

  return (
    <div style={{
      minHeight: "100vh",
      background: "#080808",
      color: "#e5e5ea",
      fontFamily: "'IBM Plex Mono', 'Courier New', monospace",
    }}>
      {/* Google Font */}
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@300;400;500;600;700&family=IBM+Plex+Sans:wght@300;400;500;600&display=swap');
        * { box-sizing: border-box; margin: 0; padding: 0; }
        ::-webkit-scrollbar { width: 4px; height: 4px; }
        ::-webkit-scrollbar-track { background: #111; }
        ::-webkit-scrollbar-thumb { background: #2c2c2e; border-radius: 2px; }
        input:focus { outline: none; }
        button:hover { opacity: 0.85; }
      `}</style>

      {/* Header */}
      <header style={{
        borderBottom: "1px solid #1c1c1e",
        padding: "0 40px",
        height: "56px",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        position: "sticky",
        top: 0,
        background: "#080808",
        zIndex: 100,
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
          <div style={{
            width: "28px", height: "28px",
            background: "linear-gradient(135deg, #bf5af2, #ff2d55)",
            borderRadius: "6px",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            fontSize: "12px",
            fontWeight: 700,
            color: "#fff",
          }}>◈</div>
          <span style={{ fontWeight: 600, fontSize: "15px", letterSpacing: "0.05em" }}>AVRA</span>
          <span style={{ color: "#3a3a3c", fontSize: "12px" }}>/ Agentic Vulnerability Research Assistant</span>
        </div>

        <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
          <span style={{
            background: "#1c1c1e",
            color: "#636366",
            fontSize: "10px",
            fontFamily: "monospace",
            padding: "3px 8px",
            borderRadius: "3px",
            letterSpacing: "0.08em",
          }}>DAY 4</span>
          <span style={{
            background: "rgba(48,209,88,0.1)",
            color: "#30d158",
            fontSize: "10px",
            fontFamily: "monospace",
            padding: "3px 8px",
            borderRadius: "3px",
            border: "1px solid rgba(48,209,88,0.2)",
          }}>● ONLINE</span>
        </div>
      </header>

      <main style={{ maxWidth: "1100px", margin: "0 auto", padding: "40px 40px" }}>

        {/* Hero input */}
        <div style={{ marginBottom: "40px" }}>
          <h1 style={{
            fontFamily: "'IBM Plex Sans', sans-serif",
            fontSize: "32px",
            fontWeight: 300,
            letterSpacing: "-0.02em",
            marginBottom: "6px",
            color: "#f2f2f7",
          }}>
            Audit a codebase.
          </h1>
          <p style={{ color: "#636366", fontSize: "13px", marginBottom: "24px" }}>
            Feed a GitHub URL — AVRA runs static analysis and surfaces vulnerabilities.
          </p>

          <div style={{ display: "flex", gap: "10px" }}>
            <div style={{
              flex: 1,
              background: "#111111",
              border: "1px solid #2c2c2e",
              borderRadius: "8px",
              display: "flex",
              alignItems: "center",
              padding: "0 14px",
              gap: "10px",
            }}>
              <span style={{ color: "#3a3a3c", fontSize: "13px" }}>$</span>
              <input
                value={repoUrl}
                onChange={e => setRepoUrl(e.target.value)}
                onKeyDown={e => e.key === "Enter" && startScan()}
                placeholder="https://github.com/owner/repo"
                disabled={status === "scanning"}
                style={{
                  flex: 1,
                  background: "none",
                  border: "none",
                  color: "#e5e5ea",
                  fontSize: "13px",
                  fontFamily: "monospace",
                  padding: "14px 0",
                }}
              />
            </div>
            <button
              onClick={startScan}
              disabled={status === "scanning" || !repoUrl.trim()}
              style={{
                background: status === "scanning"
                  ? "#2c2c2e"
                  : "linear-gradient(135deg, #bf5af2, #ff2d55)",
                border: "none",
                borderRadius: "8px",
                color: "#fff",
                fontSize: "13px",
                fontWeight: 600,
                padding: "0 24px",
                cursor: status === "scanning" ? "not-allowed" : "pointer",
                letterSpacing: "0.04em",
                whiteSpace: "nowrap",
                transition: "opacity 0.15s",
              }}
            >
              {status === "scanning" ? "SCANNING..." : "RUN SCAN →"}
            </button>
          </div>

          {/* Quick examples */}
          <div style={{ marginTop: "10px", display: "flex", gap: "8px", flexWrap: "wrap" }}>
            <span style={{ color: "#3a3a3c", fontSize: "11px" }}>try:</span>
            {[
              "https://github.com/WebGoat/WebGoat",
              "https://github.com/OWASP/NodeGoat",
            ].map(url => (
              <button
                key={url}
                onClick={() => setRepoUrl(url)}
                style={{
                  background: "none",
                  border: "1px solid #2c2c2e",
                  borderRadius: "3px",
                  color: "#636366",
                  fontSize: "10px",
                  fontFamily: "monospace",
                  padding: "2px 8px",
                  cursor: "pointer",
                }}
              >
                {url.replace("https://github.com/", "")}
              </button>
            ))}
          </div>
        </div>

        {/* Scan active area */}
        {(status !== "idle") && (
          <div style={{ marginBottom: "40px" }}>
            {/* Agent log */}
            <div style={{ marginBottom: "16px" }}>
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "8px" }}>
                <span style={{ color: "#636366", fontSize: "11px", letterSpacing: "0.08em" }}>
                  AGENT PIPELINE
                </span>
                {scanId && (
                  <span style={{ color: "#3a3a3c", fontSize: "10px", fontFamily: "monospace" }}>
                    {scanId.slice(0, 8)}
                  </span>
                )}
              </div>
              <AgentLog steps={steps} />
            </div>

            {/* Executive summary + download buttons */}
            {report && (
              <ReportCard report={report} scanId={scanId} />
            )}

            {/* Status summary */}
            {status === "complete" && findings.length > 0 && (
              <div style={{
                background: "#111",
                border: "1px solid #1c1c1e",
                borderRadius: "8px",
                padding: "16px 20px",
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                marginBottom: "24px",
              }}>
                <div>
                  <div style={{ fontSize: "22px", fontWeight: 600, color: criticalCount > 0 ? "#ff2d55" : "#ffd60a" }}>
                    {findings.length} findings
                  </div>
                  <SeverityBar findings={findings} />
                </div>
                {criticalCount > 0 && (
                  <div style={{
                    background: "rgba(255,45,85,0.08)",
                    border: "1px solid rgba(255,45,85,0.2)",
                    borderRadius: "6px",
                    padding: "10px 16px",
                    textAlign: "center",
                  }}>
                    <div style={{ color: "#ff2d55", fontSize: "20px", fontWeight: 700 }}>{criticalCount}</div>
                    <div style={{ color: "#ff2d55", fontSize: "10px", letterSpacing: "0.08em" }}>CRITICAL</div>
                  </div>
                )}
              </div>
            )}

            {status === "error" && (
              <div style={{
                background: "rgba(255,45,85,0.06)",
                border: "1px solid rgba(255,45,85,0.2)",
                borderRadius: "8px",
                padding: "14px 16px",
                color: "#ff2d55",
                fontSize: "12px",
                fontFamily: "monospace",
                marginBottom: "16px",
              }}>
                ✗ {error || "Scan failed — check agent log for details"}
              </div>
            )}

            {/* Findings */}
            {findings.length > 0 && (
              <div>
                <div style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  marginBottom: "12px",
                }}>
                  <span style={{ color: "#636366", fontSize: "11px", letterSpacing: "0.08em" }}>
                    FINDINGS — {filteredFindings.length} shown
                  </span>

                  {/* Severity filter */}
                  <div style={{ display: "flex", gap: "4px" }}>
                    {["all", "critical", "high", "medium", "low"].map(s => {
                      const active = severityFilter === s;
                      const cfg = SEVERITY_CONFIG[s] || { color: "#636366" };
                      return (
                        <button
                          key={s}
                          onClick={() => setSeverityFilter(s)}
                          style={{
                            background: active ? (s === "all" ? "#2c2c2e" : cfg.bg) : "none",
                            border: active ? `1px solid ${s === "all" ? "#3a3a3c" : cfg.color + "50"}` : "1px solid #1c1c1e",
                            borderRadius: "3px",
                            color: active ? (s === "all" ? "#e5e5ea" : cfg.color) : "#3a3a3c",
                            fontSize: "10px",
                            fontFamily: "monospace",
                            padding: "3px 8px",
                            cursor: "pointer",
                          }}
                        >
                          {s.toUpperCase()}
                        </button>
                      );
                    })}
                  </div>
                </div>

                {filteredFindings.map((finding, i) => (
                  <FindingCard key={finding.id} finding={finding} index={i} />
                ))}
              </div>
            )}
          </div>
        )}

        {/* Recent scans */}
        {recentScans.length > 0 && status === "idle" && (
          <div>
            <div style={{ color: "#636366", fontSize: "11px", letterSpacing: "0.08em", marginBottom: "12px" }}>
              RECENT SCANS
            </div>
            {recentScans.slice(0, 5).map(scan => (
              <div
                key={scan.scan_id}
                style={{
                  background: "#111",
                  border: "1px solid #1c1c1e",
                  borderRadius: "6px",
                  padding: "12px 16px",
                  marginBottom: "6px",
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                }}
              >
                <div>
                  <div style={{ color: "#e5e5ea", fontSize: "12px", fontFamily: "monospace" }}>
                    {scan.repo_url.replace("https://github.com/", "")}
                  </div>
                  <div style={{ color: "#3a3a3c", fontSize: "10px", marginTop: "2px" }}>
                    {scan.language} · {scan.scan_id.slice(0, 8)}
                  </div>
                </div>
                <div style={{ display: "flex", gap: "10px", alignItems: "center" }}>
                  <span style={{ color: "#636366", fontSize: "11px" }}>
                    {scan.finding_count} findings
                  </span>
                  <span style={{
                    fontSize: "10px",
                    color: scan.status === "complete" ? "#30d158" : scan.status === "failed" ? "#ff2d55" : "#ffd60a",
                    fontFamily: "monospace",
                  }}>
                    {scan.status}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </main>

      {/* Footer */}
      <footer style={{
        borderTop: "1px solid #1c1c1e",
        padding: "20px 40px",
        display: "flex",
        justifyContent: "space-between",
        color: "#3a3a3c",
        fontSize: "10px",
        fontFamily: "monospace",
        marginTop: "60px",
      }}>
        <span>AVRA v0.4.0 // Day 4 // Semgrep + Bandit + RAG + PDF</span>
        <span>LangGraph · FastAPI · React</span>
      </footer>
    </div>
  );
}
