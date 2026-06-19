import { useState, useEffect, useRef } from "react";

// ─────────────────────────────────────────────────────────────
// 🧠 LESSON: This URL points to YOUR Python backend running
// locally on port 8000. When you deploy to a server later,
// change this to your server's URL (e.g. https://api.cybershield.app)
// ─────────────────────────────────────────────────────────────
const BACKEND_URL = "https://your-render-app.onrender.com";

// ─────────────────────────────────────────────────────────────
// Helper: color based on threat level
// ─────────────────────────────────────────────────────────────
const COLORS = {
  HIGH:   { main: "#ff4444", bg: "rgba(255,68,68,0.08)",   border: "rgba(255,68,68,0.3)"   },
  MEDIUM: { main: "#ffaa00", bg: "rgba(255,170,0,0.08)",  border: "rgba(255,170,0,0.3)"   },
  CLEAN:  { main: "#00ff88", bg: "rgba(0,255,136,0.08)",  border: "rgba(0,255,136,0.3)"   },
  NONE:   { main: "#00d4ff", bg: "rgba(0,212,255,0.05)",  border: "rgba(0,212,255,0.2)"   },
};

const verdictColor = (v = "") => {
  const u = v.toUpperCase();
  if (["MALICIOUS","PHISHING","MALWARE","SPAM"].some(x => u.includes(x))) return "#ff4444";
  if (["SUSPICIOUS","SUSPICIOUS"].some(x => u.includes(x))) return "#ffaa00";
  return "#00ff88";
};

export default function CyberShield() {
  const [target,      setTarget]      = useState("");
  const [scanType,    setScanType]    = useState("url");
  const [result,      setResult]      = useState(null);
  const [loading,     setLoading]     = useState(false);
  const [history,     setHistory]     = useState([]);
  const [activeTab,   setActiveTab]   = useState("scanner");
  const [error,       setError]       = useState("");
  const [backendOk,   setBackendOk]   = useState(null);   // null=checking, true/false
  const [log,         setLog]         = useState([]);      // live scan log lines
  const logRef = useRef(null);

  // ─────────────────────────────────────────────────────────
  // 🧠 LESSON: useEffect runs code when component mounts.
  // Here we check if the Python backend is running.
  // It runs once (empty [] dependency array = run once).
  // ─────────────────────────────────────────────────────────
  useEffect(() => {
    checkBackend();
  }, []);

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [log]);

  const addLog = (msg, type = "info") => {
    const icons = { info: "›", success: "✓", error: "✗", warn: "⚠" };
    setLog(prev => [...prev.slice(-40), {
      text: msg, type, icon: icons[type],
      time: new Date().toLocaleTimeString()
    }]);
  };

  const checkBackend = async () => {
    try {
      const r = await fetch(`${BACKEND_URL}/health`, { signal: AbortSignal.timeout(4000) });
      const d = await r.json();
      setBackendOk(d.status === "online");
    } catch {
      setBackendOk(false);
    }
  };

  // ─────────────────────────────────────────────────────────
  // 🧠 LESSON: This is the REAL scan function.
  // It calls YOUR Python backend (not VirusTotal directly).
  // Backend handles the real API calls and returns clean data.
  // ─────────────────────────────────────────────────────────
  const runScan = async () => {
    if (!target.trim()) { setError("Enter a URL or IP address."); return; }
    if (!backendOk)     { setError("Backend is offline. Follow setup steps below."); return; }

    setError(""); setResult(null); setLoading(true); setLog([]);

    addLog(`Starting ${scanType.toUpperCase()} scan for: ${target}`);
    addLog("Connecting to CyberShield backend...");

    try {
      addLog("Querying VirusTotal threat intelligence...", "info");
      if (scanType === "ip") addLog("Querying AbuseIPDB reputation database...", "info");
      addLog("Fetching geolocation & WHOIS data...", "info");

      // 🧠 LESSON: fetch() sends HTTP POST to your Python backend
      // JSON.stringify converts JS object → JSON string for the request body
      const response = await fetch(`${BACKEND_URL}/scan`, {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ target: target.trim(), scan_type: scanType }),
        signal:  AbortSignal.timeout(30000), // 30 second timeout
      });

      if (!response.ok) {
        const err = await response.json();
        throw new Error(err.detail || "Scan failed");
      }

      // 🧠 LESSON: response.json() parses the JSON response
      // from your Python backend into a JavaScript object
      const data = await response.json();

      addLog(`Scan complete — ${Object.keys(data.engines || {}).length} engines checked`, "success");
      addLog(`Threat level: ${data.threat_level}`,
             data.threat_level === "CLEAN" ? "success" : "error");

      setResult(data);
      setHistory(prev => [{
        target, scanType,
        threatLevel: data.threat_level,
        riskScore:   data.risk_score,
        time: new Date().toLocaleTimeString()
      }, ...prev.slice(0, 19)]);

    } catch (err) {
      addLog(`Error: ${err.message}`, "error");
      setError(err.message.includes("fetch") ?
        "Cannot reach backend. Is it running? See setup instructions." :
        err.message);
    } finally {
      setLoading(false);
    }
  };

  const C = COLORS[result?.threat_level || "NONE"];

  return (
    <div style={{
      minHeight: "100vh",
      background: "#070b15",
      fontFamily: "'Share Tech Mono', 'Courier New', monospace",
      color: "#c8d6e5",
    }}>

      {/* ── HEADER ── */}
      <div style={{
        background: "linear-gradient(90deg,#070b15,#0d1f3c 50%,#070b15)",
        borderBottom: "1px solid #0d2040",
        padding: "14px 24px",
        display: "flex", alignItems: "center", justifyContent: "space-between",
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <div style={{
            width: 42, height: 42,
            background: "linear-gradient(135deg,#00d4ff,#0055ff)",
            borderRadius: 10, display: "flex", alignItems: "center",
            justifyContent: "center", fontSize: 22,
            boxShadow: "0 0 24px rgba(0,212,255,0.35)"
          }}>🛡️</div>
          <div>
            <div style={{ fontSize: 18, fontWeight: "bold", color: "#00d4ff", letterSpacing: 3 }}>
              CYBERSHIELD
            </div>
            <div style={{ fontSize: 9, color: "#2a5a8a", letterSpacing: 3 }}>
              AI THREAT INTELLIGENCE PLATFORM v1.0
            </div>
          </div>
        </div>

        {/* Backend status pill */}
        <div style={{
          display: "flex", alignItems: "center", gap: 8,
          padding: "6px 14px",
          background: backendOk === null ? "rgba(255,255,255,0.03)" :
                      backendOk ? "rgba(0,255,136,0.08)" : "rgba(255,68,68,0.08)",
          border: `1px solid ${backendOk === null ? "#1a3a5c" : backendOk ? "#00ff8844" : "#ff444444"}`,
          borderRadius: 20,
        }}>
          <div style={{
            width: 7, height: 7, borderRadius: "50%",
            background: backendOk === null ? "#4a6fa5" : backendOk ? "#00ff88" : "#ff4444",
            boxShadow: backendOk ? "0 0 8px #00ff88" : backendOk === false ? "0 0 8px #ff4444" : "none",
          }} />
          <span style={{
            fontSize: 10, letterSpacing: 1,
            color: backendOk === null ? "#4a6fa5" : backendOk ? "#00ff88" : "#ff4444"
          }}>
            {backendOk === null ? "CHECKING..." : backendOk ? "BACKEND ONLINE" : "BACKEND OFFLINE"}
          </span>
          {backendOk === false &&
            <button onClick={checkBackend} style={{
              background: "none", border: "none", color: "#ff4444",
              cursor: "pointer", fontSize: 10, padding: 0, marginLeft: 4
            }}>↺</button>
          }
        </div>
      </div>

      {/* ── BACKEND OFFLINE BANNER ── */}
      {backendOk === false && (
        <div style={{
          background: "rgba(255,68,68,0.06)",
          border: "1px solid rgba(255,68,68,0.3)",
          margin: "16px 24px 0",
          borderRadius: 10, padding: "16px 20px"
        }}>
          <div style={{ color: "#ff4444", fontWeight: "bold", marginBottom: 10, fontSize: 13 }}>
            ⚠️ Python Backend Not Running — Follow These Steps:
          </div>
          <div style={{
            background: "#050810", borderRadius: 8, padding: 14,
            fontSize: 12, color: "#00ff88", lineHeight: 2.2
          }}>
            <div style={{ color: "#4a6fa5", marginBottom: 6 }}># In Windows CMD or PowerShell:</div>
            <div>cd cybershield\backend</div>
            <div>python -m venv venv</div>
            <div>venv\Scripts\activate</div>
            <div>pip install -r requirements.txt</div>
            <div style={{ color: "#4a6fa5", marginTop: 6 }}># Copy .env.example → .env and add your API keys</div>
            <div>copy .env.example .env</div>
            <div style={{ color: "#4a6fa5", marginTop: 6 }}># Start the server:</div>
            <div>uvicorn main:app --reload --port 8000</div>
          </div>
          <div style={{ marginTop: 10, fontSize: 11, color: "#4a6fa5" }}>
            Then visit <span style={{ color: "#00d4ff" }}>http://localhost:8000</span> to confirm it's running.
          </div>
        </div>
      )}

      {/* ── TABS ── */}
      <div style={{
        display: "flex", borderBottom: "1px solid #0d2040",
        background: "#060a12", padding: "0 24px"
      }}>
        {[
          { id: "scanner", label: "⚡ Scanner" },
          { id: "history", label: "📋 History" },
          { id: "setup",   label: "🔧 Setup Guide" },
        ].map(tab => (
          <button key={tab.id} onClick={() => setActiveTab(tab.id)} style={{
            background: "none", border: "none",
            borderBottom: activeTab === tab.id ? "2px solid #00d4ff" : "2px solid transparent",
            color: activeTab === tab.id ? "#00d4ff" : "#2a5a8a",
            padding: "13px 20px", cursor: "pointer",
            fontSize: 11, letterSpacing: 2, transition: "all 0.2s"
          }}>{tab.label}</button>
        ))}
      </div>

      <div style={{ padding: "24px", maxWidth: 960, margin: "0 auto" }}>

        {/* ══════════════ SCANNER TAB ══════════════ */}
        {activeTab === "scanner" && (<>

          {/* Scan type */}
          <div style={{ display: "flex", gap: 10, marginBottom: 18 }}>
            {[
              { id: "url", icon: "🔗", label: "URL / Domain" },
              { id: "ip",  icon: "🌐", label: "IP Address"   },
            ].map(t => (
              <button key={t.id} onClick={() => setScanType(t.id)} style={{
                padding: "9px 22px",
                background: scanType === t.id ? "rgba(0,212,255,0.12)" : "rgba(255,255,255,0.02)",
                border: `1px solid ${scanType === t.id ? "#00d4ff" : "#0d2040"}`,
                borderRadius: 8, color: scanType === t.id ? "#00d4ff" : "#2a5a8a",
                cursor: "pointer", fontSize: 12, letterSpacing: 1, transition: "all 0.2s"
              }}>{t.icon} {t.label}</button>
            ))}
          </div>

          {/* Input row */}
          <div style={{
            background: "rgba(255,255,255,0.02)", border: "1px solid #0d2040",
            borderRadius: 12, padding: 20, marginBottom: 16
          }}>
            <div style={{ fontSize: 10, color: "#2a5a8a", letterSpacing: 2, marginBottom: 10 }}>
              {scanType === "url" ? "TARGET URL OR DOMAIN" : "TARGET IP ADDRESS"}
            </div>
            <div style={{ display: "flex", gap: 10 }}>
              <input
                value={target}
                onChange={e => setTarget(e.target.value)}
                onKeyDown={e => e.key === "Enter" && runScan()}
                placeholder={scanType === "url" ? "https://example.com or example.com" : "8.8.8.8"}
                style={{
                  flex: 1, background: "rgba(0,0,0,0.5)",
                  border: "1px solid #0d2040", borderRadius: 8,
                  padding: "11px 16px", color: "#00d4ff",
                  fontSize: 13, fontFamily: "inherit", outline: "none",
                }}
              />
              <button onClick={runScan} disabled={loading} style={{
                padding: "11px 28px",
                background: loading ? "#0d1f3c"
                          : "linear-gradient(135deg,#0055ff,#00d4ff)",
                border: "none", borderRadius: 8, color: "white",
                cursor: loading ? "not-allowed" : "pointer",
                fontSize: 12, fontWeight: "bold", letterSpacing: 1,
                boxShadow: loading ? "none" : "0 0 20px rgba(0,212,255,0.25)",
                minWidth: 120, transition: "all 0.2s"
              }}>
                {loading ? "SCANNING…" : "⚡ SCAN"}
              </button>
            </div>
            {error && <div style={{ marginTop: 10, color: "#ff4444", fontSize: 12 }}>⚠️ {error}</div>}
          </div>

          {/* Live log */}
          {log.length > 0 && (
            <div ref={logRef} style={{
              background: "#050810", border: "1px solid #0d2040",
              borderRadius: 10, padding: "14px 16px",
              maxHeight: 140, overflowY: "auto", marginBottom: 16,
              fontFamily: "monospace"
            }}>
              {log.map((l, i) => (
                <div key={i} style={{
                  fontSize: 11, lineHeight: 1.9,
                  color: l.type === "error" ? "#ff4444"
                       : l.type === "success" ? "#00ff88"
                       : l.type === "warn" ? "#ffaa00" : "#4a8aaa"
                }}>
                  <span style={{ color: "#1a3a5c", marginRight: 8 }}>{l.time}</span>
                  <span style={{ marginRight: 8 }}>{l.icon}</span>
                  {l.text}
                </div>
              ))}
              {loading && (
                <div style={{ fontSize: 11, color: "#0d3a5c", marginTop: 4 }}>
                  ▌ waiting for engines...
                </div>
              )}
            </div>
          )}

          {/* ── RESULTS ── */}
          {result && !loading && (() => {
            const C = COLORS[result.threat_level] || COLORS.NONE;
            return (
              <div>
                {/* Threat banner */}
                <div style={{
                  background: C.bg, border: `1px solid ${C.border}`,
                  borderRadius: 12, padding: "18px 24px",
                  display: "flex", justifyContent: "space-between",
                  alignItems: "center", marginBottom: 14
                }}>
                  <div>
                    <div style={{ fontSize: 10, color: "#2a5a8a", letterSpacing: 2 }}>VERDICT</div>
                    <div style={{ fontSize: 24, fontWeight: "bold", color: C.main, marginTop: 4 }}>
                      {result.threat_level === "CLEAN"  ? "✅ NO THREATS DETECTED" :
                       result.threat_level === "MEDIUM" ? "⚠️ SUSPICIOUS ACTIVITY" :
                                                          "🚨 THREAT DETECTED"}
                    </div>
                    <div style={{ fontSize: 11, color: "#2a5a8a", marginTop: 4 }}>
                      {result.target} · scanned {new Date(result.scanned_at).toLocaleTimeString()}
                    </div>
                  </div>
                  {/* Risk gauge */}
                  <div style={{ textAlign: "center" }}>
                    <div style={{
                      width: 84, height: 84, borderRadius: "50%",
                      background: `conic-gradient(${C.main} ${result.risk_score * 3.6}deg, #0d1a2a 0deg)`,
                      display: "flex", alignItems: "center", justifyContent: "center",
                      boxShadow: `0 0 20px ${C.main}33`
                    }}>
                      <div style={{
                        width: 62, height: 62, borderRadius: "50%",
                        background: "#070b15", display: "flex",
                        alignItems: "center", justifyContent: "center", flexDirection: "column"
                      }}>
                        <div style={{ fontSize: 20, fontWeight: "bold", color: C.main, lineHeight: 1 }}>
                          {result.risk_score}
                        </div>
                        <div style={{ fontSize: 8, color: "#2a5a8a", letterSpacing: 1 }}>RISK</div>
                      </div>
                    </div>
                    <div style={{ fontSize: 9, color: "#2a5a8a", marginTop: 6, letterSpacing: 1 }}>
                      /100
                    </div>
                  </div>
                </div>

                {/* Stats row */}
                <div style={{
                  display: "grid",
                  gridTemplateColumns: result.summary.abuse_reports !== undefined
                    ? "repeat(4,1fr)" : "repeat(3,1fr)",
                  gap: 10, marginBottom: 14
                }}>
                  {[
                    { label: "MALICIOUS",  val: result.summary.malicious,  color: "#ff4444" },
                    { label: "SUSPICIOUS", val: result.summary.suspicious, color: "#ffaa00" },
                    { label: "CLEAN",      val: result.summary.clean,      color: "#00ff88" },
                    ...(result.summary.abuse_reports !== undefined
                      ? [{ label: "ABUSE REPORTS", val: result.summary.abuse_reports, color: "#ff4444" }]
                      : []),
                  ].map(s => (
                    <div key={s.label} style={{
                      background: "rgba(255,255,255,0.02)",
                      border: "1px solid #0d2040", borderRadius: 10,
                      padding: "14px 0", textAlign: "center"
                    }}>
                      <div style={{ fontSize: 26, fontWeight: "bold", color: s.color }}>{s.val}</div>
                      <div style={{ fontSize: 9, color: "#2a5a8a", letterSpacing: 2, marginTop: 4 }}>
                        {s.label}
                      </div>
                    </div>
                  ))}
                </div>

                <div style={{
                  display: "grid",
                  gridTemplateColumns: result.geo ? "1fr 1fr" : "1fr",
                  gap: 14
                }}>
                  {/* Engine results */}
                  <div style={{
                    background: "rgba(255,255,255,0.02)",
                    border: "1px solid #0d2040", borderRadius: 12, padding: 18
                  }}>
                    <div style={{ fontSize: 10, color: "#2a5a8a", letterSpacing: 2, marginBottom: 14 }}>
                      🔬 ENGINE RESULTS ({result.summary.total_engines || Object.keys(result.engines).length} engines)
                    </div>
                    {Object.entries(result.engines).map(([engine, verdict]) => (
                      <div key={engine} style={{
                        display: "flex", justifyContent: "space-between",
                        alignItems: "center", padding: "9px 0",
                        borderBottom: "1px solid #080e1a"
                      }}>
                        <span style={{ fontSize: 11, color: "#6a9ac8" }}>{engine}</span>
                        <span style={{
                          fontSize: 9, padding: "3px 10px", borderRadius: 4,
                          background: verdictColor(verdict) === "#ff4444" ? "rgba(255,68,68,0.1)"
                                    : verdictColor(verdict) === "#ffaa00" ? "rgba(255,170,0,0.1)"
                                    : "rgba(0,255,136,0.08)",
                          color: verdictColor(verdict),
                          border: `1px solid ${verdictColor(verdict)}33`
                        }}>{verdict}</span>
                      </div>
                    ))}
                    {Object.keys(result.engines).length === 0 && (
                      <div style={{ fontSize: 11, color: "#2a5a8a" }}>No engine data returned.</div>
                    )}
                  </div>

                  {/* Geo / domain info */}
                  {result.geo && (
                    <div style={{
                      background: "rgba(255,255,255,0.02)",
                      border: "1px solid #0d2040", borderRadius: 12, padding: 18
                    }}>
                      <div style={{ fontSize: 10, color: "#2a5a8a", letterSpacing: 2, marginBottom: 14 }}>
                        🌍 GEOLOCATION & ISP
                      </div>
                      {Object.entries(result.geo).map(([key, val]) => (
                        <div key={key} style={{
                          padding: "9px 0", borderBottom: "1px solid #080e1a"
                        }}>
                          <div style={{ fontSize: 9, color: "#2a5a8a", letterSpacing: 1 }}>
                            {key.replace(/_/g," ").toUpperCase()}
                          </div>
                          <div style={{
                            fontSize: 12, color: "#c8d6e5", marginTop: 3,
                            color: typeof val === "boolean"
                              ? (val ? "#ff4444" : "#00ff88") : "#c8d6e5"
                          }}>
                            {typeof val === "boolean" ? (val ? "YES ⚠️" : "NO") : (val || "Unknown")}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Abuse info */}
                  {result.abuse && (
                    <div style={{
                      background: "rgba(255,255,255,0.02)",
                      border: "1px solid #0d2040", borderRadius: 12, padding: 18
                    }}>
                      <div style={{ fontSize: 10, color: "#2a5a8a", letterSpacing: 2, marginBottom: 14 }}>
                        🚨 ABUSEIPDB REPORT
                      </div>
                      {[
                        ["Abuse Score",    `${result.abuse.abuse_score}/100`],
                        ["Total Reports",  result.abuse.total_reports],
                        ["ISP",            result.abuse.isp],
                        ["Usage Type",     result.abuse.usage_type],
                        ["TOR Exit Node",  result.abuse.is_tor ? "YES ⚠️" : "NO"],
                        ["Last Reported",  result.abuse.last_reported || "Never"],
                      ].map(([k,v]) => (
                        <div key={k} style={{ padding: "9px 0", borderBottom: "1px solid #080e1a" }}>
                          <div style={{ fontSize: 9, color: "#2a5a8a", letterSpacing: 1 }}>
                            {k.toUpperCase()}
                          </div>
                          <div style={{ fontSize: 12, color: "#c8d6e5", marginTop: 3 }}>{String(v)}</div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            );
          })()}
        </>)}

        {/* ══════════════ HISTORY TAB ══════════════ */}
        {activeTab === "history" && (
          <div>
            <div style={{ fontSize: 10, color: "#2a5a8a", letterSpacing: 2, marginBottom: 18 }}>
              RECENT SCANS ({history.length})
            </div>
            {history.length === 0 ? (
              <div style={{
                textAlign: "center", padding: 60,
                background: "rgba(255,255,255,0.02)",
                border: "1px solid #0d2040", borderRadius: 12
              }}>
                <div style={{ fontSize: 32, marginBottom: 12 }}>📋</div>
                <div style={{ color: "#2a5a8a", fontSize: 13 }}>No scans yet.</div>
              </div>
            ) : history.map((h, i) => {
              const C = COLORS[h.threatLevel] || COLORS.NONE;
              return (
                <div key={i} style={{
                  display: "flex", justifyContent: "space-between", alignItems: "center",
                  padding: "14px 18px",
                  background: "rgba(255,255,255,0.02)",
                  border: "1px solid #0d2040", borderRadius: 10, marginBottom: 8
                }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                    <span style={{ fontSize: 18 }}>{h.scanType === "url" ? "🔗" : "🌐"}</span>
                    <div>
                      <div style={{ fontSize: 12, color: "#c8d6e5" }}>{h.target}</div>
                      <div style={{ fontSize: 10, color: "#2a5a8a", marginTop: 2 }}>
                        {h.scanType.toUpperCase()} · {h.time} · risk: {h.riskScore}/100
                      </div>
                    </div>
                  </div>
                  <span style={{
                    padding: "4px 14px", borderRadius: 6, fontSize: 10,
                    background: C.bg, color: C.main, border: `1px solid ${C.border}`
                  }}>{h.threatLevel}</span>
                </div>
              );
            })}
          </div>
        )}

        {/* ══════════════ SETUP GUIDE TAB ══════════════ */}
        {activeTab === "setup" && (
          <div>
            <div style={{ fontSize: 10, color: "#2a5a8a", letterSpacing: 2, marginBottom: 18 }}>
              🔧 COMPLETE SETUP GUIDE — WINDOWS
            </div>

            {[
              {
                step: "01", title: "Download Project Files",
                content: "Download main.py, requirements.txt and .env.example from the files shared by Claude. Put them all in a folder called cybershield\\backend on your Desktop."
              },
              {
                step: "02", title: "Create Your .env File",
                body: `# In your cybershield\\backend folder:
# 1. Rename .env.example  →  .env
# 2. Open .env in Notepad
# 3. Paste your NEW API keys:

VIRUSTOTAL_API_KEY=your_new_vt_key_here
ABUSEIPDB_API_KEY=your_new_abuseipdb_key_here`
              },
              {
                step: "03", title: "Install & Run Backend",
                body: `# Open CMD, navigate to your folder:
cd Desktop\\cybershield\\backend

# Create virtual environment:
python -m venv venv

# Activate it:
venv\\Scripts\\activate

# Install dependencies:
pip install -r requirements.txt

# Start server:
uvicorn main:app --reload --port 8000`
              },
              {
                step: "04", title: "Verify Backend is Running",
                content: 'Open your browser and go to http://localhost:8000 — you should see: {"status": "🛡️ CyberShield API is ONLINE"}. The green dot above will turn ON.'
              },
              {
                step: "05", title: "Start Scanning!",
                content: "Come back to the Scanner tab. The backend status will show ONLINE. Enter any URL or IP and hit SCAN — you'll get real VirusTotal + AbuseIPDB results!"
              },
            ].map(s => (
              <div key={s.step} style={{
                background: "rgba(255,255,255,0.02)",
                border: "1px solid #0d2040", borderRadius: 12,
                padding: 20, marginBottom: 14
              }}>
                <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 12 }}>
                  <div style={{
                    width: 32, height: 32, borderRadius: "50%",
                    background: "rgba(0,212,255,0.1)",
                    border: "1px solid #00d4ff44",
                    display: "flex", alignItems: "center", justifyContent: "center",
                    fontSize: 11, color: "#00d4ff", fontWeight: "bold"
                  }}>{s.step}</div>
                  <span style={{ color: "#00d4ff", fontSize: 13, fontWeight: "bold" }}>{s.title}</span>
                </div>
                {s.content && <div style={{ fontSize: 12, color: "#8aa6c8", lineHeight: 1.8 }}>{s.content}</div>}
                {s.body && (
                  <div style={{
                    background: "#050810", border: "1px solid #0d1f3c",
                    borderRadius: 8, padding: "12px 16px",
                    fontSize: 11, color: "#00ff88", whiteSpace: "pre", lineHeight: 2,
                    overflowX: "auto"
                  }}>{s.body}</div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap');
        * { box-sizing: border-box; margin: 0; padding: 0; }
        input::placeholder { color: #1a3a5c; }
        ::-webkit-scrollbar { width: 4px; height: 4px; }
        ::-webkit-scrollbar-track { background: #070b15; }
        ::-webkit-scrollbar-thumb { background: #0d2040; border-radius: 2px; }
      `}</style>
    </div>
  );
}
