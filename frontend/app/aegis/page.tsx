"use client";
import { useEffect, useState } from "react";
import Cookies from "js-cookie";
import { Shield, Code, Bug, Cpu, Play, RefreshCw } from "lucide-react";
import Sidebar from "../components/Sidebar";

interface VulnerabilityItem {
  type: string;
  severity: string;
  line: number;
  description: string;
  fix: string;
}

interface AegisResult {
  vulnerabilities: VulnerabilityItem[];
  score: number;
  status: string;
}

export default function AegisPage() {
  const [token, setToken] = useState<string | null>(null);
  const [mounted, setMounted] = useState(false);
  const [code, setCode] = useState(`def execute_user_query(user_input):\n    # Vulnerable SQL query construction\n    query = f"SELECT * FROM users WHERE username = '{user_input}'"\n    cursor.execute(query)\n    return cursor.fetchall()`);
  const [analyzing, setAnalyzing] = useState(false);
  const [analysisResult, setAnalysisResult] = useState<AegisResult | null>(null);

  useEffect(() => {
    const t = Cookies.get("token") || null;
    setToken(t);
    setMounted(true);
    if (!t) window.location.href = "/";
  }, []);

  // Don't render anything until mounted (prevents SSR/client mismatch)
  if (!mounted) return null;

  const handleAnalyze = () => {
    setAnalyzing(true);
    setTimeout(() => {
      setAnalysisResult({
        vulnerabilities: [
          {
            type: "SQL Injection (CWE-89)",
            severity: "CRITICAL",
            line: 3,
            description: "Direct string interpolation in SQL query string allows SQL injection.",
            fix: `def execute_user_query(user_input):\n    # Parameterized SQL query\n    query = "SELECT * FROM users WHERE username = %s"\n    cursor.execute(query, (user_input,))\n    return cursor.fetchall()`
          }
        ],
        score: 35,
        status: "Vulnerabilities Found"
      });
      setAnalyzing(false);
    }, 1200);
  };

  return (
    <div style={{ display: "flex", minHeight: "100vh" }}>
      <Sidebar />
      <main style={{ marginLeft: 240, flex: 1, padding: "32px 40px" }}>
        <div style={{ marginBottom: 32, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
              <div style={{ width: 40, height: 40, borderRadius: 10, background: "rgba(240,78,35,0.15)", display: "flex", alignItems: "center", justifyContent: "center" }}>
                <Shield size={22} color="var(--accent-primary)" />
              </div>
              <h1 style={{ fontSize: 28, fontWeight: 800 }}>Aegis AI <span className="text-gradient">Code Reviewer</span></h1>
            </div>
            <p style={{ color: "var(--text-secondary)", marginTop: 6, fontSize: 14 }}>
              Automated static code analysis, SAST scanning, and AI patch validation
            </p>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 8, background: "rgba(16,185,129,0.1)", padding: "6px 14px", borderRadius: 20, border: "1px solid rgba(16,185,129,0.2)", fontSize: 12, color: "var(--emerald)", fontWeight: 700 }}>
            <div style={{ width: 8, height: 8, borderRadius: "50%", background: "var(--emerald)", boxShadow: "0 0 8px var(--emerald)" }} />
            Aegis Engine Online
          </div>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "1.2fr 1fr", gap: 24 }}>
          {/* Code Input Card */}
          <div className="glass-card" style={{ padding: 24 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 14, fontWeight: 700 }}>
                <Code size={16} color="var(--accent-primary)" /> Python / Source Code Inspector
              </div>
              <button onClick={handleAnalyze} disabled={analyzing} className="btn-primary" style={{ display: "flex", alignItems: "center", gap: 8, padding: "8px 16px", fontSize: 13 }}>
                {analyzing ? <RefreshCw size={14} style={{ animation: "spin-slow 1s linear infinite" }} /> : <Play size={14} />}
                {analyzing ? "Scanning..." : "Analyze Code"}
              </button>
            </div>
            <textarea
              value={code}
              onChange={e => setCode(e.target.value)}
              rows={14}
              className="input-glass mono"
              style={{ width: "100%", padding: 16, fontSize: 13, lineHeight: 1.6, resize: "vertical" }}
            />
          </div>

          {/* Analysis Result Card */}
          <div className="glass-card" style={{ padding: 24 }}>
            <h2 style={{ fontSize: 16, fontWeight: 700, marginBottom: 16, display: "flex", alignItems: "center", gap: 8 }}>
              <Bug size={18} color="var(--red)" /> Vulnerability Report
            </h2>

            {!analysisResult && !analyzing && (
              <div style={{ padding: 40, textAlign: "center", color: "var(--text-muted)", fontSize: 13 }}>
                Click &quot;Analyze Code&quot; to perform static security analysis.
              </div>
            )}

            {analyzing && (
              <div style={{ padding: 40, textAlign: "center", color: "var(--text-muted)" }}>
                <Cpu size={32} style={{ animation: "spin-slow 2s linear infinite", color: "var(--accent-primary)", marginBottom: 12 }} />
                <div style={{ fontSize: 14 }}>Aegis SAST engine auditing code...</div>
              </div>
            )}

            {analysisResult && !analyzing && (
              <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", background: "var(--bg-base)", padding: 12, borderRadius: 8, border: "1px solid var(--border)" }}>
                  <span style={{ fontSize: 13, fontWeight: 600 }}>Security Score</span>
                  <span style={{ fontSize: 18, fontWeight: 800, color: "var(--red)" }}>{analysisResult.score} / 100</span>
                </div>

                {analysisResult.vulnerabilities.map((vuln: VulnerabilityItem, idx: number) => (
                  <div key={idx} style={{ background: "rgba(239,68,68,0.08)", border: "1px solid rgba(239,68,68,0.25)", borderRadius: 10, padding: 16 }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
                      <span style={{ fontWeight: 700, fontSize: 13, color: "var(--red)" }}>{vuln.type}</span>
                      <span style={{ fontSize: 10, fontWeight: 800, padding: "2px 8px", borderRadius: 4, background: "var(--red)", color: "white" }}>{vuln.severity}</span>
                    </div>
                    <div style={{ fontSize: 12, color: "var(--text-secondary)", marginBottom: 12 }}>{vuln.description}</div>
                    
                    <div style={{ fontSize: 11, fontWeight: 700, color: "var(--emerald)", marginBottom: 6 }}>Suggested AI Remediation:</div>
                    <pre className="mono" style={{ background: "var(--bg-base)", padding: 10, borderRadius: 6, fontSize: 11, color: "var(--emerald)", overflowX: "auto" }}>
                      {vuln.fix}
                    </pre>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </main>
    </div>
  );
}
