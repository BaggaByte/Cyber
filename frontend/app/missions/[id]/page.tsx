"use client";
import { useState, useEffect } from "react";
import { useParams, useRouter } from "next/navigation";
import Cookies from "js-cookie";
import {
  Shield, Target, Clock, CheckCircle, XCircle, Activity,
  AlertTriangle, Crosshair, ChevronRight, ArrowLeft,
  Cpu, Lock, Server, Zap, BrainCircuit
} from "lucide-react";
import Sidebar from "../../components/Sidebar";

const API = "";

function ScanRow({ scan, onClick }: { scan: any; onClick: () => void }) {
  return (
    <tr onClick={onClick} style={{ cursor: "pointer", borderTop: "1px solid var(--border)" }}
      onMouseEnter={e => (e.currentTarget.style.background = "var(--bg-card-hover)")}
      onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
    >
      <td style={{ padding: "12px 16px", fontFamily: "monospace", fontSize: 11, color: "var(--text-muted)" }}>#{scan.scan_id}</td>
      <td style={{ padding: "12px 16px" }}>
        <span style={{ background: "rgba(240,78,35,0.08)", color: "var(--accent-primary)", padding: "3px 10px", borderRadius: 6, fontSize: 11, fontWeight: 700, border: "1px solid rgba(240,78,35,0.2)" }}>
          {scan.tool_used?.toUpperCase()}
        </span>
      </td>
      <td style={{ padding: "12px 16px" }}>
        {scan.risk_score ? (
          <span className={`risk-${scan.risk_score.toLowerCase()}`} style={{ fontSize: 10, fontWeight: 700, padding: "3px 8px", borderRadius: 4 }}>
            {scan.risk_score}
          </span>
        ) : <span style={{ color: "var(--text-muted)", fontSize: 11 }}>—</span>}
      </td>
      <td style={{ padding: "12px 16px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          {scan.status === "completed" && <CheckCircle size={13} color="var(--emerald)" />}
          {scan.status === "failed" && <XCircle size={13} color="var(--red)" />}
          {scan.status === "running" && <Activity size={13} color="var(--accent-primary)" />}
          {scan.status === "queued" && <Clock size={13} color="var(--amber)" />}
          <span style={{ fontSize: 12, textTransform: "capitalize", fontWeight: 600 }} className={`status-${scan.status}`}>{scan.status}</span>
        </div>
      </td>
    </tr>
  );
}

export default function MissionDetailPage() {
  const params = useParams();
  const router = useRouter();
  const missionId = params?.id;
  const token = Cookies.get("token");
  const [mission, setMission] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!token) { router.push("/"); return; }
    if (!missionId) return;
    const h = { Authorization: `Bearer ${token}` };

    fetch(`${API}/api/missions/${missionId}`, { headers: h })
      .then(r => r.json())
      .then(data => { setMission(data); setLoading(false); })
      .catch(() => setLoading(false));
  }, [missionId, token]);

  if (loading) return (
    <div style={{ display: "flex", minHeight: "100vh" }}>
      <Sidebar />
      <main style={{ marginLeft: 240, flex: 1, display: "flex", alignItems: "center", justifyContent: "center" }}>
        <div style={{ textAlign: "center", color: "var(--text-muted)" }}>
          <Activity size={32} style={{ animation: "spin-slow 2s linear infinite", color: "var(--accent-primary)", marginBottom: 12 }} />
          <div style={{ fontSize: 14 }}>Loading mission data...</div>
        </div>
      </main>
    </div>
  );

  if (!mission || mission.detail) return (
    <div style={{ display: "flex", minHeight: "100vh" }}>
      <Sidebar />
      <main style={{ marginLeft: 240, flex: 1, display: "flex", alignItems: "center", justifyContent: "center" }}>
        <div style={{ textAlign: "center", color: "var(--text-muted)" }}>
          <Crosshair size={32} style={{ marginBottom: 12 }} />
          <div style={{ fontSize: 14 }}>Mission not found</div>
          <button onClick={() => router.push("/missions")} className="btn-primary" style={{ marginTop: 16 }}>Back to Missions</button>
        </div>
      </main>
    </div>
  );

  const logs = mission.decision_log || [];
  const scans = mission.scans || [];

  return (
    <div style={{ display: "flex", minHeight: "100vh" }}>
      <Sidebar />
      <main style={{ marginLeft: 240, flex: 1, padding: "40px" }}>

        {/* Breadcrumb */}
        <div className="animate-slide-up" style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 24, fontSize: 13, color: "var(--text-muted)" }}>
          <button onClick={() => router.push("/missions")} style={{
            display: "flex", alignItems: "center", gap: 6,
            background: "none", border: "none", color: "var(--text-muted)",
            cursor: "pointer", fontFamily: "inherit", fontSize: 13, padding: 0
          }}>
            <ArrowLeft size={14} /> Autonomous Missions
          </button>
          <ChevronRight size={14} />
          <span style={{ color: "var(--text-primary)", fontWeight: 600 }}>Mission #{mission.mission_id}</span>
        </div>

        {/* Hero Row: Target + Goal */}
        <div className="glass-card animate-slide-up delay-100" style={{ padding: 28, marginBottom: 32, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <div>
            <div style={{ fontSize: 12, fontWeight: 600, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "1px", marginBottom: 8 }}>Target</div>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 26, fontWeight: 700, color: "var(--text-primary)", marginBottom: 4 }}>
              {mission.target}
            </div>
            <div style={{ fontSize: 15, color: "var(--text-secondary)", fontWeight: 500 }}>
              {mission.goal}
            </div>
          </div>
          <div style={{ textAlign: "right" }}>
            <div style={{ fontSize: 12, fontWeight: 600, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "1px", marginBottom: 8 }}>Started At</div>
            <div style={{ fontSize: 15, color: "var(--text-primary)", fontWeight: 600 }}>
              {new Date(mission.created_at).toLocaleString()}
            </div>
          </div>
        </div>

        <div className="animate-slide-up delay-200" style={{ display: "grid", gridTemplateColumns: "1.3fr 1fr", gap: 32 }}>
          
          {/* Left: Decision Log Timeline */}
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 24 }}>
              <div style={{ width: 32, height: 32, borderRadius: 8, background: "rgba(240,78,35,0.15)", display: "flex", alignItems: "center", justifyContent: "center" }}>
                <BrainCircuit size={16} color="var(--accent-primary)" />
              </div>
              <h2 style={{ fontSize: 18, fontWeight: 700, color: "var(--text-primary)" }}>AI Decision Log</h2>
            </div>
            
            <div style={{ position: "relative", paddingLeft: 16 }}>
              {/* Vertical line */}
              <div style={{ position: "absolute", top: 8, bottom: 0, left: 16, width: 2, background: "var(--border)" }} />
              
              <div style={{ display: "flex", flexDirection: "column", gap: 24 }}>
                {logs.map((log: any, idx: number) => (
                  <div key={idx} style={{ position: "relative", paddingLeft: 24 }}>
                    {/* Node dot */}
                    <div style={{
                      position: "absolute", left: -5, top: 4, width: 12, height: 12, borderRadius: "50%",
                      background: "var(--bg-base)", border: "2px solid var(--accent-primary)", zIndex: 1
                    }} />
                    
                    <div className="glass-card" style={{ padding: "16px 20px" }}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
                        <div style={{ fontWeight: 700, fontSize: 14, color: "var(--text-primary)" }}>{log.action}</div>
                        <div style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "'JetBrains Mono', monospace" }}>
                          {new Date(log.timestamp).toLocaleTimeString()}
                        </div>
                      </div>
                      <div style={{ fontSize: 13, color: "var(--text-secondary)", lineHeight: 1.6, whiteSpace: "pre-wrap" }}>
                        {log.reason}
                      </div>
                      {log.confidence && (
                        <div style={{ marginTop: 12, display: "inline-block", background: "rgba(16,185,129,0.1)", color: "var(--emerald)", padding: "4px 10px", borderRadius: 20, fontSize: 11, fontWeight: 700, border: "1px solid rgba(16,185,129,0.2)" }}>
                          Confidence: {log.confidence}
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Right: Child Scans */}
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 24 }}>
              <div style={{ width: 32, height: 32, borderRadius: 8, background: "rgba(59,130,246,0.15)", display: "flex", alignItems: "center", justifyContent: "center" }}>
                <Cpu size={16} color="#3b82f6" />
              </div>
              <h2 style={{ fontSize: 18, fontWeight: 700, color: "var(--text-primary)" }}>Executed Tasks</h2>
            </div>

            <div className="glass-card" style={{ padding: 0, overflow: "hidden" }}>
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead>
                  <tr style={{ borderBottom: "1px solid var(--border)", background: "var(--bg-base)" }}>
                    {["ID", "Tool", "Risk", "Status"].map(h => (
                      <th key={h} style={{
                        padding: "12px 16px", textAlign: "left",
                        fontSize: 11, color: "var(--text-muted)", fontWeight: 600,
                        letterSpacing: "0.06em", textTransform: "uppercase"
                      }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {scans.length === 0 ? (
                    <tr><td colSpan={4} style={{ padding: 30, textAlign: "center", color: "var(--text-muted)", fontSize: 13 }}>No tasks executed yet.</td></tr>
                  ) : (
                    scans.map((scan: any) => (
                      <ScanRow key={scan.scan_id} scan={scan} onClick={() => router.push(`/scans/${scan.scan_id}`)} />
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>

        </div>

      </main>
    </div>
  );
}
