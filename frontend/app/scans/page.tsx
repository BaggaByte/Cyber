"use client";
import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import Cookies from "js-cookie";
import { Shield, Clock, CheckCircle, XCircle, Activity, ExternalLink } from "lucide-react";
import Sidebar from "../components/Sidebar";

const API = "";

function RiskBadge({ score }: { score: string | null }) {
  if (!score) return <span style={{ color: "var(--text-muted)", fontSize: 11 }}>—</span>;
  return (
    <span className={`risk-${score.toLowerCase()}`}
      style={{ fontSize: 10, fontWeight: 700, padding: "3px 8px", borderRadius: 4 }}>
      {score}
    </span>
  );
}


function ScanRow({ scan, onClick }: { scan: Record<string, unknown>; onClick: () => void }) {
  return (
    <tr onClick={onClick} style={{ cursor: "pointer", borderTop: "1px solid var(--border)" }}
      onMouseEnter={e => (e.currentTarget.style.background = "var(--bg-card-hover)")}
      onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
    >
      <td style={{ padding: "14px 20px", fontFamily: "monospace", fontSize: 11, color: "var(--text-muted)" }}>#{ scan.scan_id}</td>
      <td style={{ padding: "14px 20px", fontFamily: "'JetBrains Mono', monospace", fontSize: 13, fontWeight: 600, color: "var(--text-primary)" }}>{scan.target || "—"}</td>
      <td style={{ padding: "14px 20px" }}>
        <span style={{ background: "rgba(240,78,35,0.08)", color: "var(--accent-primary)", padding: "3px 10px", borderRadius: 6, fontSize: 11, fontWeight: 700, border: "1px solid rgba(240,78,35,0.2)" }}>
          {scan.tool_used?.toUpperCase()}
        </span>
      </td>
      <td style={{ padding: "14px 20px" }}><RiskBadge score={scan.risk_score} /></td>
      <td style={{ padding: "14px 20px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          {scan.status === "completed" && <CheckCircle size={13} color="var(--emerald)" />}
          {scan.status === "failed" && <XCircle size={13} color="var(--red)" />}
          {scan.status === "running" && <Activity size={13} color="var(--accent-primary)" />}
          {scan.status === "queued" && <Clock size={13} color="var(--amber)" />}
          <span style={{ fontSize: 12, textTransform: "capitalize", fontWeight: 600 }} className={`status-${scan.status}`}>{scan.status}</span>
        </div>
      </td>
      <td style={{ padding: "14px 20px", fontSize: 12, color: "var(--text-muted)" }}>
        {scan.completed_at ? new Date(scan.completed_at).toLocaleString() : "—"}
      </td>
      <td style={{ padding: "14px 20px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 4, color: "var(--accent-primary)", fontSize: 12, fontWeight: 600 }}>
          View <ExternalLink size={12} />
        </div>
      </td>
    </tr>
  );
}

export default function ScansPage() {
  const [scans, setScans] = useState<Record<string, unknown>[]>([]);
  const [loading, setLoading] = useState(true);
  const token = Cookies.get("token");
  const router = useRouter();

  useEffect(() => {
    if (!token) { window.location.href = "/"; return; }
    fetch(`${API}/api/scans?limit=50`, { headers: { "Authorization": `Bearer ${token}` } })
      .then(r => r.json()).then(data => { setScans(Array.isArray(data) ? data : []); setLoading(false); })
      .catch(() => setLoading(false));
  }, [token]);

  return (
    <div style={{ display: "flex", minHeight: "100vh" }}>
      <Sidebar />
      <main style={{ marginLeft: 240, flex: 1, padding: "32px 40px" }}>
        <div className="animate-slide-up" style={{ marginBottom: 32, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <div>
            <h1 style={{ fontSize: 30, fontWeight: 800, letterSpacing: "-1px" }}>Scan <span className="text-gradient">History</span></h1>
            <p style={{ color: "var(--text-secondary)", marginTop: 6, fontSize: 14 }}>
              {scans.length} total scans — click any row to view full details
            </p>
          </div>
          <button onClick={() => router.push("/dashboard")} className="btn-primary" style={{ display: "flex", alignItems: "center", gap: 8, padding: "10px 18px", fontSize: 13 }}>
            <Shield size={14} /> Launch New Scan
          </button>
        </div>

        <div style={{ background: "var(--bg-card)", border: "1px solid var(--border)", borderRadius: 12, overflow: "hidden" }}>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr style={{ borderBottom: "1px solid var(--border)" }}>
                {["ID", "Target", "Tool", "Risk", "Status", "Completed", ""].map(h => (
                  <th key={h} style={{
                    padding: "12px 16px", textAlign: "left",
                    fontSize: 11, color: "var(--text-muted)", fontWeight: 600,
                    letterSpacing: "0.06em", textTransform: "uppercase"
                  }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loading && (
                <tr><td colSpan={7} style={{ padding: 40, textAlign: "center", color: "var(--text-muted)" }}>Loading...</td></tr>
              )}
              {!loading && scans.length === 0 && (
                <tr><td colSpan={7} style={{ padding: 40, textAlign: "center", color: "var(--text-muted)" }}>No scans yet. Launch one from the Orchestrate page.</td></tr>
              )}
              {scans.map(scan => <ScanRow key={scan.scan_id} scan={scan} onClick={() => router.push(`/scans/${scan.scan_id}`)} />)}
            </tbody>
          </table>
        </div>
      </main>
    </div>
  );
}
