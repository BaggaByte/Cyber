"use client";
import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import Cookies from "js-cookie";
import { Target, ChevronRight, Activity, ExternalLink, Crosshair } from "lucide-react";
import Sidebar from "../components/Sidebar";

const API = "";

function MissionRow({ mission, onClick }: { mission: any; onClick: () => void }) {
  return (
    <tr onClick={onClick} style={{ cursor: "pointer", borderTop: "1px solid var(--border)" }}
      onMouseEnter={e => (e.currentTarget.style.background = "var(--bg-card-hover)")}
      onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
    >
      <td style={{ padding: "14px 20px", fontFamily: "monospace", fontSize: 11, color: "var(--text-muted)" }}>#{mission.mission_id}</td>
      <td style={{ padding: "14px 20px", fontFamily: "'JetBrains Mono', monospace", fontSize: 13, fontWeight: 600, color: "var(--text-primary)" }}>{mission.target || "—"}</td>
      <td style={{ padding: "14px 20px" }}>
        <span style={{ fontSize: 13, color: "var(--text-secondary)" }}>
          {mission.goal}
        </span>
      </td>
      <td style={{ padding: "14px 20px" }}>
        <span style={{ background: "rgba(14,165,233,0.1)", color: "#0ea5e9", padding: "3px 10px", borderRadius: 6, fontSize: 11, fontWeight: 700, border: "1px solid rgba(14,165,233,0.2)" }}>
          {mission.scan_count} Tasks
        </span>
      </td>
      <td style={{ padding: "14px 20px", fontSize: 12, color: "var(--text-muted)" }}>
        {new Date(mission.created_at).toLocaleString()}
      </td>
      <td style={{ padding: "14px 20px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 4, color: "var(--accent-primary)", fontSize: 12, fontWeight: 600 }}>
          View <ExternalLink size={12} />
        </div>
      </td>
    </tr>
  );
}

export default function MissionsPage() {
  const [missions, setMissions] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const token = Cookies.get("token");
  const router = useRouter();

  useEffect(() => {
    if (!token) { window.location.href = "/"; return; }
    fetch(`${API}/api/missions?limit=50`, { headers: { "Authorization": `Bearer ${token}` } })
      .then(r => r.json()).then(data => { setMissions(Array.isArray(data) ? data : []); setLoading(false); })
      .catch(() => setLoading(false));
  }, [token]);

  return (
    <div style={{ display: "flex", minHeight: "100vh" }}>
      <Sidebar />
      <main style={{ marginLeft: 240, flex: 1, padding: "32px 40px" }}>
        <div className="animate-slide-up" style={{ marginBottom: 32, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <div>
            <h1 style={{ fontSize: 30, fontWeight: 800, letterSpacing: "-1px" }}>Autonomous <span className="text-gradient">Missions</span></h1>
            <p style={{ color: "var(--text-secondary)", marginTop: 6, fontSize: 14 }}>
              {missions.length} active or completed agentic missions
            </p>
          </div>
          <button onClick={() => router.push("/orchestrate")} className="btn-primary" style={{ display: "flex", alignItems: "center", gap: 8, padding: "10px 18px", fontSize: 13 }}>
            <Crosshair size={14} /> New Mission
          </button>
        </div>

        <div style={{ background: "var(--bg-card)", border: "1px solid var(--border)", borderRadius: 12, overflow: "hidden" }}>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr style={{ borderBottom: "1px solid var(--border)" }}>
                {["ID", "Target", "Goal", "Tasks Executed", "Date", ""].map(h => (
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
                <tr><td colSpan={6} style={{ padding: 40, textAlign: "center", color: "var(--text-muted)" }}>Loading...</td></tr>
              )}
              {!loading && missions.length === 0 && (
                <tr><td colSpan={6} style={{ padding: 40, textAlign: "center", color: "var(--text-muted)" }}>No missions yet. Launch one from the Orchestrate page.</td></tr>
              )}
              {missions.map(mission => <MissionRow key={mission.mission_id} mission={mission} onClick={() => router.push(`/missions/${mission.mission_id}`)} />)}
            </tbody>
          </table>
        </div>
      </main>
    </div>
  );
}
