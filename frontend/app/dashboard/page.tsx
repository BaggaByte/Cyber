"use client";
import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import Cookies from "js-cookie";
import { Shield, Target, Activity, AlertTriangle, CheckCircle, XCircle, Clock, Zap, TrendingUp } from "lucide-react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell, AreaChart, Area } from "recharts";
import Sidebar from "../components/Sidebar";

const API = "";

function StatCard({ label, value, icon: Icon, color }: any) {
  return (
    <div className="glass-card hover-lift" style={{
      padding: "24px",
      display: "flex", alignItems: "center", gap: "20px",
    }}>
      <div className="animate-pulse-glow" style={{
        width: "56px", height: "56px", borderRadius: "50%",
        background: `${color}15`, border: `2px solid ${color}30`,
        display: "flex", alignItems: "center", justifyContent: "center",
      }}>
        <Icon size={26} color={color} />
      </div>
      <div>
        <div style={{ fontSize: "32px", fontWeight: "800", color: "var(--text-primary)", letterSpacing: "-1px" }}>{value ?? "—"}</div>
        <div style={{ fontSize: "14px", color: "var(--text-secondary)", fontWeight: "500", marginTop: "4px" }}>{label}</div>
      </div>
    </div>
  );
}

const RISK_COLORS: Record<string, string> = {
  CRITICAL: "var(--red)", HIGH: "var(--amber)",
  MEDIUM: "var(--accent-primary)", LOW: "var(--emerald)", INFO: "var(--text-muted)",
};

export default function DashboardPage() {
  const [summary, setSummary] = useState<any>(null);
  const [recentScans, setRecentScans] = useState<any[]>([]);
  const [trend, setTrend] = useState<any[]>([]);
  const [liveEvents, setLiveEvents] = useState<any[]>([]);
  const router = useRouter();
  const token = Cookies.get("token");

  useEffect(() => {
    if (!token) { window.location.href = "/"; return; }
    const h = { "Authorization": `Bearer ${token}` };

    let isRedirecting = false;
    const checkAuth = async (r: Response) => {
      if (r.status === 401 && !isRedirecting) { 
        isRedirecting = true;
        Cookies.remove("token"); 
        window.location.href = "/"; 
        return null;
      }
      return r.ok ? r.json() : null;
    };

    const safeCatch = (err: any) => {
      if (!isRedirecting) console.error(err);
    };

    fetch(`${API}/api/dashboard/summary`, { headers: h })
      .then(checkAuth).then(d => d && setSummary(d)).catch(safeCatch);

    fetch(`${API}/api/scans?limit=8`, { headers: h })
      .then(checkAuth).then(d => {
        if (!d) return;
        const scans = Array.isArray(d) ? d : [];
        setRecentScans(scans);
        const events = scans.slice(0, 6).map((s: any) => ({
          id: s.scan_id,
          type: s.risk_score === "CRITICAL" ? "alert" : s.status === "completed" ? "success" : "info",
          message: `${s.tool_used?.toUpperCase()} scan on ${s.target} — ${s.risk_score || s.status}`,
          time: s.completed_at || s.started_at,
        }));
        setLiveEvents(events);
      }).catch(safeCatch);

    fetch(`${API}/api/reports/summary`, { headers: h })
      .then(checkAuth).then(d => d && setTrend(d.daily_trend || [])).catch(safeCatch);
  }, [token]);

  const riskData = summary?.risk_breakdown
    ? Object.entries(summary.risk_breakdown).map(([k, v]) => ({ name: k, count: v }))
    : [];

  return (
    <div style={{ display: "flex", minHeight: "100vh" }}>
      <Sidebar />
      <main style={{ marginLeft: "240px", flex: 1, padding: "40px" }}>
        
        {/* Row 1: Header */}
        <div className="animate-slide-up" style={{ marginBottom: "32px" }}>
          <h1 style={{ fontSize: "32px", fontWeight: "800", letterSpacing: "-1px" }}>Attack Surface <span className="text-gradient">Overview</span></h1>
          <p style={{ color: "var(--text-secondary)", marginTop: "8px", fontSize: "16px", fontWeight: "400" }}>
            Real-time intelligence across your organization's asset inventory
          </p>
        </div>

        {/* Row 2: Stat Cards */}
        <div className="animate-slide-up delay-100" style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "24px", marginBottom: "32px" }}>
          <StatCard label="Total Assets" value={summary?.total_assets} icon={Target} color="var(--accent-primary)" />
          <StatCard label="Total Scans" value={summary?.total_scans} icon={Activity} color="#3b82f6" />
          <StatCard label="Completed" value={summary?.completed_scans} icon={CheckCircle} color="var(--emerald)" />
          <StatCard label="Failed" value={summary?.failed_scans} icon={XCircle} color="var(--red)" />
        </div>

        {/* Row 3: Chart + Live Feed + Quick Scan */}
        <div className="animate-slide-up delay-200" style={{ display: "grid", gridTemplateColumns: "1.6fr 1fr 0.9fr", gap: "24px", marginBottom: "32px" }}>
          
          {/* Risk Distribution Chart */}
          <div className="glass-card" style={{ padding: "28px" }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "20px" }}>
              <h2 style={{ fontSize: "17px", fontWeight: "700", color: "var(--text-primary)" }}>Risk Distribution</h2>
              <a href="/reports" style={{ fontSize: 12, color: "var(--accent-primary)", textDecoration: "none", fontWeight: 600 }}>Analytics →</a>
            </div>
            {riskData.length > 0 ? (
              <ResponsiveContainer width="100%" height={180}>
                <BarChart data={riskData} barSize={36}>
                  <XAxis dataKey="name" tick={{ fill: "var(--text-secondary)", fontSize: 11, fontWeight: 500 }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fill: "var(--text-secondary)", fontSize: 11 }} axisLine={false} tickLine={false} />
                  <Tooltip contentStyle={{ background: "var(--bg-card)", border: "1px solid var(--border)", borderRadius: "10px" }} />
                  <Bar dataKey="count" radius={[6, 6, 0, 0]}>
                    {riskData.map((entry) => (
                      <Cell key={entry.name} fill={RISK_COLORS[entry.name] || "var(--text-muted)"} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div style={{ height: "180px", display: "flex", alignItems: "center", justifyContent: "center", color: "var(--text-muted)", fontSize: "13px" }}>No scan data yet</div>
            )}
          </div>

          {/* Live Threat Feed */}
          <div className="glass-card" style={{ padding: "0", overflow: "hidden", display: "flex", flexDirection: "column" }}>
            <div style={{ padding: "18px 20px", borderBottom: "1px solid var(--border)", display: "flex", alignItems: "center", gap: 8 }}>
              <div style={{ width: 8, height: 8, borderRadius: "50%", background: "var(--emerald)", boxShadow: "0 0 8px var(--emerald)", animation: "pulse-glow-border 2s infinite" }} />
              <h2 style={{ fontSize: "14px", fontWeight: "700" }}>Live Activity</h2>
            </div>
            <div style={{ flex: 1, overflowY: "auto", padding: "12px" }}>
              {liveEvents.length === 0 ? (
                <div style={{ padding: "24px", textAlign: "center", color: "var(--text-muted)", fontSize: 12 }}>No events yet</div>
              ) : liveEvents.map((ev, i) => (
                <div key={i} style={{
                  display: "flex", gap: 10, padding: "10px 8px", borderRadius: 8,
                  borderLeft: `3px solid ${ev.type === "alert" ? "var(--red)" : ev.type === "success" ? "var(--emerald)" : "var(--cyan)"}`,
                  background: "var(--bg-base)", marginBottom: 8,
                }}>
                  <div style={{ flex: 1 }}>
                    <div style={{ fontSize: 11, fontWeight: 600, color: "var(--text-primary)", lineHeight: 1.4 }}>{ev.message}</div>
                    {ev.time && <div style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 3 }}>
                      {new Date(ev.time).toLocaleTimeString()}
                    </div>}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Quick Scan Widget */}
          <div className="glass-card" style={{ padding: "28px", display: "flex", flexDirection: "column" }}>
            <h2 style={{ fontSize: "15px", fontWeight: "700", marginBottom: "6px", color: "var(--text-primary)" }}>Launch Scan</h2>
            <p style={{ fontSize: "12px", color: "var(--text-secondary)", marginBottom: "20px" }}>Trigger an on-demand security scan.</p>
            
            <form onSubmit={async (e) => {
              e.preventDefault();
              const target = (e.target as any).target.value;
              const tool = (e.target as any).tool.value;
              if (!target) return;
              
              const btn = (e.target as any).querySelector('button');
              btn.innerText = 'Scanning...';
              btn.disabled = true;
              
              try {
                const res = await fetch('/api/recon', {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
                  body: JSON.stringify({ target, tool })
                });
                if (res.status === 401) { Cookies.remove("token"); window.location.href = "/"; return; }
                const data = await res.json();
                if (res.ok && data.scan_id) router.push(`/scans/${data.scan_id}`);
                else alert(data.detail || 'Failed to launch scan');
                (e.target as any).reset();
              } catch (err) {
                alert('Failed to launch scan');
              } finally {
                btn.innerText = 'Launch Scan';
                btn.disabled = false;
              }
            }} style={{ display: 'flex', flexDirection: 'column', gap: '14px', flex: 1 }}>
              
              <div>
                <label style={{ display: "block", fontSize: "11px", fontWeight: "600", color: "var(--text-secondary)", marginBottom: "6px", textTransform: "uppercase", letterSpacing: "0.5px" }}>Target</label>
                <input name="target" type="text" placeholder="example.com" className="input-glass" style={{ width: "100%", padding: "10px 12px", fontSize: "13px" }} required />
              </div>
              
              <div>
                <label style={{ display: "block", fontSize: "11px", fontWeight: "600", color: "var(--text-secondary)", marginBottom: "6px", textTransform: "uppercase", letterSpacing: "0.5px" }}>Tool</label>
                <select name="tool" className="input-glass" style={{ width: "100%", padding: "10px 12px", fontSize: "13px", cursor: "pointer", appearance: "none" }}>
                  <option value="nmap">Nmap Port Scan</option>
                  <option value="subdomain">Subdomain Enum</option>
                  <option value="nuclei">Nuclei</option>
                  <option value="httpx">HTTPx</option>
                  <option value="nikto">Nikto</option>
                  <option value="trivy">Trivy</option>
                  <option value="grype">Grype</option>
                </select>
              </div>

              <div style={{ marginTop: "auto" }}>
                <button type="submit" className="btn-primary" style={{ width: "100%", padding: "12px", fontSize: "13px" }}>Launch Scan</button>
              </div>
            </form>
          </div>
        </div>

        {/* Row 4: Recent Scans Data Table */}
        <div className="glass-card animate-slide-up delay-300" style={{ padding: "0", overflow: "hidden" }}>
          <div style={{ padding: "24px 28px", borderBottom: "1px solid var(--border)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <h2 style={{ fontSize: "18px", fontWeight: "700", color: "var(--text-primary)" }}>Recent Scans</h2>
            <a href="/scans" style={{ fontSize: "13px", fontWeight: "600", color: "var(--accent-primary)", textDecoration: "none" }}>View All →</a>
          </div>
          
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", textAlign: "left" }}>
              <thead style={{ background: "var(--bg-base)" }}>
                <tr>
                  <th style={{ padding: "16px 28px", fontSize: "12px", fontWeight: "600", color: "var(--text-secondary)", textTransform: "uppercase", letterSpacing: "0.5px" }}>Target</th>
                  <th style={{ padding: "16px 28px", fontSize: "12px", fontWeight: "600", color: "var(--text-secondary)", textTransform: "uppercase", letterSpacing: "0.5px" }}>Tool</th>
                  <th style={{ padding: "16px 28px", fontSize: "12px", fontWeight: "600", color: "var(--text-secondary)", textTransform: "uppercase", letterSpacing: "0.5px" }}>Risk</th>
                  <th style={{ padding: "16px 28px", fontSize: "12px", fontWeight: "600", color: "var(--text-secondary)", textTransform: "uppercase", letterSpacing: "0.5px" }}>Status</th>
                  <th style={{ padding: "16px 28px", fontSize: "12px", fontWeight: "600", color: "var(--text-secondary)", textTransform: "uppercase", letterSpacing: "0.5px" }}>Date</th>
                </tr>
              </thead>
              <tbody>
                {recentScans.length === 0 ? (
                  <tr>
                    <td colSpan={5} style={{ padding: "40px", textAlign: "center", color: "var(--text-muted)", fontSize: "14px" }}>No recent scans found.</td>
                  </tr>
                ) : (
                  recentScans.map((scan, i) => (
                    <tr key={scan.scan_id}
                      onClick={() => router.push(`/scans/${scan.scan_id}`)}
                      style={{ borderTop: "1px solid var(--border)", transition: "background 0.15s", cursor: "pointer" }} 
                        onMouseEnter={e => e.currentTarget.style.background = "var(--bg-card-hover)"}
                        onMouseLeave={e => e.currentTarget.style.background = "transparent"}
                    >
                      <td style={{ padding: "16px 28px", fontFamily: "var(--font-mono)", fontSize: "14px", fontWeight: "500", color: "var(--text-primary)" }}>{scan.target}</td>
                      <td style={{ padding: "16px 28px", fontSize: "13px", fontWeight: "600", color: "var(--accent-primary)" }}>{scan.tool_used.toUpperCase()}</td>
                      <td style={{ padding: "16px 28px" }}>
                        {scan.risk_score ? (
                          <span className={`risk-${scan.risk_score.toLowerCase()}`} style={{ fontSize: "11px", fontWeight: "700", padding: "4px 8px", borderRadius: "6px" }}>
                            {scan.risk_score}
                          </span>
                        ) : (
                          <span style={{ color: "var(--text-muted)", fontSize: "12px" }}>—</span>
                        )}
                      </td>
                      <td style={{ padding: "16px 28px" }}>
                        <span className={`status-${scan.status}`} style={{ fontSize: "12px", fontWeight: "600", textTransform: "capitalize", display: "flex", alignItems: "center", gap: "6px" }}>
                          {scan.status === 'completed' && <CheckCircle size={14} />}
                          {scan.status === 'failed' && <XCircle size={14} />}
                          {scan.status === 'running' && <Activity size={14} />}
                          {scan.status === 'queued' && <Clock size={14} />}
                          {scan.status}
                        </span>
                      </td>
                      <td style={{ padding: "16px 28px", fontSize: "13px", color: "var(--text-secondary)" }}>
                        {new Date(scan.started_at || Date.now()).toLocaleDateString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

      </main>
    </div>
  );
}
