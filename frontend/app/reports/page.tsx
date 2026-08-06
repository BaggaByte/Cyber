"use client";
import { useState, useEffect } from "react";
import Cookies from "js-cookie";
import {
  BarChart2, TrendingUp, Target, Shield, Download, RefreshCw,
  AlertTriangle, CheckCircle, Cpu, Globe, Layers, Activity
} from "lucide-react";
import {
  AreaChart, Area, BarChart, Bar, XAxis, YAxis, Tooltip,
  ResponsiveContainer, Cell, PieChart, Pie, Legend
} from "recharts";
import Sidebar from "../components/Sidebar";

const API = "";

const RISK_COLORS: Record<string, string> = {
  CRITICAL: "#dc2626", HIGH: "#d97706",
  MEDIUM: "#f04e23", LOW: "#10b981", INFO: "#94a3b8",
};

const TOOL_COLORS = [
  "var(--accent-primary)", "#3b82f6", "#8b5cf6",
  "#10b981", "#f59e0b", "#06b6d4"
];

function MetricCard({ label, value, sub, icon: Icon, color }: any) {
  return (
    <div className="glass-card hover-lift" style={{ padding: 24, display: "flex", alignItems: "center", gap: 18 }}>
      <div className="animate-pulse-glow" style={{
        width: 52, height: 52, borderRadius: "50%",
        background: `${color}12`, border: `2px solid ${color}25`,
        display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0,
      }}>
        <Icon size={22} color={color} />
      </div>
      <div>
        <div style={{ fontSize: 30, fontWeight: 800, color: "var(--text-primary)", letterSpacing: "-1px" }}>{value ?? "—"}</div>
        <div style={{ fontSize: 13, color: "var(--text-secondary)", fontWeight: 600, marginTop: 2 }}>{label}</div>
        {sub && <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 3 }}>{sub}</div>}
      </div>
    </div>
  );
}

const CUSTOM_TOOLTIP = ({ active, payload, label }: any) => {
  if (active && payload && payload.length) {
    return (
      <div className="glass-card" style={{ padding: "10px 14px", fontSize: 13 }}>
        <div style={{ fontWeight: 700, marginBottom: 4 }}>{label}</div>
        {payload.map((p: any) => (
          <div key={p.name} style={{ color: p.color }}>
            {p.name}: <strong>{p.value}</strong>
          </div>
        ))}
      </div>
    );
  }
  return null;
};

export default function ReportsPage() {
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const token = Cookies.get("token");

  const fetchData = () => {
    if (!token) { window.location.href = "/"; return; }
    setLoading(true);
    fetch(`${API}/api/reports/summary`, { headers: { Authorization: `Bearer ${token}` } })
      .then(r => r.json())
      .then(d => { setData(d); setLoading(false); })
      .catch(() => setLoading(false));
  };

  useEffect(() => { fetchData(); }, []);

  const riskData = data?.risk_breakdown
    ? Object.entries(data.risk_breakdown).map(([k, v]) => ({ name: k, value: v as number, color: RISK_COLORS[k] }))
    : [];
  const riskDataFiltered = riskData.filter(d => d.value > 0);

  const criticalCount = data?.risk_breakdown?.CRITICAL ?? 0;
  const highCount = data?.risk_breakdown?.HIGH ?? 0;

  return (
    <div style={{ display: "flex", minHeight: "100vh" }}>
      <Sidebar />
      <main style={{ marginLeft: 240, flex: 1, padding: "40px" }}>

        {/* Header */}
        <div className="animate-slide-up" style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", marginBottom: 32 }}>
          <div>
            <h1 style={{ fontSize: 32, fontWeight: 800, letterSpacing: "-1px" }}>
              Reports &amp; <span className="text-gradient">Analytics</span>
            </h1>
            <p style={{ color: "var(--text-secondary)", marginTop: 8, fontSize: 15 }}>
              Organization-wide security posture, trends, and scan intelligence
            </p>
          </div>
          <div style={{ display: "flex", gap: 10 }}>
            <button onClick={fetchData} style={{
              display: "flex", alignItems: "center", gap: 8,
              padding: "10px 16px", borderRadius: 8, cursor: "pointer",
              background: "white", border: "1px solid var(--border)",
              color: "var(--text-secondary)", fontSize: 13, fontWeight: 600,
              fontFamily: "inherit",
            }}>
              <RefreshCw size={14} style={{ animation: loading ? "spin-slow 1s linear infinite" : "none" }} />
              Refresh
            </button>
            <button
              onClick={() => window.print()}
              className="btn-primary"
              style={{ display: "flex", alignItems: "center", gap: 8, padding: "10px 20px" }}>
              <Download size={14} />
              Export Report
            </button>
          </div>
        </div>

        {/* Metric Cards Row */}
        <div className="animate-slide-up delay-100" style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 20, marginBottom: 28 }}>
          <MetricCard label="Total Scans" value={data?.total_scans} icon={Activity} color="var(--accent-primary)" />
          <MetricCard label="Assets Monitored" value={data?.total_assets} icon={Target} color="#3b82f6" />
          <MetricCard
            label="Critical Findings" value={criticalCount}
            sub={criticalCount > 0 ? "Immediate action required" : "All clear"}
            icon={AlertTriangle} color={criticalCount > 0 ? "#dc2626" : "#10b981"}
          />
          <MetricCard
            label="High Risk" value={highCount}
            sub={(highCount > 0) ? "Review within 24h" : "None detected"}
            icon={Shield} color={highCount > 0 ? "#d97706" : "#10b981"}
          />
        </div>

        {/* Main Charts Row */}
        <div className="animate-slide-up delay-200" style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 20, marginBottom: 20 }}>

          {/* Area Chart: Scan Trend */}
          <div className="glass-card" style={{ padding: 28 }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 24 }}>
              <div>
                <h2 style={{ fontSize: 17, fontWeight: 700 }}>Scan Volume — Last 7 Days</h2>
                <p style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 3 }}>Daily completed scans</p>
              </div>
              <TrendingUp size={18} color="var(--accent-primary)" />
            </div>
            {data?.daily_trend ? (
              <ResponsiveContainer width="100%" height={220}>
                <AreaChart data={data.daily_trend} margin={{ top: 5, right: 5, bottom: 0, left: 0 }}>
                  <defs>
                    <linearGradient id="scanGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="var(--accent-primary)" stopOpacity={0.2} />
                      <stop offset="95%" stopColor="var(--accent-primary)" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="date" tick={{ fill: "var(--text-muted)", fontSize: 11 }} axisLine={false} tickLine={false} />
                  <YAxis allowDecimals={false} tick={{ fill: "var(--text-muted)", fontSize: 11 }} axisLine={false} tickLine={false} />
                  <Tooltip content={<CUSTOM_TOOLTIP />} />
                  <Area type="monotone" dataKey="scans" stroke="var(--accent-primary)" strokeWidth={2.5}
                    fill="url(#scanGrad)" dot={{ fill: "var(--accent-primary)", strokeWidth: 0, r: 4 }}
                    activeDot={{ r: 6, fill: "var(--accent-primary)" }}
                  />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div style={{ height: 220, display: "flex", alignItems: "center", justifyContent: "center", color: "var(--text-muted)", fontSize: 13 }}>
                No trend data yet
              </div>
            )}
          </div>

          {/* Pie: Risk Breakdown */}
          <div className="glass-card" style={{ padding: 28 }}>
            <h2 style={{ fontSize: 17, fontWeight: 700, marginBottom: 6 }}>Risk Distribution</h2>
            <p style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 20 }}>Across all completed scans</p>
            {riskDataFiltered.length > 0 ? (
              <ResponsiveContainer width="100%" height={200}>
                <PieChart>
                  <Pie data={riskDataFiltered} dataKey="value" nameKey="name" cx="50%" cy="50%" innerRadius={55} outerRadius={85} paddingAngle={3}>
                    {riskDataFiltered.map((entry) => (
                      <Cell key={entry.name} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip formatter={(v: any, n: any) => [v, n]} />
                  <Legend iconType="circle" iconSize={8} wrapperStyle={{ fontSize: 12 }} />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div style={{ height: 200, display: "flex", alignItems: "center", justifyContent: "center", color: "var(--text-muted)", fontSize: 13 }}>
                No scan data yet
              </div>
            )}
          </div>
        </div>

        {/* Second Row: Top Assets + Top Tools */}
        <div className="animate-slide-up delay-300" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20, marginBottom: 20 }}>

          {/* Top Assets Table */}
          <div className="glass-card" style={{ padding: 0, overflow: "hidden" }}>
            <div style={{ padding: "20px 24px", borderBottom: "1px solid var(--border)", display: "flex", alignItems: "center", gap: 10 }}>
              <Target size={16} color="var(--accent-primary)" />
              <h2 style={{ fontSize: 15, fontWeight: 700 }}>Most Scanned Assets</h2>
            </div>
            {data?.top_assets && data.top_assets.length > 0 ? (
              <div>
                {data.top_assets.map((asset: any, i: number) => {
                  const pct = data.top_assets[0].scan_count > 0 ? (asset.scan_count / data.top_assets[0].scan_count) * 100 : 0;
                  return (
                    <div key={i} style={{ padding: "14px 24px", borderBottom: i < data.top_assets.length - 1 ? "1px solid var(--border)" : "none" }}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
                        <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 13, fontWeight: 600, color: "var(--text-primary)" }}>
                          {asset.target}
                        </span>
                        <span style={{ fontSize: 12, fontWeight: 700, color: "var(--accent-primary)" }}>
                          {asset.scan_count} scans
                        </span>
                      </div>
                      <div style={{ height: 4, background: "var(--bg-base)", borderRadius: 2, overflow: "hidden" }}>
                        <div style={{ height: "100%", width: `${pct}%`, background: "var(--accent-primary)", borderRadius: 2, transition: "width 0.8s ease" }} />
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div style={{ padding: 32, textAlign: "center", color: "var(--text-muted)", fontSize: 13 }}>No scan data yet</div>
            )}
          </div>

          {/* Top Tools Bar Chart */}
          <div className="glass-card" style={{ padding: 28 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 20 }}>
              <Cpu size={16} color="#8b5cf6" />
              <h2 style={{ fontSize: 15, fontWeight: 700 }}>Tool Usage</h2>
            </div>
            {data?.top_tools && data.top_tools.length > 0 ? (
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={data.top_tools} barSize={32} layout="vertical" margin={{ left: 0 }}>
                  <XAxis type="number" tick={{ fill: "var(--text-muted)", fontSize: 11 }} axisLine={false} tickLine={false} />
                  <YAxis type="category" dataKey="tool" tick={{ fill: "var(--text-secondary)", fontSize: 12, fontWeight: 600 }} axisLine={false} tickLine={false} width={72} />
                  <Tooltip content={<CUSTOM_TOOLTIP />} />
                  <Bar dataKey="count" radius={[0, 6, 6, 0]}>
                    {data.top_tools.map((_: any, i: number) => (
                      <Cell key={i} fill={TOOL_COLORS[i % TOOL_COLORS.length]} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div style={{ height: 200, display: "flex", alignItems: "center", justifyContent: "center", color: "var(--text-muted)", fontSize: 13 }}>No data yet</div>
            )}
          </div>
        </div>

        {/* Security Posture Score Card */}
        <div className="glass-card animate-slide-up delay-400" style={{ padding: 28, display: "grid", gridTemplateColumns: "auto 1fr", gap: 32, alignItems: "center" }}>
          <div>
            {/* Security Score */}
            {(() => {
              const total = data?.total_scans || 0;
              const crit = data?.risk_breakdown?.CRITICAL || 0;
              const high = data?.risk_breakdown?.HIGH || 0;
              const score = total === 0 ? 0 : Math.max(0, Math.round(100 - (crit * 20 + high * 10) / Math.max(total, 1)));
              const color = score >= 80 ? "#10b981" : score >= 60 ? "#f59e0b" : "#ef4444";
              const label = score >= 80 ? "STRONG" : score >= 60 ? "MODERATE" : "WEAK";
              return (
                <div style={{ textAlign: "center" }}>
                  <svg width={120} height={120} viewBox="0 0 120 120">
                    <circle cx={60} cy={60} r={50} fill="none" stroke="var(--border)" strokeWidth={10} />
                    <circle cx={60} cy={60} r={50} fill="none" stroke={color} strokeWidth={10}
                      strokeDasharray={`${(score / 100) * 314} 314`}
                      strokeLinecap="round" transform="rotate(-90 60 60)"
                      style={{ transition: "all 1.2s ease" }}
                    />
                    <text x={60} y={56} textAnchor="middle" fill={color} fontSize={24} fontWeight={800} fontFamily="Outfit,sans-serif">{score}</text>
                    <text x={60} y={72} textAnchor="middle" fill="var(--text-muted)" fontSize={9} fontFamily="Outfit,sans-serif">/ 100</text>
                  </svg>
                  <div style={{ fontSize: 12, fontWeight: 700, color, marginTop: 8, letterSpacing: "1px" }}>{label}</div>
                </div>
              );
            })()}
          </div>
          <div>
            <h2 style={{ fontSize: 20, fontWeight: 800, marginBottom: 6 }}>Security Posture Score</h2>
            <p style={{ fontSize: 13, color: "var(--text-secondary)", marginBottom: 20 }}>
              Composite score calculated from scan volume, critical/high findings ratio, and asset coverage.
            </p>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 12 }}>
              {[
                { label: "Scans Run", value: data?.total_scans ?? 0, good: true },
                { label: "Critical Issues", value: data?.risk_breakdown?.CRITICAL ?? 0, good: (data?.risk_breakdown?.CRITICAL ?? 0) === 0 },
                { label: "High Issues", value: data?.risk_breakdown?.HIGH ?? 0, good: (data?.risk_breakdown?.HIGH ?? 0) === 0 },
              ].map(({ label, value, good }) => (
                <div key={label} style={{ padding: "12px 16px", borderRadius: 8, background: good ? "rgba(16,185,129,0.06)" : "rgba(239,68,68,0.06)", border: `1px solid ${good ? "rgba(16,185,129,0.2)" : "rgba(239,68,68,0.2)"}` }}>
                  <div style={{ fontSize: 20, fontWeight: 800, color: good ? "#10b981" : "#dc2626" }}>{value}</div>
                  <div style={{ fontSize: 11, color: "var(--text-secondary)", marginTop: 4, fontWeight: 600 }}>{label}</div>
                </div>
              ))}
            </div>
          </div>
        </div>

      </main>
    </div>
  );
}
