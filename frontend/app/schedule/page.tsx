"use client";
import { useState, useEffect } from "react";
import Cookies from "js-cookie";
import { Calendar, Plus, Clock, Target, Play } from "lucide-react";
import Sidebar from "../components/Sidebar";

const API = "";

export default function SchedulePage() {
  const [schedules, setSchedules] = useState<any[]>([]);
  const [target, setTarget] = useState("");
  const [tool, setTool] = useState("nmap");
  const [cron, setCron] = useState("0 0 * * *"); // Default daily
  const [loading, setLoading] = useState(false);
  const token = Cookies.get("token");

  const fetchSchedules = () => {
    fetch(`${API}/api/scans/schedule`, {
      headers: { "Authorization": `Bearer ${token}` }
    })
      .then(res => res.json())
      .then(data => setSchedules(Array.isArray(data) ? data : []))
      .catch(console.error);
  };

  useEffect(() => {
    if (!token) { window.location.href = "/"; return; }
    fetchSchedules();
  }, [token]);

  const handleSchedule = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    try {
      const res = await fetch(`${API}/api/scans/schedule`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`
        },
        body: JSON.stringify({ target, tool, cron_expression: cron })
      });
      if (res.ok) {
        setTarget("");
        fetchSchedules();
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ display: "flex", minHeight: "100vh" }}>
      <Sidebar />
      <main style={{ marginLeft: "240px", flex: 1, padding: "40px" }}>
        
        <div style={{ marginBottom: "40px" }}>
          <h1 style={{ fontSize: "32px", fontWeight: "800", letterSpacing: "-1px" }}>Continuous <span className="text-gradient">Scanning</span></h1>
          <p style={{ color: "var(--text-secondary)", marginTop: "8px", fontSize: "16px", fontWeight: "400" }}>
            Automate your attack surface monitoring with recurring scans
          </p>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 2fr", gap: "32px" }}>
          
          {/* Create Schedule Form */}
          <div className="glass-card" style={{ padding: "32px", alignSelf: "start" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "12px", marginBottom: "24px" }}>
              <div style={{ padding: "8px", background: "rgba(16, 185, 129, 0.1)", borderRadius: "10px" }}>
                <Plus size={20} color="var(--emerald)" />
              </div>
              <h2 style={{ fontSize: "18px", fontWeight: "700" }}>New Schedule</h2>
            </div>
            
            <form onSubmit={handleSchedule} style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
              <div>
                <label style={{ display: "block", fontSize: "13px", fontWeight: "600", marginBottom: "8px", color: "var(--text-secondary)" }}>Target Domain / IP</label>
                <div style={{ position: "relative" }}>
                  <Target size={16} color="var(--text-muted)" style={{ position: "absolute", left: "14px", top: "14px" }} />
                  <input
                    type="text" required
                    value={target} onChange={e => setTarget(e.target.value)}
                    placeholder="example.com"
                    className="input-glass"
                    style={{ width: "100%", padding: "12px 14px 12px 42px", borderRadius: "10px" }}
                  />
                </div>
              </div>

              <div>
                <label style={{ display: "block", fontSize: "13px", fontWeight: "600", marginBottom: "8px", color: "var(--text-secondary)" }}>Scan Tool</label>
                <select 
                  value={tool} onChange={e => setTool(e.target.value)}
                  className="input-glass"
                  style={{ width: "100%", padding: "12px 14px", borderRadius: "10px", appearance: "none" }}
                >
                  <option value="nmap" style={{background: "#1e1e24"}}>Nmap Port Scan</option>
                  <option value="subdomain" style={{background: "#1e1e24"}}>Subdomain Enum</option>
                  <option value="masscan" style={{background: "#1e1e24"}}>Masscan</option>
                  <option value="httpx" style={{background: "#1e1e24"}}>HTTPx</option>
                  <option value="amass" style={{background: "#1e1e24"}}>Amass</option>
                  <option value="sublist3r" style={{background: "#1e1e24"}}>Sublist3r</option>
                  <option value="nuclei" style={{background: "#1e1e24"}}>Nuclei</option>
                  <option value="nikto" style={{background: "#1e1e24"}}>Nikto</option>
                  <option value="trivy" style={{background: "#1e1e24"}}>Trivy</option>
                  <option value="grype" style={{background: "#1e1e24"}}>Grype</option>
                  <option value="ffuf" style={{background: "#1e1e24"}}>FFuF</option>
                  <option value="gobuster" style={{background: "#1e1e24"}}>Gobuster</option>
                  <option value="sqlmap" style={{background: "#1e1e24"}}>SQLMap</option>
                  <option value="wpscan" style={{background: "#1e1e24"}}>WPScan</option>
                  <option value="zap" style={{background: "#1e1e24"}}>OWASP ZAP</option>
                </select>
              </div>

              <div>
                <label style={{ display: "block", fontSize: "13px", fontWeight: "600", marginBottom: "8px", color: "var(--text-secondary)" }}>Cron Expression</label>
                <div style={{ position: "relative" }}>
                  <Calendar size={16} color="var(--text-muted)" style={{ position: "absolute", left: "14px", top: "14px" }} />
                  <input
                    type="text" required
                    value={cron} onChange={e => setCron(e.target.value)}
                    className="input-glass mono"
                    style={{ width: "100%", padding: "12px 14px 12px 42px", borderRadius: "10px" }}
                  />
                </div>
                <div style={{ fontSize: "11px", color: "var(--text-muted)", marginTop: "6px" }}>
                  Examples: <code>0 0 * * *</code> (Daily), <code>0 * * * *</code> (Hourly)
                </div>
              </div>

              <button type="submit" disabled={loading || !target} className="btn-primary" style={{ width: "100%", padding: "14px", marginTop: "8px" }}>
                {loading ? "Scheduling..." : "Create Schedule"}
              </button>
            </form>
          </div>

          {/* Scheduled Scans List */}
          <div className="glass-card" style={{ padding: "32px" }}>
             <h2 style={{ fontSize: "18px", fontWeight: "700", marginBottom: "24px" }}>Active Schedules</h2>
             
             <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
               {schedules.length === 0 ? (
                 <div style={{ textAlign: "center", padding: "40px", color: "var(--text-muted)" }}>
                   No scheduled scans yet
                 </div>
               ) : (
                 schedules.map(s => (
                   <div key={s.id} className="glass-panel hover-lift" style={{
                     padding: "20px", borderRadius: "12px", display: "flex", justifyContent: "space-between", alignItems: "center"
                   }}>
                     <div>
                       <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "6px" }}>
                         <span style={{ fontSize: "16px", fontWeight: "700", fontFamily: "var(--font-mono)" }}>{s.target}</span>
                         <span style={{ fontSize: "11px", fontWeight: "800", padding: "4px 8px", background: "var(--bg-surface)", borderRadius: "6px", color: "var(--accent-primary)" }}>{s.tool.toUpperCase()}</span>
                       </div>
                       <div style={{ display: "flex", alignItems: "center", gap: "16px", fontSize: "13px", color: "var(--text-secondary)" }}>
                         <span style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                           <Clock size={14} /> Cron: <code style={{ color: "var(--emerald)" }}>{s.cron_expression}</code>
                         </span>
                       </div>
                     </div>
                     <div style={{ textAlign: "right" }}>
                        <div style={{ fontSize: "12px", color: "var(--text-muted)", marginBottom: "4px" }}>Next Run</div>
                        <div style={{ fontSize: "14px", fontWeight: "600", color: "var(--text-primary)" }}>
                          {new Date(s.next_run).toLocaleString()}
                        </div>
                     </div>
                   </div>
                 ))
               )}
             </div>
          </div>
        </div>
      </main>
    </div>
  );
}
