"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";
import Cookies from "js-cookie";
import {
  BrainCircuit, Zap, ChevronRight, Loader,
  Globe, Server, Search, Bug, Package, Crosshair,
  CheckCircle, ExternalLink, Code, Lock
} from "lucide-react";
import Sidebar from "../components/Sidebar";

import { toast } from "sonner";
const TOOL_CATALOG = [
  {
    category: "Port Scanning",
    color: "#3b82f6",
    icon: Server,
    tools: [
      { name: "nmap",    desc: "Network port scanner — service & OS fingerprinting",   badges: ["TCP","UDP","SV"] },
      { name: "masscan", desc: "Ultra-fast internet-scale scanner — 10M pkts/sec",      badges: ["HIGH-SPEED","IPv4"] },
    ]
  },
  {
    category: "DNS & Recon",
    color: "#8b5cf6",
    icon: Globe,
    tools: [
      { name: "subdomain", desc: "Native DNS enumeration of common subdomains",          badges: ["PASSIVE"] },
      { name: "amass",     desc: "Comprehensive subdomain enum via DNS, certs, APIs",    badges: ["PASSIVE","ACTIVE"] },
      { name: "sublist3r", desc: "Fast subdomain search via search engines",              badges: ["OSINT"] },
      { name: "httpx",     desc: "HTTP probing — WAF, tech stack, live host detection",  badges: ["HTTP","HTTPS"] },
    ]
  },
  {
    category: "Vulnerability Scanning",
    color: "#ef4444",
    icon: Bug,
    tools: [
      { name: "nuclei", desc: "Template-based CVE & misconfiguration scanner",           badges: ["CVE","CRITICAL"] },
      { name: "nikto",  desc: "Web server misconfig, dangerous files & header checks",   badges: ["HTTP"] },
    ]
  },
  {
    category: "Web Fuzzing",
    color: "#f59e0b",
    icon: Search,
    tools: [
      { name: "ffuf",     desc: "Fast web fuzzer — hidden dirs, endpoints, API paths",  badges: ["FUZZ"] },
      { name: "gobuster", desc: "Directory & file brute-forcer for web targets",         badges: ["DIR","DNS"] },
    ]
  },
  {
    category: "Container & SCA",
    color: "#10b981",
    icon: Package,
    tools: [
      { name: "trivy", desc: "Container image & filesystem CVE scanner",                 badges: ["CVE","IaC"] },
      { name: "grype", desc: "Software composition analysis — package vulnerabilities",  badges: ["SCA","SBOM"] },
    ]
  },
  {
    category: "Advanced Pentesting",
    color: "#ec4899",
    icon: Code,
    tools: [
      { name: "sqlmap", desc: "Automatic SQL injection & database takeover tool",        badges: ["SQLi", "LEVEL 1-5"] },
      { name: "wpscan", desc: "WordPress vulnerability & user enumeration scanner",      badges: ["CMS"] },
    ]
  },
  {
    category: "TLS / Certificate",
    color: "#06b6d4",
    icon: Lock,
    tools: [
      { name: "certcheck", desc: "OpenSSL-powered TLS inspector — SANs, expiry, cipher, chain", badges: ["TLS", "SANs", "EXPIRY"] },
    ]
  },
];

const GOAL_PRESETS = [
  { label: "Full Attack Surface Map", goal: "Map the full attack surface including all open ports, exposed subdomains and live web services", emoji: "🗺️", tags: ["nmap","masscan","subdomain","httpx"] },
  { label: "Web Application Audit",   goal: "Perform a comprehensive web audit including vulnerability scanning, directory fuzzing and header analysis", emoji: "🌐", tags: ["nikto","nuclei","ffuf"] },
  { label: "Rapid Port Discovery",    goal: "High-speed enumerate all open ports on the target using masscan and nmap service detection", emoji: "⚡", tags: ["masscan","nmap"] },
  { label: "Subdomain Discovery",     goal: "Discover all subdomains and map the DNS attack surface using passive and active enumeration", emoji: "🕸️", tags: ["amass","sublist3r","subdomain"] },
  { label: "CVE Vulnerability Scan",  goal: "Scan for known CVEs and critical vulnerabilities on all exposed web services", emoji: "⚠️", tags: ["nuclei","nikto"] },
  { label: "Container Security",      goal: "Scan container images and infrastructure for CVEs, misconfigurations and supply chain risks", emoji: "📦", tags: ["trivy","grype"] },
  { label: "SQL Injection Test",      goal: "Test the target web application for SQL injection vulnerabilities",                                       emoji: "💉", tags: ["sqlmap"] },
  { label: "Stealth Recon",           goal: "Quietly identify open ports and subdomains without triggering IDS using slow scan techniques",               emoji: "🥷", tags: ["nmap", "amass"] },
  { label: "TLS Certificate Audit",   goal: "Inspect the TLS certificate chain, check for expiry, weak ciphers, and enumerate SANs for hidden assets",   emoji: "🔐", tags: ["certcheck"] },
];

function ToolBadge({ text, color }: { text: string; color: string }) {
  return (
    <span style={{
      fontSize: 9, fontWeight: 700, padding: "2px 6px", borderRadius: 4,
      background: `${color}18`, color: color, border: `1px solid ${color}30`,
      letterSpacing: "0.5px", textTransform: "uppercase"
    }}>{text}</span>
  );
}

interface OrchestrationResult {
  mission_id?: string;
  planner_reasoning?: string;
  tasks_dispatched?: number;
  scans?: Array<{ scan_id: string; tool?: string; target?: string; risk_score?: string; status?: string }>;
}

export default function OrchestratePage() {
  const [goal, setGoal]       = useState("");
  const [target, setTarget]   = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult]   = useState<OrchestrationResult | null>(null);
  const [error, setError]     = useState("");
  const [activePreset, setActivePreset] = useState<string | null>(null);
  const router = useRouter();
  const token = Cookies.get("token");

  const handleOrchestrate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!goal || !target) return;
    setLoading(true); setResult(null); setError("");

    try {
      const res = await fetch(`/api/orchestrate`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Authorization": `Bearer ${token}` },
        body: JSON.stringify({ goal, target }),
      });
      if (!res.ok) { const d = await res.json(); throw new Error(d.detail || "Orchestration failed"); }
      const data = await res.json();
      setResult(data);
      toast.success("Agentic swarm deployed successfully!");
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setError(msg);
      toast.error(msg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ display: "flex", minHeight: "100vh" }}>
      <Sidebar />
      <main style={{ marginLeft: 240, flex: 1, padding: "32px 40px", maxWidth: "calc(100vw - 240px)" }}>

        {/* Header */}
        <div className="animate-slide-up" style={{ marginBottom: 32 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 14, marginBottom: 8 }}>
            <div style={{
              width: 44, height: 44, borderRadius: 12,
              background: "linear-gradient(135deg, #3b82f6, #8b5cf6)",
              display: "flex", alignItems: "center", justifyContent: "center",
              boxShadow: "0 0 20px rgba(139,92,246,0.4)"
            }}>
              <BrainCircuit size={22} color="#fff" />
            </div>
            <div>
              <h1 style={{ fontSize: 28, fontWeight: 800, letterSpacing: "-1px" }}>
                AI <span className="text-gradient">Orchestrator</span>
              </h1>
              <p style={{ color: "var(--text-secondary)", fontSize: 13, marginTop: 2 }}>
                Describe a security goal — the Planner AI deploys the optimal agent swarm automatically
              </p>
            </div>
          </div>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 360px", gap: 28, alignItems: "start" }}>

          {/* ── Left Column ── */}
          <div style={{ display: "flex", flexDirection: "column", gap: 24 }}>

            {/* Mission Form */}
            <div className="glass-card animate-slide-up delay-100" style={{ padding: 28 }}>
              <form onSubmit={handleOrchestrate}>
                <label style={{ fontSize: 11, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.08em", display: "block", marginBottom: 8, fontWeight: 600 }}>
                  Primary Target
                </label>
                <input
                  type="text" value={target} onChange={e => setTarget(e.target.value)}
                  placeholder="e.g. scanme.nmap.org  or  192.168.1.0/24"
                  className="input-glass"
                  style={{ width: "100%", padding: "12px 16px", fontSize: 14, fontFamily: "monospace", marginBottom: 20 }}
                />

                <label style={{ fontSize: 11, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.08em", display: "block", marginBottom: 8, fontWeight: 600 }}>
                  Security Mission Goal
                </label>
                <textarea
                  value={goal} onChange={e => setGoal(e.target.value)}
                  placeholder="Describe your objective in plain English. E.g. 'Find all open ports, discover subdomains and scan for critical CVEs'..."
                  rows={4}
                  className="input-glass"
                  style={{ width: "100%", padding: "12px 16px", fontSize: 14, resize: "vertical", marginBottom: 24, fontFamily: "inherit" }}
                />

                <button type="submit" disabled={loading || !goal || !target} style={{
                  display: "flex", alignItems: "center", gap: 10,
                  background: loading ? "var(--bg-base)" : "linear-gradient(135deg, #3b82f6, #8b5cf6)",
                  border: "none", borderRadius: 10, padding: "14px 28px",
                  color: loading ? "var(--text-muted)" : "#fff", fontSize: 14, fontWeight: 700,
                  cursor: loading || !goal || !target ? "not-allowed" : "pointer",
                  opacity: !goal || !target ? 0.5 : 1, transition: "all 0.2s",
                  boxShadow: loading || !goal || !target ? "none" : "0 0 24px rgba(139,92,246,0.4)"
                }}>
                  {loading ? <Loader size={16} style={{ animation: "spin-slow 1s linear infinite" }} /> : <BrainCircuit size={16} />}
                  {loading ? "AI Planning — Dispatching Agent Swarm..." : "Launch Agentic Sequence"}
                </button>
              </form>
            </div>

            {/* Error */}
            {error && (
              <div style={{
                background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.3)",
                borderRadius: 12, padding: "14px 18px", color: "var(--red)", fontSize: 13
              }}>
                ⚠️ {error}
              </div>
            )}

            {/* Result */}
            {result && (
              <div className="glass-card animate-slide-up" style={{ padding: 28, border: "1px solid rgba(139,92,246,0.35)", boxShadow: "0 0 32px rgba(139,92,246,0.12)" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 20 }}>
                  <div style={{ width: 10, height: 10, borderRadius: "50%", background: "var(--emerald)", boxShadow: "0 0 10px var(--emerald)" }} />
                  <h3 style={{ fontSize: 16, fontWeight: 700 }}>Agentic Sequence Initiated</h3>
                  <span style={{ marginLeft: "auto", fontSize: 11, color: "var(--text-muted)", fontFamily: "monospace" }}>
                    {result.tasks_dispatched} agents dispatched · Mission #{result.mission_id}
                  </span>
                </div>

                {result.planner_reasoning && (
                  <div style={{
                    background: "var(--bg-base)", borderRadius: 8, padding: "12px 16px",
                    fontSize: 12, color: "var(--text-secondary)", marginBottom: 20,
                    borderLeft: "3px solid #8b5cf6", lineHeight: 1.7
                  }}>
                    <span style={{ color: "#8b5cf6", fontWeight: 700 }}>🧠 AI Planner: </span>{result.planner_reasoning}
                  </div>
                )}

                <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                  {result.scans?.map((s, i) => (
                    <div key={s.scan_id} style={{
                      display: "flex", alignItems: "center", gap: 12,
                      background: "var(--bg-base)", borderRadius: 8, padding: "12px 16px",
                      border: "1px solid var(--border)"
                    }}>
                      <span style={{ fontSize: 11, color: "var(--text-muted)", width: 20, fontWeight: 700 }}>{i + 1}.</span>
                      <ChevronRight size={12} color="#3b82f6" />
                      <span style={{ fontFamily: "monospace", fontSize: 13, fontWeight: 700, color: "var(--accent-primary)", flex: 1 }}>{s.tool?.toUpperCase()}</span>
                      <span style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "monospace" }}>{s.target}</span>
                      <button
                        onClick={() => router.push(`/scans/${s.scan_id}`)}
                        style={{
                          display: "flex", alignItems: "center", gap: 5, padding: "4px 10px",
                          background: "rgba(59,130,246,0.08)", color: "#3b82f6",
                          border: "1px solid rgba(59,130,246,0.2)", borderRadius: 6,
                          fontSize: 11, fontWeight: 600, cursor: "pointer"
                        }}>
                        #{s.scan_id} <ExternalLink size={11} />
                      </button>
                    </div>
                  ))}
                </div>

                <button
                  onClick={() => router.push(`/missions/${result.mission_id}`)}
                  className="btn-primary"
                  style={{ marginTop: 20, display: "flex", alignItems: "center", gap: 8, padding: "10px 18px", fontSize: 13 }}>
                  <Crosshair size={14} /> View Mission Dashboard
                </button>
              </div>
            )}

            {/* Tool Capability Matrix */}
            <div className="animate-slide-up delay-200">
              <h2 style={{ fontSize: 16, fontWeight: 700, marginBottom: 16, color: "var(--text-primary)" }}>
                🛠️ Available Tool Arsenal ({TOOL_CATALOG.reduce((a, c) => a + c.tools.length, 0)} tools)
              </h2>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
                {TOOL_CATALOG.map(({ category, color, icon: Icon, tools }) => (
                  <div key={category} className="glass-card" style={{ padding: "20px" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 14 }}>
                      <div style={{ width: 28, height: 28, borderRadius: 7, background: `${color}18`, display: "flex", alignItems: "center", justifyContent: "center" }}>
                        <Icon size={14} color={color} />
                      </div>
                      <span style={{ fontWeight: 700, fontSize: 13, color: "var(--text-primary)" }}>{category}</span>
                    </div>
                    <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                      {tools.map(({ name, desc, badges }) => (
                        <div key={name} style={{ padding: "10px 12px", background: "var(--bg-base)", borderRadius: 8, border: "1px solid var(--border)" }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 5 }}>
                            <span style={{ fontFamily: "monospace", fontWeight: 700, fontSize: 12, color }}>
                              {name.toUpperCase()}
                            </span>
                            <div style={{ display: "flex", gap: 4, marginLeft: "auto" }}>
                              {badges.map(b => <ToolBadge key={b} text={b} color={color} />)}
                            </div>
                          </div>
                          <div style={{ fontSize: 11, color: "var(--text-muted)", lineHeight: 1.5 }}>{desc}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* ── Right Column: Presets ── */}
          <div style={{ display: "flex", flexDirection: "column", gap: 16, position: "sticky", top: 32 }}>
            <div className="glass-card animate-slide-up delay-100" style={{ padding: 24 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 16 }}>
                <Zap size={14} color="var(--amber)" />
                <span style={{ fontSize: 13, fontWeight: 700 }}>Mission Presets</span>
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                {GOAL_PRESETS.map(({ label, goal: g, emoji, tags }) => (
                  <button key={label} onClick={() => { setGoal(g); setActivePreset(label); }}
                    style={{
                      width: "100%", textAlign: "left",
                      background: activePreset === label ? "rgba(139,92,246,0.08)" : "var(--bg-base)",
                      border: `1px solid ${activePreset === label ? "rgba(139,92,246,0.4)" : "var(--border)"}`,
                      borderRadius: 10, padding: "12px 14px", cursor: "pointer",
                      color: "var(--text-primary)", transition: "all 0.15s",
                    }}
                    onMouseEnter={e => { if (activePreset !== label) e.currentTarget.style.borderColor = "rgba(255,255,255,0.2)"; }}
                    onMouseLeave={e => { if (activePreset !== label) e.currentTarget.style.borderColor = "var(--border)"; }}
                  >
                    <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
                      <span style={{ fontSize: 16 }}>{emoji}</span>
                      <div style={{ fontSize: 12, fontWeight: 600 }}>{label}</div>
                      {activePreset === label && <CheckCircle size={12} color="#8b5cf6" style={{ marginLeft: "auto" }} />}
                    </div>
                    <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                      {tags.map(t => (
                        <span key={t} style={{
                          fontSize: 9, fontWeight: 700, padding: "2px 6px", borderRadius: 4,
                          background: "rgba(59,130,246,0.1)", color: "#3b82f6",
                          border: "1px solid rgba(59,130,246,0.2)", textTransform: "uppercase"
                        }}>{t}</span>
                      ))}
                    </div>
                  </button>
                ))}
              </div>
            </div>

            {/* How it works */}
            <div className="glass-card animate-slide-up delay-200" style={{ padding: 20 }}>
              <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 14, color: "var(--text-primary)" }}>⚙️ How Agentic Planning Works</div>
              {[
                { step: "1", label: "Planner AI analyzes your goal", color: "#3b82f6" },
                { step: "2", label: "Agent Swarm selects optimal tools", color: "#8b5cf6" },
                { step: "3", label: "Sandbox executes tools safely", color: "#f59e0b" },
                { step: "4", label: "Specialist AI verifies findings", color: "#ef4444" },
                { step: "5", label: "Decision Log & evidence captured", color: "#10b981" },
              ].map(({ step, label, color }) => (
                <div key={step} style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10 }}>
                  <div style={{
                    width: 22, height: 22, borderRadius: "50%", background: `${color}15`,
                    border: `1.5px solid ${color}40`, color, fontSize: 10, fontWeight: 800,
                    display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0
                  }}>{step}</div>
                  <span style={{ fontSize: 12, color: "var(--text-secondary)", lineHeight: 1.4 }}>{label}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
