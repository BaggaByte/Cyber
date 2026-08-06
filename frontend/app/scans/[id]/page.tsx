"use client";
import { useState, useEffect } from "react";
import { useParams, useRouter } from "next/navigation";
import Cookies from "js-cookie";
import {
  Shield, Target, Clock, CheckCircle, XCircle, Activity,
  AlertTriangle, Terminal, Ticket, ChevronRight, ArrowLeft,
  Cpu, Globe, Lock, Server, Zap, FileText, Copy, ExternalLink,
  Download, Link as LinkIcon, Key
} from "lucide-react";

import Sidebar from "../../components/Sidebar";

const API = "";

const RISK_CONFIG: Record<string, { color: string; bg: string; border: string; score: number }> = {
  CRITICAL: { color: "#dc2626", bg: "rgba(239,68,68,0.08)", border: "rgba(239,68,68,0.25)", score: 95 },
  HIGH:     { color: "#d97706", bg: "rgba(245,158,11,0.08)", border: "rgba(245,158,11,0.25)", score: 72 },
  MEDIUM:   { color: "#f04e23", bg: "rgba(240,78,35,0.08)", border: "rgba(240,78,35,0.25)", score: 45 },
  LOW:      { color: "#059669", bg: "rgba(16,185,129,0.08)", border: "rgba(16,185,129,0.25)", score: 18 },
  INFO:     { color: "#64748b", bg: "rgba(100,116,139,0.08)", border: "rgba(100,116,139,0.25)", score: 5 },
};

function RiskGauge({ risk }: { risk: string }) {
  const cfg = RISK_CONFIG[risk] || RISK_CONFIG.INFO;
  const pct = cfg.score;
  const radius = 52;
  const circ = 2 * Math.PI * radius;
  const strokeDash = (pct / 100) * circ;

  return (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 12 }}>
      <svg width={140} height={140} viewBox="0 0 140 140">
        <circle cx={70} cy={70} r={radius} fill="none" stroke="var(--border)" strokeWidth={10} />
        <circle
          cx={70} cy={70} r={radius} fill="none"
          stroke={cfg.color} strokeWidth={10}
          strokeDasharray={`${strokeDash} ${circ}`}
          strokeLinecap="round"
          transform="rotate(-90 70 70)"
          style={{ transition: "stroke-dasharray 1s ease" }}
        />
        <text x={70} y={66} textAnchor="middle" fill={cfg.color} fontSize={22} fontWeight={800} fontFamily="Outfit,sans-serif">{pct}</text>
        <text x={70} y={84} textAnchor="middle" fill="var(--text-muted)" fontSize={11} fontFamily="Outfit,sans-serif">Risk Score</text>
      </svg>
      <span style={{
        padding: "6px 20px", borderRadius: 20, fontSize: 13, fontWeight: 700,
        background: cfg.bg, color: cfg.color, border: `1px solid ${cfg.border}`,
        letterSpacing: "1px"
      }}>{risk}</span>
    </div>
  );
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };
  return (
    <button onClick={copy} style={{
      display: "flex", alignItems: "center", gap: 6,
      padding: "6px 12px", borderRadius: 6, cursor: "pointer",
      background: copied ? "rgba(16,185,129,0.1)" : "var(--bg-base)",
      border: `1px solid ${copied ? "var(--emerald)" : "var(--border)"}`,
      color: copied ? "var(--emerald)" : "var(--text-secondary)",
      fontSize: 12, fontWeight: 600, transition: "all 0.2s"
    }}>
      <Copy size={13} />
      {copied ? "Copied!" : "Copy"}
    </button>
  );
}

function FindingCard({ title, items, icon: Icon, color }: any) {
  if (!items || items.length === 0) return null;
  return (
    <div className="glass-card" style={{ padding: 20 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 14 }}>
        <div style={{
          width: 32, height: 32, borderRadius: 8,
          background: `${color}15`, display: "flex", alignItems: "center", justifyContent: "center"
        }}>
          <Icon size={16} color={color} />
        </div>
        <span style={{ fontWeight: 700, fontSize: 14 }}>{title}</span>
        <span style={{
          marginLeft: "auto", padding: "2px 8px", borderRadius: 10,
          background: "var(--bg-base)", fontSize: 11, fontWeight: 700,
          color: "var(--text-secondary)", border: "1px solid var(--border)"
        }}>{items.length}</span>
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        {items.slice(0, 10).map((item: any, i: number) => (
          <div key={i} style={{
            padding: "10px 12px", borderRadius: 8,
            background: "var(--bg-base)", border: "1px solid var(--border)",
            fontFamily: "'JetBrains Mono', monospace", fontSize: 12,
            color: "var(--text-primary)", lineHeight: 1.6,
          }}>
            {typeof item === "object" ? (
              <div>
                {item.port && <span style={{ color, fontWeight: 700 }}>{item.port}/{item.protocol} </span>}
                {item.service && <span style={{ color: "var(--text-secondary)" }}>{item.service}</span>}
                {item.version && <span style={{ color: "var(--text-muted)" }}> v{item.version}</span>}
                {!item.port && <span>{JSON.stringify(item)}</span>}
              </div>
            ) : (
              <span>{String(item)}</span>
            )}
          </div>
        ))}
        {items.length > 10 && (
          <div style={{ textAlign: "center", fontSize: 12, color: "var(--text-muted)", paddingTop: 4 }}>
            +{items.length - 10} more findings
          </div>
        )}
      </div>
    </div>
  );
}

export default function ScanDetailPage() {
  const params = useParams();
  const router = useRouter();
  const scanId = params?.id;
  const token = Cookies.get("token");
  const [scan, setScan] = useState<any>(null);
  const [response, setResponse] = useState<any>(null);
  const [activeTab, setActiveTab] = useState<"findings" | "remediation" | "script" | "ticket">("findings");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!token) { router.push("/"); return; }
    if (!scanId) return;
    const h = { Authorization: `Bearer ${token}` };

    Promise.all([
      fetch(`${API}/api/scans/${scanId}`, { headers: h }).then(r => r.json()),
      fetch(`${API}/api/scans/${scanId}/response`, { headers: h }).then(r => r.json()),
    ]).then(([scanData, responseData]) => {
      setScan(scanData);
      setResponse(responseData);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, [scanId, token]);

  if (loading) return (
    <div style={{ display: "flex", minHeight: "100vh" }}>
      <Sidebar />
      <main style={{ marginLeft: 240, flex: 1, display: "flex", alignItems: "center", justifyContent: "center" }}>
        <div style={{ textAlign: "center", color: "var(--text-muted)" }}>
          <Activity size={32} style={{ animation: "spin-slow 2s linear infinite", color: "var(--accent-primary)", marginBottom: 12 }} />
          <div style={{ fontSize: 14 }}>Loading scan data...</div>
        </div>
      </main>
    </div>
  );

  if (!scan || scan.detail) return (
    <div style={{ display: "flex", minHeight: "100vh" }}>
      <Sidebar />
      <main style={{ marginLeft: 240, flex: 1, display: "flex", alignItems: "center", justifyContent: "center" }}>
        <div style={{ textAlign: "center", color: "var(--text-muted)" }}>
          <Shield size={32} style={{ marginBottom: 12 }} />
          <div style={{ fontSize: 14 }}>Scan not found</div>
          <button onClick={() => router.push("/scans")} className="btn-primary" style={{ marginTop: 16 }}>Back to Scans</button>
        </div>
      </main>
    </div>
  );

  const findings = scan.findings || {};
  const risk = scan.risk_score || "INFO";
  const riskCfg = RISK_CONFIG[risk] || RISK_CONFIG.INFO;
  const tabs = [
    { id: "findings", label: "Findings", icon: Shield },
    { id: "remediation", label: "AI Report", icon: FileText },
    ...(response?.script ? [{ id: "script", label: "Auto-Script", icon: Terminal }] : []),
    ...(response?.ticket_payload ? [{ id: "ticket", label: "Jira Ticket", icon: Ticket }] : []),
  ];

  return (
    <div style={{ display: "flex", minHeight: "100vh" }}>
      <Sidebar />
      <main style={{ marginLeft: 240, flex: 1, padding: "40px" }}>

        {/* Breadcrumb */}
        <div className="animate-slide-up" style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 24, fontSize: 13, color: "var(--text-muted)" }}>
          <button onClick={() => router.push("/scans")} style={{
            display: "flex", alignItems: "center", gap: 6,
            background: "none", border: "none", color: "var(--text-muted)",
            cursor: "pointer", fontFamily: "inherit", fontSize: 13, padding: 0
          }}>
            <ArrowLeft size={14} /> Scan History
          </button>
          <ChevronRight size={14} />
          <span style={{ color: "var(--text-primary)", fontWeight: 600 }}>Scan #{scan.scan_id}</span>
        </div>

        {/* Hero Row: Target + Risk Gauge + Meta */}
        <div className="glass-card animate-slide-up delay-100" style={{ padding: 28, marginBottom: 24, display: "grid", gridTemplateColumns: "1fr auto 1fr", gap: 32, alignItems: "center" }}>
          {/* Left: Target info */}
          <div>
            <div style={{ fontSize: 12, fontWeight: 600, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "1px", marginBottom: 8 }}>Target</div>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 22, fontWeight: 700, color: "var(--text-primary)", marginBottom: 16 }}>
              {scan.target}
            </div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 10 }}>
              <span style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 13, fontWeight: 600, color: "var(--accent-primary)", background: "rgba(240,78,35,0.08)", padding: "4px 12px", borderRadius: 20, border: "1px solid rgba(240,78,35,0.2)" }}>
                <Cpu size={13} /> {scan.tool_used?.toUpperCase()}
              </span>
              <span className={`status-${scan.status}`} style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 13, fontWeight: 600, padding: "4px 12px", borderRadius: 20, background: "var(--bg-base)", border: "1px solid var(--border)" }}>
                {scan.status === "completed" && <CheckCircle size={13} />}
                {scan.status === "failed" && <XCircle size={13} />}
                {scan.status === "running" && <Activity size={13} />}
                {scan.status === "queued" && <Clock size={13} />}
                {scan.status}
              </span>
            </div>
          </div>

          {/* Center: Risk Gauge */}
          <RiskGauge risk={risk} />

          {/* Right: Timestamps & Actions */}
          <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            <div style={{ display: "flex", gap: 24 }}>
              {[
                { label: "Scan ID", value: `#${scan.scan_id}`, icon: Shield },
                { label: "Completed", value: scan.completed_at ? new Date(scan.completed_at).toLocaleString() : "—", icon: CheckCircle },
              ].map(({ label, value, icon: Icon }) => (
                <div key={label} style={{ display: "flex", alignItems: "center", gap: 10 }}>
                  <Icon size={14} color="var(--text-muted)" />
                  <div>
                    <div style={{ fontSize: 10, fontWeight: 600, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.8px" }}>{label}</div>
                    <div style={{ fontSize: 13, fontWeight: 600, color: "var(--text-primary)", marginTop: 2 }}>{value}</div>
                  </div>
                </div>
              ))}
            </div>
            
            {scan.status === "completed" && (
              <a 
                href={`${API}/api/scans/${scan.scan_id}/report/pdf`} 
                target="_blank"
                className="btn-primary" 
                style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 8, padding: "10px 16px", fontSize: 13, textDecoration: "none", marginTop: 8 }}
              >
                <Download size={16} />
                Download PDF Report
              </a>
            )}
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="animate-slide-up delay-200" style={{ display: "flex", gap: 4, marginBottom: 20, padding: "4px", background: "var(--bg-base)", borderRadius: 10, border: "1px solid var(--border)", width: "fit-content" }}>
          {tabs.map(({ id, label, icon: Icon }: any) => (
            <button
              key={id}
              onClick={() => setActiveTab(id)}
              style={{
                display: "flex", alignItems: "center", gap: 7,
                padding: "8px 16px", borderRadius: 8, cursor: "pointer",
                background: activeTab === id ? "white" : "transparent",
                border: activeTab === id ? "1px solid var(--border)" : "1px solid transparent",
                color: activeTab === id ? "var(--accent-primary)" : "var(--text-secondary)",
                fontSize: 13, fontWeight: activeTab === id ? 700 : 500,
                boxShadow: activeTab === id ? "0 2px 6px rgba(0,0,0,0.06)" : "none",
                transition: "all 0.15s",
              }}
            >
              <Icon size={14} />
              {label}
            </button>
          ))}
        </div>

        {/* Tab Content */}
        <div className="animate-slide-up delay-300">

          {/* ── FINDINGS TAB ── */}
          {activeTab === "findings" && (
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
              {/* Evidence Links */}
              {scan.evidence_links && scan.evidence_links.length > 0 && (
                <div className="glass-card" style={{ padding: 20, gridColumn: "1/-1", border: "1px solid var(--accent-primary)" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 14 }}>
                    <div style={{ width: 32, height: 32, borderRadius: 8, background: "rgba(240,78,35,0.15)", display: "flex", alignItems: "center", justifyContent: "center" }}>
                      <LinkIcon size={16} color="var(--accent-primary)" />
                    </div>
                    <span style={{ fontWeight: 700, fontSize: 14 }}>Raw Evidence Logs (MinIO Object Store)</span>
                  </div>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 12 }}>
                    {scan.evidence_links.map((link: string, idx: number) => (
                      <a key={idx} href={link} target="_blank" rel="noopener noreferrer" style={{
                        display: "flex", alignItems: "center", gap: 8, padding: "10px 16px", borderRadius: 8,
                        background: "var(--bg-base)", border: "1px solid var(--border)",
                        fontSize: 12, fontWeight: 600, color: "var(--text-primary)", textDecoration: "none",
                        transition: "all 0.2s"
                      }}
                      onMouseEnter={e => e.currentTarget.style.borderColor = "var(--accent-primary)"}
                      onMouseLeave={e => e.currentTarget.style.borderColor = "var(--border)"}
                      >
                        Evidence File #{idx + 1} <ExternalLink size={14} color="var(--text-muted)" />
                      </a>
                    ))}
                  </div>
                </div>
              )}

              <FindingCard title="Open Ports" items={findings.open_ports} icon={Server} color="var(--accent-primary)" />
              <FindingCard title="Discovered Subdomains" items={findings.discovered_subdomains} icon={Globe} color="#3b82f6" />

              {/* TLS Certificate Card */}
              {findings.certificate && Object.keys(findings.certificate).length > 0 && (() => {
                const cert = findings.certificate;
                const certVulns = findings.vulnerabilities || [];
                const days = cert.days_remaining;
                const daysColor = cert.is_expired ? "var(--red)" : days <= 30 ? "var(--amber)" : "var(--emerald)";
                return (
                  <div className="glass-card" style={{ padding: 20, gridColumn: "1/-1", border: `1px solid ${cert.is_expired ? "var(--red)" : days <= 30 ? "var(--amber)" : "var(--border)"}` }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 18 }}>
                      <div style={{ width: 32, height: 32, borderRadius: 8, background: "rgba(6,182,212,0.12)", display: "flex", alignItems: "center", justifyContent: "center" }}>
                        <Lock size={16} color="#06b6d4" />
                      </div>
                      <span style={{ fontWeight: 700, fontSize: 14 }}>TLS Certificate Inspection</span>
                      {days !== undefined && days !== null && (
                        <span style={{ marginLeft: "auto", padding: "4px 12px", borderRadius: 20, fontSize: 12, fontWeight: 700, background: `${daysColor}15`, color: daysColor, border: `1px solid ${daysColor}30` }}>
                          {cert.is_expired ? `Expired ${Math.abs(days)}d ago` : `Expires in ${days} days`}
                        </span>
                      )}
                    </div>

                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 16, marginBottom: 16 }}>
                      {[
                        { label: "Common Name",    value: cert.common_name || "—" },
                        { label: "Organization",   value: cert.organization || "—" },
                        { label: "Issued By",      value: cert.issuer_cn || "—" },
                        { label: "TLS Version",    value: cert.tls_version || "—" },
                        { label: "Cipher Suite",   value: cert.cipher_suite || "—" },
                        { label: "Cipher Bits",    value: cert.cipher_bits ? `${cert.cipher_bits} bit` : "—" },
                        { label: "Valid From",     value: cert.not_before ? new Date(cert.not_before).toLocaleDateString() : "—" },
                        { label: "Valid Until",    value: cert.not_after ? new Date(cert.not_after).toLocaleDateString() : "—" },
                        { label: "Serial Number",  value: cert.serial_number ? cert.serial_number.slice(0, 20) + "..." : "—" },
                      ].map(({ label, value }) => (
                        <div key={label} style={{ padding: "10px 14px", background: "var(--bg-base)", borderRadius: 8, border: "1px solid var(--border)" }}>
                          <div style={{ fontSize: 10, fontWeight: 600, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.5px", marginBottom: 4 }}>{label}</div>
                          <div style={{ fontSize: 12, fontWeight: 600, color: "var(--text-primary)", fontFamily: "'JetBrains Mono', monospace", wordBreak: "break-all" }}>{value}</div>
                        </div>
                      ))}
                    </div>

                    {/* SANs */}
                    {cert.san_domains && cert.san_domains.length > 0 && (
                      <div style={{ marginBottom: 16 }}>
                        <div style={{ fontSize: 11, fontWeight: 700, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.5px", marginBottom: 8 }}>
                          Subject Alternative Names ({cert.san_domains.length})
                        </div>
                        <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                          {cert.san_domains.map((san: string, i: number) => (
                            <span key={i} style={{ padding: "3px 10px", borderRadius: 6, background: "rgba(139,92,246,0.08)", color: "#8b5cf6", border: "1px solid rgba(139,92,246,0.2)", fontSize: 12, fontFamily: "monospace" }}>
                              {san}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Certificate Vulnerability Flags */}
                    {certVulns.length > 0 && (
                      <div>
                        <div style={{ fontSize: 11, fontWeight: 700, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.5px", marginBottom: 8 }}>
                          Certificate Issues
                        </div>
                        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                          {certVulns.map((v: any, i: number) => {
                            const sColor = v.severity === "CRITICAL" ? "var(--red)" : v.severity === "HIGH" ? "var(--amber)" : "var(--accent-primary)";
                            return (
                              <div key={i} style={{ padding: "10px 14px", borderRadius: 8, background: `${sColor}08`, border: `1px solid ${sColor}25`, display: "flex", gap: 12, alignItems: "flex-start" }}>
                                <span style={{ fontSize: 10, fontWeight: 700, padding: "2px 6px", borderRadius: 4, background: `${sColor}15`, color: sColor, border: `1px solid ${sColor}30`, flexShrink: 0, marginTop: 2 }}>{v.severity}</span>
                                <div>
                                  <div style={{ fontSize: 13, fontWeight: 700, color: "var(--text-primary)" }}>{v.title}</div>
                                  <div style={{ fontSize: 12, color: "var(--text-secondary)", marginTop: 2 }}>{v.detail}</div>
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    )}
                  </div>
                );
              })()}


              <FindingCard title="Vulnerabilities" items={findings.vulnerabilities} icon={AlertTriangle} color="var(--red)" />
              <FindingCard title="Exposed Services" items={findings.services} icon={Lock} color="var(--amber)" />

              {/* Raw Output fallback */}
              {!findings.open_ports && !findings.discovered_subdomains && (
                <div className="glass-card" style={{ padding: 20, gridColumn: "1/-1" }}>
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 14 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                      <Terminal size={16} color="var(--text-secondary)" />
                      <span style={{ fontWeight: 700, fontSize: 14 }}>Raw Output</span>
                    </div>
                    {findings.raw_output && <CopyButton text={findings.raw_output} />}
                  </div>
                  <pre style={{
                    background: "#0f172a", color: "#e2e8f0",
                    padding: 16, borderRadius: 8,
                    fontFamily: "'JetBrains Mono', monospace", fontSize: 12,
                    overflowX: "auto", maxHeight: 400, lineHeight: 1.6,
                    whiteSpace: "pre-wrap", wordBreak: "break-all",
                  }}>
                    {findings.raw_output || JSON.stringify(findings, null, 2) || "No output available."}
                  </pre>
                </div>
              )}

              {/* Error state */}
              {findings.error && (
                <div className="glass-card" style={{ padding: 20, gridColumn: "1/-1", borderColor: "var(--red)" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8, color: "var(--red)" }}>
                    <XCircle size={16} />
                    <span style={{ fontWeight: 700 }}>Scan Error</span>
                  </div>
                  <p style={{ marginTop: 10, fontSize: 13, color: "var(--text-secondary)" }}>{findings.error}</p>
                </div>
              )}
            </div>
          )}

          {/* ── AI REMEDIATION TAB ── */}
          {activeTab === "remediation" && (
            <div className="glass-card" style={{ padding: 28 }}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                  <div style={{ width: 36, height: 36, borderRadius: 10, background: "linear-gradient(135deg, var(--accent-primary), var(--accent-secondary))", display: "flex", alignItems: "center", justifyContent: "center" }}>
                    <Zap size={18} color="#fff" />
                  </div>
                  <div>
                    <div style={{ fontWeight: 800, fontSize: 16 }}>AI Security Report</div>
                    <div style={{ fontSize: 12, color: "var(--text-muted)" }}>Generated by Llama 3.1 via Groq</div>
                  </div>
                </div>
                <span style={{ padding: "4px 12px", borderRadius: 20, fontSize: 11, fontWeight: 700, background: riskCfg.bg, color: riskCfg.color, border: `1px solid ${riskCfg.border}` }}>
                  {risk} RISK
                </span>
              </div>
              <div style={{
                background: "var(--bg-base)", borderRadius: 8, padding: 20,
                fontSize: 14, lineHeight: 1.8, color: "var(--text-primary)",
                border: "1px solid var(--border)", whiteSpace: "pre-wrap",
                fontFamily: "inherit",
              }}>
                {findings.remediation_plan || "No AI report generated for this scan."}
              </div>
            </div>
          )}

          {/* ── SCRIPT TAB ── */}
          {activeTab === "script" && response?.script && (
            <div className="glass-card" style={{ padding: 28 }}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                  <div style={{ width: 36, height: 36, borderRadius: 10, background: "#0f172a", display: "flex", alignItems: "center", justifyContent: "center" }}>
                    <Terminal size={18} color="#10b981" />
                  </div>
                  <div>
                    <div style={{ fontWeight: 800, fontSize: 16 }}>Auto-Generated Remediation Script</div>
                    <div style={{ fontSize: 12, color: "var(--text-muted)" }}>AI-generated bash script — review before executing</div>
                  </div>
                </div>
                <CopyButton text={response.script} />
              </div>
              <div style={{ background: "#0f172a", borderRadius: 10, overflow: "hidden" }}>
                <div style={{ padding: "10px 16px", background: "#1e293b", display: "flex", gap: 6 }}>
                  {["#ef4444","#f59e0b","#10b981"].map(c => <div key={c} style={{ width: 12, height: 12, borderRadius: "50%", background: c }} />)}
                  <span style={{ marginLeft: 8, fontSize: 12, color: "#64748b", fontFamily: "monospace" }}>remediation.sh</span>
                </div>
                <pre style={{
                  padding: "20px 24px", color: "#e2e8f0",
                  fontFamily: "'JetBrains Mono', monospace", fontSize: 13,
                  lineHeight: 1.7, overflowX: "auto", whiteSpace: "pre-wrap",
                  margin: 0, maxHeight: 500,
                }}>
                  {response.script}
                </pre>
              </div>
            </div>
          )}

          {/* ── TICKET TAB ── */}
          {activeTab === "ticket" && response?.ticket_payload && (
            <div className="glass-card" style={{ padding: 28 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 20 }}>
                <div style={{ width: 36, height: 36, borderRadius: 10, background: "rgba(14,165,233,0.1)", display: "flex", alignItems: "center", justifyContent: "center" }}>
                  <Ticket size={18} color="#0ea5e9" />
                </div>
                <div>
                  <div style={{ fontWeight: 800, fontSize: 16 }}>Auto-Generated Jira Ticket</div>
                  <div style={{ fontSize: 12, color: "var(--text-muted)" }}>Simulated ServiceNow / Jira payload</div>
                </div>
                <span style={{ marginLeft: "auto", padding: "4px 12px", borderRadius: 20, fontSize: 11, fontWeight: 700, background: "rgba(14,165,233,0.1)", color: "#0ea5e9", border: "1px solid rgba(14,165,233,0.2)" }}>
                  {response.status?.toUpperCase()}
                </span>
              </div>

              {/* Ticket preview card */}
              <div style={{ border: "1px solid var(--border)", borderRadius: 10, overflow: "hidden" }}>
                <div style={{ padding: "16px 20px", background: "var(--bg-base)", borderBottom: "1px solid var(--border)", display: "flex", gap: 12, alignItems: "flex-start" }}>
                  <div style={{ padding: "4px 8px", background: "#0ea5e9", color: "#fff", borderRadius: 4, fontSize: 11, fontWeight: 700, minWidth: 60, textAlign: "center" }}>SEC-AUTO</div>
                  <div>
                    <div style={{ fontWeight: 700, fontSize: 15 }}>{response.ticket_payload?.fields?.summary}</div>
                    <div style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 4 }}>Priority: {response.ticket_payload?.fields?.priority?.name} · Type: {response.ticket_payload?.fields?.issuetype?.name}</div>
                  </div>
                </div>
                <div style={{ padding: "20px", fontSize: 13, lineHeight: 1.7, color: "var(--text-secondary)", whiteSpace: "pre-wrap", fontFamily: "inherit" }}>
                  {response.ticket_payload?.fields?.description}
                </div>
              </div>

              <div style={{ marginTop: 16 }}>
                <div style={{ fontSize: 12, fontWeight: 600, color: "var(--text-muted)", marginBottom: 8 }}>Raw JSON Payload</div>
                <div style={{ position: "relative" }}>
                  <div style={{ position: "absolute", top: 10, right: 10 }}>
                    <CopyButton text={JSON.stringify(response.ticket_payload, null, 2)} />
                  </div>
                  <pre style={{
                    background: "#0f172a", color: "#94a3b8",
                    padding: "16px 20px", borderRadius: 8,
                    fontFamily: "'JetBrains Mono', monospace", fontSize: 11,
                    overflowX: "auto", lineHeight: 1.6, maxHeight: 300,
                  }}>
                    {JSON.stringify(response.ticket_payload, null, 2)}
                  </pre>
                </div>
              </div>
            </div>
          )}
        </div>

      </main>
    </div>
  );
}
