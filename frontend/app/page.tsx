"use client";

import { useState, useEffect, useRef } from 'react';
import Cookies from 'js-cookie';
import { Shield, Server, Target, ArrowRight, Lock, User, ChevronRight, Activity, Eye, Zap, GitBranch, Globe, Database, AlertTriangle, FileSearch, BarChart2, Check, X } from 'lucide-react';

// ── Animated Counter Hook ────────────────────────────────────────────────────
function useCounter(end: number, duration: number = 2000, startWhen: boolean = true) {
  const [count, setCount] = useState(0);
  useEffect(() => {
    if (!startWhen) return;
    let start = 0;
    const step = end / (duration / 16);
    const timer = setInterval(() => {
      start += step;
      if (start >= end) { setCount(end); clearInterval(timer); }
      else setCount(Math.floor(start));
    }, 16);
    return () => clearInterval(timer);
  }, [end, duration, startWhen]);
  return count;
}

// ── Stats Data ───────────────────────────────────────────────────────────────
const STATS = [
  { label: "Vulnerabilities Detected", value: 284712, suffix: "+" },
  { label: "Attack Surfaces Mapped", value: 18300, suffix: "+" },
  { label: "Compliance Frameworks", value: 14, suffix: "" },
  { label: "Mean Time to Remediate", value: 4, suffix: "hrs" },
];

// ── Platform Data ────────────────────────────────────────────────────────────
const PLATFORMS = [
  {
    id: "sentinel",
    icon: Shield,
    name: "Sentinel AI",
    tagline: "Autonomous Attack Surface Intelligence",
    description: "Continuously maps your entire external attack surface using AI-driven reconnaissance. Sentinel autonomously enumerates subdomains, detects open ports, fingerprints services, and correlates findings against live CVE databases — without human intervention.",
    accentColor: "#f04e23",
    glowColor: "rgba(240,78,35,0.15)",
    borderColor: "rgba(240,78,35,0.3)",
    href: "/dashboard",
    features: [
      { icon: Globe, label: "Subdomain Enumeration & DNS Mapping" },
      { icon: Eye, label: "Service & Version Fingerprinting" },
      { icon: AlertTriangle, label: "Real-time CVE Correlation Engine" },
      { icon: Activity, label: "Continuous Attack Surface Monitoring" },
      { icon: GitBranch, label: "Knowledge Graph Relationship Mapping" },
      { icon: Zap, label: "Autonomous Threat Orchestration" },
    ],
  },
  {
    id: "aegis",
    icon: Server,
    name: "Aegis AI",
    tagline: "AI-Powered Threat Remediation Engine",
    description: "Goes beyond detection — Aegis generates contextual, AI-powered remediation plans for every finding. Backed by a Retrieval-Augmented Generation (RAG) pipeline and a local Ollama-powered LLM, all analysis happens on-premises with zero data egress.",
    accentColor: "#10b981",
    glowColor: "rgba(16,185,129,0.15)",
    borderColor: "rgba(16,185,129,0.3)",
    href: "/aegis/",
    features: [
      { icon: FileSearch, label: "RAG-Augmented Contextual Analysis" },
      { icon: Lock, label: "On-Premises Local LLM (Ollama)" },
      { icon: Zap, label: "Executable Auto-Remediation Scripts" },
      { icon: Database, label: "ChromaDB Threat Intelligence Memory" },
      { icon: GitBranch, label: "Jira / ServiceNow Ticket Generation" },
      { icon: Activity, label: "TLS Certificate Deep Inspection" },
    ],
  },
  {
    id: "nexus",
    icon: Target,
    name: "Nexus AI",
    tagline: "Enterprise GRC & Compliance Intelligence",
    description: "Provides a unified governance, risk, and compliance command center. Nexus continuously monitors your posture against major regulatory frameworks, generates audit-ready reports, and provides board-level risk scoring powered by real-time threat data.",
    accentColor: "#3b82f6",
    glowColor: "rgba(59,130,246,0.15)",
    borderColor: "rgba(59,130,246,0.3)",
    href: "/nexus/",
    features: [
      { icon: BarChart2, label: "Multi-Framework Compliance Scoring" },
      { icon: FileSearch, label: "Automated Audit Trail Generation" },
      { icon: Globe, label: "Global Threat Intelligence Integration" },
      { icon: Database, label: "Board-Level Risk Reporting" },
      { icon: Activity, label: "Policy Violation Alerting" },
      { icon: Eye, label: "Continuous Posture Monitoring" },
    ],
  },
];

// ── Auth Modal ───────────────────────────────────────────────────────────────
function AuthModal({ onClose, onSuccess }: { onClose: () => void; onSuccess: () => void }) {
  const [isRegistering, setIsRegistering] = useState(false);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [orgName, setOrgName] = useState("");
  const [firstName, setFirstName] = useState("");
  const [lastName, setLastName] = useState("");
  const [jobTitle, setJobTitle] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const strength = (() => {
    let s = 0;
    if (password.length >= 8) s += 25;
    if (/[A-Z]/.test(password)) s += 25;
    if (/[0-9]/.test(password)) s += 25;
    if (/[^A-Za-z0-9]/.test(password)) s += 25;
    return s;
  })();

  const handleAuth = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError("");
    const endpoint = isRegistering ? "/api/register" : "/api/login";
    const payload = isRegistering
      ? { email, password, org_name: orgName, first_name: firstName, last_name: lastName, job_title: jobTitle }
      : { email, password };
    try {
      const res = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (res.ok) {
        const data = await res.json();
        if (data.access_token) {
          Cookies.set("token", data.access_token, { path: "/" });
          onSuccess();
        } else {
          setIsRegistering(false);
          setError("Registration successful. Please log in.");
        }
      } else {
        const err = await res.json().catch(() => ({}));
        setError(err.detail || "Authentication failed.");
      }
    } catch {
      setError("Connection error. Ensure the API is running.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      style={{
        position: "fixed", inset: 0, zIndex: 100,
        background: "rgba(2,6,23,0.85)",
        backdropFilter: "blur(12px)",
        display: "flex", alignItems: "center", justifyContent: "center",
      }}
      onClick={onClose}
    >
      <div
        onClick={e => e.stopPropagation()}
        style={{
          background: "#0f172a",
          border: "1px solid rgba(255,255,255,0.1)",
          borderRadius: "16px",
          padding: "40px",
          width: "100%",
          maxWidth: "420px",
          boxShadow: "0 25px 60px rgba(0,0,0,0.5)",
          animation: "fadeInUp 0.3s ease forwards",
        }}
      >
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "32px" }}>
          <div>
            <div style={{ fontSize: "22px", fontWeight: "800", color: "#f8fafc" }}>
              {isRegistering ? "Create Workspace" : "Secure Access"}
            </div>
            <div style={{ fontSize: "13px", color: "#64748b", marginTop: "4px" }}>
              {isRegistering ? "Deploy your autonomous SOC." : "Enter credentials to continue."}
            </div>
          </div>
          <button onClick={onClose} style={{ background: "transparent", border: "none", color: "#64748b", cursor: "pointer", padding: "4px" }}>
            <X size={20} />
          </button>
        </div>

        <form onSubmit={handleAuth} style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
          <div style={{ position: "relative" }}>
            <User size={16} style={{ position: "absolute", left: "14px", top: "50%", transform: "translateY(-50%)", color: "#64748b" }} />
            <input type="email" placeholder="Email Address" value={email} onChange={e => setEmail(e.target.value)} required
              style={{ width: "100%", background: "#1e293b", border: "1px solid rgba(255,255,255,0.08)", borderRadius: "10px", padding: "12px 14px 12px 40px", color: "#f8fafc", fontSize: "14px", outline: "none", boxSizing: "border-box" }} />
          </div>
          <div style={{ position: "relative" }}>
            <Lock size={16} style={{ position: "absolute", left: "14px", top: "50%", transform: "translateY(-50%)", color: "#64748b" }} />
            <input type="password" placeholder="Password" value={password} onChange={e => setPassword(e.target.value)} required
              style={{ width: "100%", background: "#1e293b", border: "1px solid rgba(255,255,255,0.08)", borderRadius: "10px", padding: "12px 14px 12px 40px", color: "#f8fafc", fontSize: "14px", outline: "none", boxSizing: "border-box" }} />
          </div>

          {isRegistering && (
            <>
              <div style={{ height: "4px", background: "#1e293b", borderRadius: "4px", overflow: "hidden" }}>
                <div style={{ height: "100%", width: `${strength}%`, transition: "width 0.3s", background: strength < 50 ? "#ef4444" : strength < 100 ? "#f59e0b" : "#10b981", borderRadius: "4px" }} />
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "10px" }}>
                <input placeholder="First Name" value={firstName} onChange={e => setFirstName(e.target.value)} required
                  style={{ background: "#1e293b", border: "1px solid rgba(255,255,255,0.08)", borderRadius: "10px", padding: "12px 14px", color: "#f8fafc", fontSize: "14px", outline: "none" }} />
                <input placeholder="Last Name" value={lastName} onChange={e => setLastName(e.target.value)} required
                  style={{ background: "#1e293b", border: "1px solid rgba(255,255,255,0.08)", borderRadius: "10px", padding: "12px 14px", color: "#f8fafc", fontSize: "14px", outline: "none" }} />
              </div>
              <input placeholder="Job Title" value={jobTitle} onChange={e => setJobTitle(e.target.value)} required
                style={{ background: "#1e293b", border: "1px solid rgba(255,255,255,0.08)", borderRadius: "10px", padding: "12px 14px", color: "#f8fafc", fontSize: "14px", outline: "none" }} />
              <input placeholder="Organization Name" value={orgName} onChange={e => setOrgName(e.target.value)} required
                style={{ background: "#1e293b", border: "1px solid rgba(255,255,255,0.08)", borderRadius: "10px", padding: "12px 14px", color: "#f8fafc", fontSize: "14px", outline: "none" }} />
            </>
          )}

          {error && <div style={{ fontSize: "13px", color: "#ef4444", background: "rgba(239,68,68,0.08)", borderRadius: "8px", padding: "10px 14px" }}>{error}</div>}

          <button type="submit" disabled={loading || (isRegistering && strength < 100)}
            style={{ marginTop: "8px", padding: "13px", background: "#f04e23", color: "white", border: "none", borderRadius: "10px", fontWeight: "700", fontSize: "14px", cursor: loading ? "not-allowed" : "pointer", opacity: loading ? 0.7 : 1, transition: "all 0.2s", display: "flex", alignItems: "center", justifyContent: "center", gap: "8px" }}>
            {loading ? "Authenticating..." : (isRegistering ? "Register Workspace" : "Access Platform")}
            {!loading && <ArrowRight size={16} />}
          </button>
        </form>

        <div style={{ textAlign: "center", marginTop: "20px", fontSize: "13px", color: "#64748b" }}>
          {isRegistering ? "Already have an account?" : "New to Saga?"}
          <button onClick={() => { setIsRegistering(!isRegistering); setError(""); }}
            style={{ background: "none", border: "none", color: "#f04e23", fontWeight: "700", cursor: "pointer", marginLeft: "6px" }}>
            {isRegistering ? "Sign in" : "Register"}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Main Landing Page ────────────────────────────────────────────────────────
export default function Home() {
  const [showAuth, setShowAuth] = useState(false);
  const [token, setToken] = useState<string | null>(null);
  const [statsVisible, setStatsVisible] = useState(false);
  const statsRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const saved = Cookies.get("token");
    if (saved) setToken(saved);
    const observer = new IntersectionObserver(([entry]) => { if (entry.isIntersecting) setStatsVisible(true); }, { threshold: 0.3 });
    if (statsRef.current) observer.observe(statsRef.current);
    return () => observer.disconnect();
  }, []);

  const c0 = useCounter(STATS[0].value, 2200, statsVisible);
  const c1 = useCounter(STATS[1].value, 2200, statsVisible);
  const c2 = useCounter(STATS[2].value, 1800, statsVisible);
  const c3 = useCounter(STATS[3].value, 1600, statsVisible);
  const counts = [c0, c1, c2, c3];

  const handleAuthSuccess = () => {
    setToken(Cookies.get("token") || "");
    setShowAuth(false);
    window.location.href = "/dashboard";
  };

  return (
    <div style={{ background: "#020617", minHeight: "100vh", fontFamily: "'Outfit', sans-serif", color: "#f8fafc", overflowX: "hidden" }}>

      {/* ── Noise Texture Overlay ── */}
      <div style={{
        position: "fixed", inset: 0, zIndex: 0, pointerEvents: "none",
        backgroundImage: "radial-gradient(ellipse 80% 50% at 50% -20%, rgba(240,78,35,0.12), transparent), radial-gradient(ellipse 50% 80% at 80% 80%, rgba(59,130,246,0.06), transparent)",
      }} />

      {/* ── Topbar Nav ── */}
      <nav style={{
        position: "sticky", top: 0, zIndex: 50,
        borderBottom: "1px solid rgba(255,255,255,0.06)",
        backdropFilter: "blur(20px)",
        background: "rgba(2,6,23,0.8)",
        padding: "0 48px",
        display: "flex", alignItems: "center", justifyContent: "space-between",
        height: "64px",
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
          <div style={{ width: "32px", height: "32px", background: "#f04e23", borderRadius: "8px", display: "flex", alignItems: "center", justifyContent: "center", boxShadow: "0 0 16px rgba(240,78,35,0.4)" }}>
            <Shield size={18} color="white" />
          </div>
          <span style={{ fontWeight: "800", fontSize: "18px", letterSpacing: "-0.5px" }}>
            Saga<span style={{ color: "#f04e23" }}>AI</span>
          </span>
          <span style={{ fontSize: "11px", background: "rgba(240,78,35,0.1)", color: "#f04e23", border: "1px solid rgba(240,78,35,0.2)", borderRadius: "999px", padding: "2px 10px", fontWeight: "700", letterSpacing: "0.5px", textTransform: "uppercase" }}>Enterprise</span>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <a href="#platforms" style={{ padding: "8px 16px", fontSize: "14px", color: "#94a3b8", textDecoration: "none", fontWeight: "500", transition: "color 0.2s" }} onMouseEnter={e => (e.currentTarget.style.color = "#f8fafc")} onMouseLeave={e => (e.currentTarget.style.color = "#94a3b8")}>Platforms</a>
          <a href="#capabilities" style={{ padding: "8px 16px", fontSize: "14px", color: "#94a3b8", textDecoration: "none", fontWeight: "500", transition: "color 0.2s" }} onMouseEnter={e => (e.currentTarget.style.color = "#f8fafc")} onMouseLeave={e => (e.currentTarget.style.color = "#94a3b8")}>Capabilities</a>

          {token ? (
            <a href="/dashboard" style={{ display: "flex", alignItems: "center", gap: "8px", padding: "8px 20px", background: "#f04e23", color: "white", borderRadius: "8px", textDecoration: "none", fontWeight: "700", fontSize: "14px", transition: "all 0.2s" }}
              onMouseEnter={e => { (e.currentTarget as HTMLAnchorElement).style.background = "#ff6b3d"; }}
              onMouseLeave={e => { (e.currentTarget as HTMLAnchorElement).style.background = "#f04e23"; }}>
              Open Dashboard <ArrowRight size={14} />
            </a>
          ) : (
            <button onClick={() => setShowAuth(true)} style={{ display: "flex", alignItems: "center", gap: "8px", padding: "8px 20px", background: "#f04e23", color: "white", border: "none", borderRadius: "8px", fontWeight: "700", fontSize: "14px", cursor: "pointer", transition: "all 0.2s" }}
              onMouseEnter={e => { (e.currentTarget as HTMLButtonElement).style.background = "#ff6b3d"; }}
              onMouseLeave={e => { (e.currentTarget as HTMLButtonElement).style.background = "#f04e23"; }}>
              Sign In <ArrowRight size={14} />
            </button>
          )}
        </div>
      </nav>

      {/* ── Hero ── */}
      <section style={{ position: "relative", zIndex: 1, maxWidth: "1200px", margin: "0 auto", padding: "120px 48px 80px" }}>
        <div style={{ display: "inline-flex", alignItems: "center", gap: "8px", background: "rgba(240,78,35,0.08)", border: "1px solid rgba(240,78,35,0.2)", borderRadius: "999px", padding: "6px 16px", marginBottom: "32px" }}>
          <div style={{ width: "6px", height: "6px", borderRadius: "50%", background: "#f04e23", boxShadow: "0 0 8px #f04e23", animation: "pulse 2s infinite" }} />
          <span style={{ fontSize: "12px", fontWeight: "700", color: "#f04e23", letterSpacing: "1px", textTransform: "uppercase" }}>Active Security Operations</span>
        </div>

        <h1 style={{ fontSize: "clamp(40px, 7vw, 76px)", fontWeight: "900", lineHeight: "1.05", letterSpacing: "-2px", maxWidth: "800px", marginBottom: "28px" }}>
          The Unified{" "}
          <span style={{ background: "linear-gradient(135deg, #f04e23, #ff8c63)", WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent" }}>
            AI Security
          </span>
          <br />Operations Platform
        </h1>

        <p style={{ fontSize: "18px", color: "#94a3b8", lineHeight: "1.7", maxWidth: "620px", marginBottom: "48px", fontWeight: "400" }}>
          Sentinel, Aegis, and Nexus — three specialized AI engines working in concert to autonomously map attack surfaces, remediate vulnerabilities, and enforce compliance across your entire enterprise.
        </p>

        <div style={{ display: "flex", gap: "16px", flexWrap: "wrap" }}>
          <button onClick={() => token ? window.location.href = "/dashboard" : setShowAuth(true)}
            style={{ display: "flex", alignItems: "center", gap: "10px", padding: "14px 28px", background: "#f04e23", color: "white", border: "none", borderRadius: "10px", fontWeight: "700", fontSize: "15px", cursor: "pointer", boxShadow: "0 0 24px rgba(240,78,35,0.35)", transition: "all 0.25s" }}
            onMouseEnter={e => { const b = e.currentTarget; b.style.transform = "translateY(-2px)"; b.style.boxShadow = "0 4px 32px rgba(240,78,35,0.5)"; }}
            onMouseLeave={e => { const b = e.currentTarget; b.style.transform = "translateY(0)"; b.style.boxShadow = "0 0 24px rgba(240,78,35,0.35)"; }}>
            <Zap size={18} /> Launch Platform <ArrowRight size={16} />
          </button>
          <a href="#platforms"
            style={{ display: "flex", alignItems: "center", gap: "10px", padding: "14px 28px", background: "transparent", color: "#94a3b8", border: "1px solid rgba(255,255,255,0.1)", borderRadius: "10px", fontWeight: "600", fontSize: "15px", cursor: "pointer", textDecoration: "none", transition: "all 0.25s" }}
            onMouseEnter={e => { const b = e.currentTarget; b.style.color = "#f8fafc"; b.style.borderColor = "rgba(255,255,255,0.3)"; }}
            onMouseLeave={e => { const b = e.currentTarget; b.style.color = "#94a3b8"; b.style.borderColor = "rgba(255,255,255,0.1)"; }}>
            Explore Platforms <ChevronRight size={16} />
          </a>
        </div>
      </section>

      {/* ── Stats Bar ── */}
      <section ref={statsRef} style={{ position: "relative", zIndex: 1, borderTop: "1px solid rgba(255,255,255,0.06)", borderBottom: "1px solid rgba(255,255,255,0.06)", background: "rgba(15,23,42,0.6)", backdropFilter: "blur(8px)", willChange: "transform, opacity" }}>
        <div style={{ maxWidth: "1200px", margin: "0 auto", padding: "0 48px", display: "grid", gridTemplateColumns: "repeat(4, 1fr)" }}>
          {STATS.map((stat, i) => (
            <div key={i} style={{ padding: "36px 24px", textAlign: "center", borderRight: i < 3 ? "1px solid rgba(255,255,255,0.06)" : "none" }}>
              <div style={{ fontSize: "clamp(28px, 4vw, 42px)", fontWeight: "900", letterSpacing: "-1.5px", color: "#f8fafc", fontVariantNumeric: "tabular-nums" }}>
                {counts[i].toLocaleString()}{stat.suffix}
              </div>
              <div style={{ fontSize: "13px", color: "#64748b", marginTop: "6px", fontWeight: "500" }}>{stat.label}</div>
            </div>
          ))}
        </div>
      </section>

      {/* ── Platforms ── */}
      <section id="platforms" style={{ position: "relative", zIndex: 1, maxWidth: "1200px", margin: "0 auto", padding: "120px 48px" }}>
        <div style={{ marginBottom: "72px" }}>
          <div style={{ fontSize: "12px", fontWeight: "700", color: "#64748b", letterSpacing: "2px", textTransform: "uppercase", marginBottom: "16px" }}>// Three Specialized Engines</div>
          <h2 style={{ fontSize: "clamp(32px, 4vw, 48px)", fontWeight: "900", letterSpacing: "-1.5px", maxWidth: "560px", lineHeight: "1.1" }}>
            Purpose-Built for{" "}
            <span style={{ background: "linear-gradient(135deg, #f04e23, #ff8c63)", WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent" }}>Enterprise Security</span>
          </h2>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: "2px" }}>
          {PLATFORMS.map((platform, index) => {
            const Icon = platform.icon;
            const isAlt = index % 2 !== 0;
            return (
              <div key={platform.id}
                style={{ background: "rgba(15,23,42,0.85)", border: "1px solid rgba(255,255,255,0.08)", backdropFilter: "blur(12px)", willChange: "transform, opacity", borderRadius: "20px", overflow: "hidden", marginBottom: "24px", transition: "border-color 0.3s" }}
                onMouseEnter={e => (e.currentTarget.style.borderColor = platform.borderColor)}
                onMouseLeave={e => (e.currentTarget.style.borderColor = "rgba(255,255,255,0.07)")}>
                <div style={{ display: "grid", gridTemplateColumns: isAlt ? "1fr 1.2fr" : "1.2fr 1fr", gap: "0" }}>

                  {/* Text Block */}
                  <div style={{ order: isAlt ? 1 : 0, padding: "56px", display: "flex", flexDirection: "column", justifyContent: "center" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "14px", marginBottom: "24px" }}>
                      <div style={{ width: "48px", height: "48px", borderRadius: "12px", background: platform.glowColor, border: `1px solid ${platform.borderColor}`, display: "flex", alignItems: "center", justifyContent: "center" }}>
                        <Icon size={24} color={platform.accentColor} />
                      </div>
                      <div>
                        <div style={{ fontSize: "20px", fontWeight: "800", letterSpacing: "-0.5px" }}>{platform.name}</div>
                        <div style={{ fontSize: "13px", color: platform.accentColor, fontWeight: "600", marginTop: "2px" }}>{platform.tagline}</div>
                      </div>
                    </div>
                    <p style={{ fontSize: "15px", color: "#94a3b8", lineHeight: "1.75", marginBottom: "36px", fontWeight: "400" }}>
                      {platform.description}
                    </p>
                    <a href={token ? platform.href : "#"} onClick={e => { if (!token) { e.preventDefault(); setShowAuth(true); } }}
                      style={{ display: "inline-flex", alignItems: "center", gap: "8px", padding: "11px 22px", background: "transparent", color: platform.accentColor, border: `1px solid ${platform.borderColor}`, borderRadius: "9px", fontWeight: "700", fontSize: "14px", textDecoration: "none", width: "fit-content", transition: "all 0.2s" }}
                      onMouseEnter={e => { const a = e.currentTarget; a.style.background = platform.glowColor; a.style.transform = "translateX(4px)"; }}
                      onMouseLeave={e => { const a = e.currentTarget; a.style.background = "transparent"; a.style.transform = "translateX(0)"; }}>
                      Launch {platform.name} <ArrowRight size={14} />
                    </a>
                  </div>

                  {/* Features Block */}
                  <div style={{ order: isAlt ? 0 : 1, padding: "56px", borderLeft: isAlt ? "none" : "1px solid rgba(255,255,255,0.07)", borderRight: isAlt ? "1px solid rgba(255,255,255,0.07)" : "none", background: "rgba(2,6,23,0.4)" }}>
                    <div style={{ fontSize: "11px", fontWeight: "700", color: "#64748b", letterSpacing: "1.5px", textTransform: "uppercase", marginBottom: "24px" }}>Core Capabilities</div>
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "14px" }}>
                      {platform.features.map((feat, fi) => {
                        const FIcon = feat.icon;
                        return (
                          <div key={fi} style={{ display: "flex", alignItems: "flex-start", gap: "10px", padding: "12px", background: "rgba(255,255,255,0.02)", borderRadius: "8px", border: "1px solid rgba(255,255,255,0.04)" }}>
                            <div style={{ marginTop: "2px", flexShrink: 0 }}>
                              <FIcon size={14} color={platform.accentColor} />
                            </div>
                            <span style={{ fontSize: "12px", color: "#94a3b8", lineHeight: "1.5", fontWeight: "500" }}>{feat.label}</span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </section>

      {/* ── Capabilities Section ── */}
      <section id="capabilities" style={{ position: "relative", zIndex: 1, background: "rgba(15,23,42,0.4)", borderTop: "1px solid rgba(255,255,255,0.06)", borderBottom: "1px solid rgba(255,255,255,0.06)" }}>
        <div style={{ maxWidth: "1200px", margin: "0 auto", padding: "100px 48px" }}>
          <div style={{ textAlign: "center", marginBottom: "72px" }}>
            <div style={{ fontSize: "12px", fontWeight: "700", color: "#64748b", letterSpacing: "2px", textTransform: "uppercase", marginBottom: "16px" }}>// Platform Architecture</div>
            <h2 style={{ fontSize: "clamp(28px, 4vw, 44px)", fontWeight: "900", letterSpacing: "-1.5px" }}>
              Built for the Modern{" "}
              <span style={{ background: "linear-gradient(135deg, #3b82f6, #60a5fa)", WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent" }}>Security Stack</span>
            </h2>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "16px" }}>
            {[
              { title: "AI-Native Architecture", desc: "Every platform layer is built around AI-first principles — not bolted on. Local LLM inference via Ollama ensures zero data egress.", icon: Zap, color: "#f04e23" },
              { title: "Graph-Powered Intelligence", desc: "Neo4j knowledge graphs map relationships between assets, vulnerabilities, and threat actors — revealing attack paths invisible to scanners.", icon: GitBranch, color: "#10b981" },
              { title: "Multi-Layer Observability", desc: "Full-stack observability with Prometheus, Grafana, and Loki. Every event, scan, and decision is logged and queryable.", icon: Activity, color: "#3b82f6" },
              { title: "Evidence-First Reporting", desc: "All scan artifacts, raw tool outputs, and AI-generated reports are stored in MinIO (S3-compatible) for compliance and forensic auditing.", icon: Database, color: "#f59e0b" },
              { title: "Blazing Fast Search", desc: "All findings are indexed into OpenSearch, enabling sub-second querying across millions of vulnerability records and log events.", icon: Eye, color: "#8b5cf6" },
              { title: "Autonomous Orchestration", desc: "Goal-based Mission Planner breaks down high-level security objectives into specific tool chains, dispatched and managed autonomously.", icon: Target, color: "#ec4899" },
            ].map((cap, i) => {
              const CIcon = cap.icon;
              return (
                <div key={i}
                  style={{ padding: "32px", background: "rgba(2,6,23,0.6)", border: "1px solid rgba(255,255,255,0.06)", borderRadius: "14px", transition: "all 0.3s" }}
                  onMouseEnter={e => { const d = e.currentTarget; d.style.borderColor = "rgba(255,255,255,0.15)"; d.style.transform = "translateY(-4px)"; d.style.background = "rgba(15,23,42,0.8)"; }}
                  onMouseLeave={e => { const d = e.currentTarget; d.style.borderColor = "rgba(255,255,255,0.06)"; d.style.transform = "translateY(0)"; d.style.background = "rgba(2,6,23,0.6)"; }}>
                  <div style={{ width: "40px", height: "40px", borderRadius: "10px", background: `${cap.color}15`, display: "flex", alignItems: "center", justifyContent: "center", marginBottom: "20px", border: `1px solid ${cap.color}30` }}>
                    <CIcon size={20} color={cap.color} />
                  </div>
                  <div style={{ fontSize: "15px", fontWeight: "700", marginBottom: "10px", letterSpacing: "-0.3px" }}>{cap.title}</div>
                  <div style={{ fontSize: "13px", color: "#64748b", lineHeight: "1.65", fontWeight: "400" }}>{cap.desc}</div>
                </div>
              );
            })}
          </div>
        </div>
      </section>

      {/* ── CTA ── */}
      <section style={{ position: "relative", zIndex: 1, maxWidth: "1200px", margin: "0 auto", padding: "120px 48px" }}>
        <div style={{
          textAlign: "center", padding: "80px 48px",
          background: "radial-gradient(ellipse 80% 60% at 50% 50%, rgba(240,78,35,0.08), transparent)",
          border: "1px solid rgba(240,78,35,0.15)", borderRadius: "24px",
        }}>
          <div style={{ fontSize: "12px", fontWeight: "700", color: "#f04e23", letterSpacing: "2px", textTransform: "uppercase", marginBottom: "20px" }}>// Get Started</div>
          <h2 style={{ fontSize: "clamp(30px, 4vw, 48px)", fontWeight: "900", letterSpacing: "-1.5px", marginBottom: "20px" }}>
            Autonomous Security,<br /> Starting Now
          </h2>
          <p style={{ fontSize: "16px", color: "#94a3b8", marginBottom: "40px", maxWidth: "480px", margin: "0 auto 40px" }}>
            Connect your infrastructure and let the Saga ecosystem continuously monitor, analyze, and respond — without manual intervention.
          </p>
          <div style={{ display: "flex", gap: "14px", justifyContent: "center" }}>
            <button onClick={() => token ? window.location.href = "/dashboard" : setShowAuth(true)}
              style={{ display: "flex", alignItems: "center", gap: "8px", padding: "14px 28px", background: "#f04e23", color: "white", border: "none", borderRadius: "10px", fontWeight: "700", fontSize: "15px", cursor: "pointer", boxShadow: "0 0 24px rgba(240,78,35,0.35)", transition: "all 0.2s" }}
              onMouseEnter={e => { const b = e.currentTarget; b.style.transform = "translateY(-2px)"; }}
              onMouseLeave={e => { const b = e.currentTarget; b.style.transform = "translateY(0)"; }}>
              {token ? "Open Dashboard" : "Create Account"} <ArrowRight size={16} />
            </button>
          </div>
        </div>
      </section>

      {/* ── Footer ── */}
      <footer style={{ position: "relative", zIndex: 1, borderTop: "1px solid rgba(255,255,255,0.06)", padding: "32px 48px", display: "flex", alignItems: "center", justifyContent: "space-between", maxWidth: "none" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
          <div style={{ width: "24px", height: "24px", background: "#f04e23", borderRadius: "6px", display: "flex", alignItems: "center", justifyContent: "center" }}>
            <Shield size={14} color="white" />
          </div>
          <span style={{ fontWeight: "700", fontSize: "14px" }}>Saga<span style={{ color: "#f04e23" }}>AI</span></span>
          <span style={{ color: "#1e293b", margin: "0 8px" }}>|</span>
          <span style={{ fontSize: "12px", color: "#334155" }}>Enterprise Security Platform</span>
        </div>
        <div style={{ fontSize: "12px", color: "#334155" }}>
          Built with FastAPI · Next.js · Ollama · ChromaDB · Neo4j · OpenSearch
        </div>
      </footer>

      {/* ── Auth Modal ── */}
      {showAuth && <AuthModal onClose={() => setShowAuth(false)} onSuccess={handleAuthSuccess} />}

      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700;800;900&display=swap');
        @keyframes pulse { 0%,100%{opacity:1;} 50%{opacity:0.4;} }
        @keyframes fadeInUp { from{opacity:0;transform:translateY(16px);} to{opacity:1;transform:translateY(0);} }
      `}</style>
    </div>
  );
}
