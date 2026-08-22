"use client";
import { useEffect, useState } from "react";
import Cookies from "js-cookie";
import { FileCheck, Download } from "lucide-react";
import Sidebar from "../components/Sidebar";

export default function NexusPage() {
  const [token, setToken] = useState<string | null>(null);
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    const t = Cookies.get("token") || null;
    setToken(t);
    setMounted(true);
    if (!t) window.location.href = "/";
  }, []);

  if (!mounted) return null;

  const isoControls = [
    { code: "A.5.1", title: "Information Security Policies", status: "COMPLIANT", score: "100%" },
    { code: "A.8.2", title: "Privileged Access Rights", status: "COMPLIANT", score: "100%" },
    { code: "A.8.8", title: "Management of Technical Vulnerabilities", status: "ACTION REQUIRED", score: "82%" },
    { code: "A.8.20", title: "Network Security & Segmentation", status: "COMPLIANT", score: "96%" },
    { code: "A.8.28", title: "Secure Coding & SAST Practices", status: "COMPLIANT", score: "94%" },
  ];

  return (
    <div style={{ display: "flex", minHeight: "100vh" }}>
      <Sidebar />
      <main style={{ marginLeft: 240, flex: 1, padding: "32px 40px" }}>
        <div style={{ marginBottom: 32, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
              <div style={{ width: 40, height: 40, borderRadius: 10, background: "rgba(14,165,233,0.15)", display: "flex", alignItems: "center", justifyContent: "center" }}>
                <FileCheck size={22} color="#0ea5e9" />
              </div>
              <h1 style={{ fontSize: 28, fontWeight: 800 }}>Nexus AI <span className="text-gradient">GRC &amp; ISO 27001</span></h1>
            </div>
            <p style={{ color: "var(--text-secondary)", marginTop: 6, fontSize: 14 }}>
              Autonomous compliance tracking, policy auditing, and GRC reporting
            </p>
          </div>
          <button onClick={() => window.print()} className="btn-primary" style={{ display: "flex", alignItems: "center", gap: 8, padding: "10px 18px", fontSize: 13 }}>
            <Download size={14} /> Export ISO Audit Report
          </button>
        </div>

        {/* Overview Stats */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 20, marginBottom: 28 }}>
          <div className="glass-card" style={{ padding: 24 }}>
            <div style={{ fontSize: 13, color: "var(--text-muted)", fontWeight: 600 }}>Overall ISO 27001 Compliance</div>
            <div style={{ fontSize: 32, fontWeight: 800, color: "var(--emerald)", marginTop: 4 }}>94.4%</div>
          </div>
          <div className="glass-card" style={{ padding: 24 }}>
            <div style={{ fontSize: 13, color: "var(--text-muted)", fontWeight: 600 }}>Controls Audited</div>
            <div style={{ fontSize: 32, fontWeight: 800, color: "var(--text-primary)", marginTop: 4 }}>93 / 93</div>
          </div>
          <div className="glass-card" style={{ padding: 24 }}>
            <div style={{ fontSize: 13, color: "var(--text-muted)", fontWeight: 600 }}>Open Evidence Findings</div>
            <div style={{ fontSize: 32, fontWeight: 800, color: "var(--amber)", marginTop: 4 }}>2</div>
          </div>
        </div>

        {/* ISO Controls Table */}
        <div className="glass-card" style={{ padding: 0, overflow: "hidden" }}>
          <div style={{ padding: "18px 24px", borderBottom: "1px solid var(--border)", fontWeight: 700, fontSize: 15 }}>
            ISO 27001:2022 Control Audit Summary
          </div>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr style={{ borderBottom: "1px solid var(--border)", background: "var(--bg-base)" }}>
                {["Control Code", "Control Name", "Compliance Status", "Score"].map(h => (
                  <th key={h} style={{ padding: "12px 20px", textAlign: "left", fontSize: 11, color: "var(--text-muted)", fontWeight: 600, textTransform: "uppercase" }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {isoControls.map((c, i) => (
                <tr key={i} style={{ borderTop: "1px solid var(--border)" }}>
                  <td style={{ padding: "14px 20px", fontFamily: "monospace", fontSize: 12, fontWeight: 700, color: "var(--accent-primary)" }}>{c.code}</td>
                  <td style={{ padding: "14px 20px", fontSize: 13, fontWeight: 600, color: "var(--text-primary)" }}>{c.title}</td>
                  <td style={{ padding: "14px 20px" }}>
                    <span style={{
                      padding: "4px 10px", borderRadius: 20, fontSize: 11, fontWeight: 700,
                      background: c.status === "COMPLIANT" ? "rgba(16,185,129,0.1)" : "rgba(245,158,11,0.1)",
                      color: c.status === "COMPLIANT" ? "var(--emerald)" : "var(--amber)",
                      border: `1px solid ${c.status === "COMPLIANT" ? "rgba(16,185,129,0.2)" : "rgba(245,158,11,0.2)"}`
                    }}>
                      {c.status}
                    </span>
                  </td>
                  <td style={{ padding: "14px 20px", fontFamily: "monospace", fontSize: 13, fontWeight: 700 }}>{c.score}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </main>
    </div>
  );
}
