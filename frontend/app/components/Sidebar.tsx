"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import Cookies from "js-cookie";
import { useState, useEffect } from "react";
import {
  LayoutDashboard, Shield, Target, BrainCircuit,
  MessageSquare, LogOut, Activity, BarChart2, Settings,
  Calendar, ChevronRight, Crosshair
} from "lucide-react";
import ThemeSwitcher from "./ThemeSwitcher";

const NAV = [
  { href: "/dashboard",   label: "Dashboard",      icon: LayoutDashboard },
  { href: "/missions",    label: "Autonomous Missions", icon: Crosshair },
  { href: "/scans",       label: "Scan History",   icon: Shield },
  { href: "/assets",      label: "Assets",         icon: Target },
  { href: "/schedule",    label: "Scheduling",     icon: Calendar },
  { href: "/orchestrate", label: "AI Orchestrate", icon: BrainCircuit },
  { href: "/chat",        label: "AI Copilot",     icon: MessageSquare },
  { href: "/reports",     label: "Reports",        icon: BarChart2 },
  { href: "/settings",    label: "Settings",       icon: Settings },
];

export default function Sidebar() {
  const path = usePathname();
  const [profile, setProfile] = useState<any>(null);

  useEffect(() => {
    const token = Cookies.get("token");
    if (!token) return;
    fetch("/api/me", {
      headers: { Authorization: `Bearer ${token}` }
    })
      .then(r => r.json())
      .then(d => { if (d?.email) setProfile(d); })
      .catch(() => {});
  }, []);

  const handleLogout = () => {
    Cookies.remove("token");
    window.location.href = "/";
  };

  return (
    <aside style={{
      width: 240,
      height: "100vh",
      background: "var(--bg-sidebar)",
      borderRight: "1px solid var(--border)",
      display: "flex",
      flexDirection: "column",
      position: "fixed",
      top: 0,
      left: 0,
      zIndex: 100,
      overflowY: "auto",
      overflowX: "hidden",
    }}>

      {/* ── Logo ── */}
      <div style={{
        padding: "20px 20px 16px",
        borderBottom: "1px solid rgba(255,255,255,0.06)",
        flexShrink: 0,
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <div style={{
            width: 34, height: 34, borderRadius: 9,
            background: "var(--accent-primary)",
            display: "flex", alignItems: "center", justifyContent: "center",
            boxShadow: "0 0 16px rgba(240,78,35,0.4)",
            flexShrink: 0,
          }}>
            <Activity size={18} color="#fff" />
          </div>
          <div>
            <div style={{
              fontWeight: 800, fontSize: 15, letterSpacing: "-0.03em",
              color: "#f8fafc",
            }}>
              Sentinel<span style={{ color: "var(--accent-primary)" }}>AI</span>
            </div>
            <div style={{ fontSize: 9, color: "#475569", marginTop: 1, letterSpacing: "1.5px", textTransform: "uppercase" }}>
              Enterprise SecOps
            </div>
          </div>
        </div>
      </div>

      {/* ── Nav Label ── */}
      <div style={{ padding: "14px 20px 6px", fontSize: 9, fontWeight: 700, color: "#334155", letterSpacing: "1.5px", textTransform: "uppercase" }}>
        Navigation
      </div>

      {/* ── Nav Links ── */}
      <nav style={{ flex: 1, padding: "0 10px", display: "flex", flexDirection: "column", gap: 2 }}>
        {NAV.map(({ href, label, icon: Icon }) => {
          const active = path === href || path.startsWith(href + "/");
          return (
            <Link
              key={href}
              href={href}
              style={{
                display: "flex", alignItems: "center", gap: 10,
                padding: "9px 12px", borderRadius: 8,
                background: active ? "rgba(240,78,35,0.15)" : "transparent",
                color: active ? "var(--accent-primary)" : "#64748b",
                textDecoration: "none", fontSize: 13,
                fontWeight: active ? 600 : 400,
                transition: "all 0.15s ease",
                borderLeft: active ? "2px solid var(--accent-primary)" : "2px solid transparent",
              }}
              onMouseEnter={e => {
                if (!active) {
                  (e.currentTarget as HTMLAnchorElement).style.background = "rgba(255,255,255,0.04)";
                  (e.currentTarget as HTMLAnchorElement).style.color = "#cbd5e1";
                }
              }}
              onMouseLeave={e => {
                if (!active) {
                  (e.currentTarget as HTMLAnchorElement).style.background = "transparent";
                  (e.currentTarget as HTMLAnchorElement).style.color = "#64748b";
                }
              }}
            >
              <Icon
                size={15}
                style={{ flexShrink: 0 }}
                color={active ? "var(--accent-primary)" : "currentColor"}
              />
              <span style={{ flex: 1 }}>{label}</span>
              {active && <ChevronRight size={12} style={{ opacity: 0.6 }} />}
            </Link>
          );
        })}
      </nav>

      {/* ── Divider ── */}
      <div style={{ margin: "8px 16px", borderTop: "1px solid rgba(255,255,255,0.06)" }} />

      {/* ── User Profile Strip ── */}
      {profile ? (
        <div style={{
          padding: "10px 14px",
          display: "flex", alignItems: "center", gap: 10,
          flexShrink: 0,
        }}>
          <div style={{
            width: 32, height: 32, borderRadius: "50%", flexShrink: 0,
            background: "linear-gradient(135deg, var(--accent-primary), #d03b17)",
            display: "flex", alignItems: "center", justifyContent: "center",
            fontSize: 13, fontWeight: 800, color: "#fff",
            boxShadow: "0 0 10px rgba(240,78,35,0.3)",
          }}>
            {profile.email?.[0]?.toUpperCase()}
          </div>
          <div style={{ overflow: "hidden", flex: 1 }}>
            <div style={{
              fontSize: 12, fontWeight: 600, color: "#e2e8f0",
              whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis",
            }}>
              {profile.email}
            </div>
            <div style={{ fontSize: 10, color: "#475569", marginTop: 2, textTransform: "capitalize" }}>
              {profile.role} · {profile.org_name}
            </div>
          </div>
        </div>
      ) : (
        <div style={{ padding: "10px 14px" }} />
      )}

      {/* ── Sign Out & Theme Switcher ── */}
      <div style={{ padding: "4px 10px 16px", flexShrink: 0, display: "flex", alignItems: "center", gap: 8 }}>
        <button
          onClick={handleLogout}
          style={{
            flex: 1, display: "flex", alignItems: "center", gap: 10,
            padding: "9px 12px", borderRadius: 8,
            background: "transparent",
            border: "none",
            color: "#475569", fontSize: 13, cursor: "pointer",
            transition: "all 0.15s", fontFamily: "inherit",
            textAlign: "left",
          }}
          onMouseEnter={e => {
            (e.currentTarget as HTMLButtonElement).style.background = "rgba(239,68,68,0.08)";
            (e.currentTarget as HTMLButtonElement).style.color = "#ef4444";
          }}
          onMouseLeave={e => {
            (e.currentTarget as HTMLButtonElement).style.background = "transparent";
            (e.currentTarget as HTMLButtonElement).style.color = "#475569";
          }}
        >
          <LogOut size={15} style={{ flexShrink: 0 }} />
          Sign Out
        </button>
        <ThemeSwitcher />
      </div>

    </aside>
  );
}
