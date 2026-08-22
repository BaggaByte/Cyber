"use client";
import { useState, useEffect } from "react";
import Cookies from "js-cookie";
import {
  Building, Bell, Key, Save, CheckCircle,
  AlertTriangle, Eye, EyeOff, Cpu, LogOut
} from "lucide-react";
import Sidebar from "../components/Sidebar";

const API = "";

interface SettingSectionProps {
  title: string;
  description: string;
  icon: React.ElementType;
  children: React.ReactNode;
}

function SettingSection({ title, description, icon: Icon, children }: SettingSectionProps) {
  return (
    <div className="glass-card" style={{ padding: 0, overflow: "hidden", marginBottom: 20 }}>
      <div style={{ padding: "20px 28px", borderBottom: "1px solid var(--border)", display: "flex", alignItems: "center", gap: 12 }}>
        <div style={{ width: 38, height: 38, borderRadius: 10, background: "rgba(240,78,35,0.08)", display: "flex", alignItems: "center", justifyContent: "center" }}>
          <Icon size={18} color="var(--accent-primary)" />
        </div>
        <div>
          <div style={{ fontWeight: 700, fontSize: 15 }}>{title}</div>
          <div style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 2 }}>{description}</div>
        </div>
      </div>
      <div style={{ padding: "24px 28px" }}>{children}</div>
    </div>
  );
}

interface FormRowProps {
  label: string;
  hint?: string;
  children: React.ReactNode;
}

function FormRow({ label, hint, children }: FormRowProps) {
  return (
    <div style={{ display: "grid", gridTemplateColumns: "1fr 2fr", gap: 24, alignItems: "start", paddingBottom: 20, marginBottom: 20, borderBottom: "1px solid var(--border)" }}>
      <div>
        <div style={{ fontWeight: 600, fontSize: 13, color: "var(--text-primary)" }}>{label}</div>
        {hint && <div style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 4, lineHeight: 1.5 }}>{hint}</div>}
      </div>
      <div>{children}</div>
    </div>
  );
}

function Toggle({ value, onChange }: { value: boolean; onChange: (v: boolean) => void }) {
  return (
    <button
      onClick={() => onChange(!value)}
      style={{
        width: 44, height: 24, borderRadius: 12, cursor: "pointer",
        background: value ? "var(--accent-primary)" : "var(--border)",
        border: "none", position: "relative", transition: "background 0.2s", padding: 0,
      }}
    >
      <div style={{
        width: 18, height: 18, borderRadius: "50%", background: "#fff",
        position: "absolute", top: 3,
        left: value ? 23 : 3,
        transition: "left 0.2s",
        boxShadow: "0 1px 4px rgba(0,0,0,0.2)"
      }} />
    </button>
  );
}

interface NotifsState {
  slackEnabled: boolean;
  slackWebhook: string;
  teamsEnabled: boolean;
  teamsWebhook: string;
  emailAlerts: boolean;
  criticalOnly: boolean;
}

export default function SettingsPage() {
  const token = Cookies.get("token");
  const [profile, setProfile] = useState<Record<string, unknown> | null>(null);
  const [saved, setSaved] = useState<string | null>(null);

  // Notification settings (stored locally for now)
  const [notifs, setNotifs] = useState<NotifsState>(() => {
    if (typeof window === "undefined") {
      return { slackEnabled: false, slackWebhook: "", teamsEnabled: false, teamsWebhook: "", emailAlerts: true, criticalOnly: false };
    }
    try {
      const saved = JSON.parse(localStorage.getItem("sentinelai_settings") || "{}");
      return {
        slackEnabled: false,
        slackWebhook: "",
        teamsEnabled: false,
        teamsWebhook: "",
        emailAlerts: true,
        criticalOnly: false,
        ...(saved.notifs || {}),
      };
    } catch {
      return { slackEnabled: false, slackWebhook: "", teamsEnabled: false, teamsWebhook: "", emailAlerts: true, criticalOnly: false };
    }
  });

  // Security settings
  const [showKey, setShowKey] = useState(false);
  const [apiKey] = useState("sentinelai_sk_9f8e7d6c5b4a3f2e1d0c9b8a");

  useEffect(() => {
    if (!token) { window.location.href = "/"; return; }
    fetch(`${API}/api/me`, { headers: { Authorization: `Bearer ${token}` } })
      .then(r => r.json()).then(setProfile).catch(console.error);
  }, [token]);

  const saveSettings = () => {
    localStorage.setItem("sentinelai_settings", JSON.stringify({ notifs }));
    setSaved("settings");
    setTimeout(() => setSaved(null), 3000);
  };

  const handleLogout = () => {
    Cookies.remove("token");
    window.location.href = "/";
  };

  return (
    <div style={{ display: "flex", minHeight: "100vh" }}>
      <Sidebar />
      <main style={{ marginLeft: 240, flex: 1, padding: "40px", maxWidth: 900 }}>

        {/* Header */}
        <div className="animate-slide-up" style={{ marginBottom: 32 }}>
          <h1 style={{ fontSize: 32, fontWeight: 800, letterSpacing: "-1px" }}>
            Platform <span className="text-gradient">Settings</span>
          </h1>
          <p style={{ color: "var(--text-secondary)", marginTop: 8, fontSize: 15 }}>
            Manage your organization, notifications, integrations, and security preferences
          </p>
        </div>

        {/* Save Banner */}
        {saved && (
          <div style={{
            display: "flex", alignItems: "center", gap: 10,
            padding: "12px 20px", borderRadius: 10, marginBottom: 20,
            background: "rgba(16,185,129,0.08)", border: "1px solid rgba(16,185,129,0.25)",
            color: "#059669", fontSize: 13, fontWeight: 600,
            animation: "fadeInUp 0.3s ease",
          }}>
            <CheckCircle size={16} />
            Settings saved successfully
          </div>
        )}

        {/* Profile & Organization */}
        <div className="animate-slide-up delay-100">
          <SettingSection title="Profile & Organization" description="Your account identity and organization details" icon={Building}>
            <FormRow label="Email Address" hint="Your login email address">
              <input
                className="input-glass" disabled
                value={profile?.email || "Loading..."}
                style={{ width: "100%", padding: "10px 14px", fontSize: 13, background: "var(--bg-base)", color: "var(--text-muted)" }}
              />
            </FormRow>
            <FormRow label="Organization" hint="Your security workspace name">
              <input
                className="input-glass" disabled
                value={profile?.org_name || "Loading..."}
                style={{ width: "100%", padding: "10px 14px", fontSize: 13, background: "var(--bg-base)", color: "var(--text-muted)" }}
              />
            </FormRow>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 2fr", gap: 24, alignItems: "start" }}>
              <div>
                <div style={{ fontWeight: 600, fontSize: 13, color: "var(--text-primary)" }}>Access Level</div>
                <div style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 4 }}>Your RBAC role in this organization</div>
              </div>
              <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
                <span style={{ padding: "6px 14px", borderRadius: 20, fontSize: 12, fontWeight: 700, background: "rgba(240,78,35,0.08)", color: "var(--accent-primary)", border: "1px solid rgba(240,78,35,0.2)", textTransform: "capitalize" }}>
                  {profile?.role || "analyst"}
                </span>
                <span style={{ padding: "6px 14px", borderRadius: 20, fontSize: 12, fontWeight: 700, background: "rgba(14,165,233,0.08)", color: "#0ea5e9", border: "1px solid rgba(14,165,233,0.2)", textTransform: "capitalize" }}>
                  {profile?.org_tier || "enterprise"}
                </span>
              </div>
            </div>
          </SettingSection>
        </div>

        {/* Notifications */}
        <div className="animate-slide-up delay-200">
          <SettingSection title="Alerts & Notifications" description="Configure where SentinelAI sends security alerts" icon={Bell}>
            <FormRow label="Slack Webhook" hint="Receive critical vulnerability alerts in Slack">
              <div style={{ display: "flex", gap: 10, alignItems: "center", marginBottom: 10 }}>
                <span style={{ fontSize: 12, fontWeight: 600, color: "var(--text-muted)" }}>Enable Slack</span>
                <Toggle value={notifs.slackEnabled} onChange={v => setNotifs(n => ({ ...n, slackEnabled: v }))} />
              </div>
              {notifs.slackEnabled && (
                <input
                  className="input-glass"
                  placeholder="https://hooks.slack.com/services/..."
                  value={notifs.slackWebhook}
                  onChange={e => setNotifs(n => ({ ...n, slackWebhook: e.target.value }))}
                  style={{ width: "100%", padding: "10px 14px", fontSize: 13 }}
                />
              )}
            </FormRow>

            <FormRow label="Microsoft Teams" hint="Receive alerts in your Teams channel">
              <div style={{ display: "flex", gap: 10, alignItems: "center", marginBottom: 10 }}>
                <span style={{ fontSize: 12, fontWeight: 600, color: "var(--text-muted)" }}>Enable Teams</span>
                <Toggle value={notifs.teamsEnabled} onChange={v => setNotifs(n => ({ ...n, teamsEnabled: v }))} />
              </div>
              {notifs.teamsEnabled && (
                <input
                  className="input-glass"
                  placeholder="https://outlook.office.com/webhook/..."
                  value={notifs.teamsWebhook}
                  onChange={e => setNotifs(n => ({ ...n, teamsWebhook: e.target.value }))}
                  style={{ width: "100%", padding: "10px 14px", fontSize: 13 }}
                />
              )}
            </FormRow>

            <FormRow label="Alert Threshold" hint="Which severity level triggers notifications">
              <div style={{ display: "flex", gap: 8 }}>
                {["All Findings", "Critical Only"].map((opt, i) => (
                  <button
                    key={opt}
                    onClick={() => setNotifs(n => ({ ...n, criticalOnly: i === 1 }))}
                    style={{
                      padding: "8px 16px", borderRadius: 8, cursor: "pointer",
                      border: `1px solid ${(i === 1) === notifs.criticalOnly ? "var(--accent-primary)" : "var(--border)"}`,
                      background: (i === 1) === notifs.criticalOnly ? "rgba(240,78,35,0.08)" : "transparent",
                      color: (i === 1) === notifs.criticalOnly ? "var(--accent-primary)" : "var(--text-secondary)",
                      fontSize: 13, fontWeight: 600, fontFamily: "inherit",
                      transition: "all 0.15s",
                    }}
                  >
                    {opt}
                  </button>
                ))}
              </div>
            </FormRow>
          </SettingSection>
        </div>

        {/* API Key */}
        <div className="animate-slide-up delay-300">
          <SettingSection title="API Access" description="Your API key for programmatic access and CI/CD integration" icon={Key}>
            <FormRow label="API Key" hint="Use this key to authenticate with the SentinelAI REST API from your pipeline or scripts">
              <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                <input
                  className="input-glass"
                  readOnly
                  type={showKey ? "text" : "password"}
                  value={apiKey}
                  style={{ flex: 1, padding: "10px 14px", fontSize: 13, fontFamily: "'JetBrains Mono', monospace" }}
                />
                <button
                  onClick={() => setShowKey(s => !s)}
                  style={{ padding: "10px 14px", borderRadius: 8, border: "1px solid var(--border)", background: "white", cursor: "pointer", color: "var(--text-secondary)" }}
                >
                  {showKey ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
              <div style={{ marginTop: 8, display: "flex", alignItems: "center", gap: 6, fontSize: 11, color: "var(--text-muted)" }}>
                <AlertTriangle size={12} />
                Never expose this key publicly. Rotate it immediately if compromised.
              </div>
            </FormRow>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 2fr", gap: 24, alignItems: "start" }}>
              <div>
                <div style={{ fontWeight: 600, fontSize: 13, color: "var(--text-primary)" }}>Endpoints</div>
                <div style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 4 }}>Base API URL</div>
              </div>
              <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, background: "var(--bg-base)", padding: "10px 14px", borderRadius: 8, border: "1px solid var(--border)", color: "var(--text-secondary)" }}>
                {API}
              </div>
            </div>
          </SettingSection>
        </div>

        {/* Platform Info */}
        <div className="animate-slide-up delay-400">
          <SettingSection title="Platform Information" description="SentinelAI version and component status" icon={Cpu}>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
              {[
                { label: "Platform", value: "SentinelAI Enterprise v1.0" },
                { label: "Backend", value: "FastAPI + Celery + LangGraph" },
                { label: "AI Engine", value: "Ollama / Llama 3.1-8b + CrewAI" },
                { label: "Database", value: "PostgreSQL + PGVector + Neo4j" },
                { label: "Observability", value: "Prometheus + Grafana + Loki" },
                { label: "Tools Registry", value: "13 security tools active" },
              ].map(({ label, value }) => (
                <div key={label} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "12px 0", borderBottom: "1px solid var(--border)" }}>
                  <span style={{ fontSize: 13, color: "var(--text-secondary)" }}>{label}</span>
                  <span style={{ fontSize: 13, fontWeight: 600, color: "var(--text-primary)" }}>{value}</span>
                </div>
              ))}
            </div>
          </SettingSection>
        </div>

        {/* Action Buttons */}
        <div className="animate-slide-up delay-500" style={{ display: "flex", justifyContent: "space-between", alignItems: "center", paddingTop: 8 }}>
          <button onClick={handleLogout} style={{
            display: "flex", alignItems: "center", gap: 8,
            padding: "10px 20px", borderRadius: 8, cursor: "pointer",
            background: "rgba(239,68,68,0.06)", border: "1px solid rgba(239,68,68,0.2)",
            color: "#dc2626", fontSize: 13, fontWeight: 600, fontFamily: "inherit",
            transition: "all 0.2s",
          }}>
            <LogOut size={14} />
            Sign Out
          </button>
          <button onClick={saveSettings} className="btn-primary" style={{ display: "flex", alignItems: "center", gap: 8, padding: "10px 24px" }}>
            <Save size={14} />
            Save Settings
          </button>
        </div>

      </main>
    </div>
  );
}
