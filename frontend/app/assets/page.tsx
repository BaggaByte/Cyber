"use client";
import { useState, useEffect } from "react";
import Cookies from "js-cookie";
import { useQuery } from "@tanstack/react-query";
import { Target, ExternalLink } from "lucide-react";
import Sidebar from "../components/Sidebar";

const API = "";

interface AssetItem {
  asset_id: string;
  target?: string;
  asset_type?: string;
  scan_count?: number;
  last_risk_score?: string;
  discovered_at?: string;
}

export default function AssetsPage() {
  const token = Cookies.get("token");
  
  const { data: assets = [], isLoading: loading } = useQuery({
    queryKey: ['assets'],
    queryFn: async () => {
      const res = await fetch(`/api/assets`, { headers: { "Authorization": `Bearer ${token}` } });
      if (!res.ok) throw new Error("Failed to fetch");
      const data = await res.json();
      return Array.isArray(data) ? data : [];
    },
    enabled: !!token,
  });

  if (!token) {
    if (typeof window !== 'undefined') window.location.href = "/";
    return null;
  }

  return (
    <div style={{ display: "flex", minHeight: "100vh" }}>
      <Sidebar />
      <main style={{ marginLeft: 220, flex: 1, padding: "32px 40px" }}>
        <div style={{ marginBottom: 32, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <div>
            <h1 style={{ fontSize: 26, fontWeight: 700 }}>Asset Inventory</h1>
            <p style={{ color: "var(--text-secondary)", marginTop: 4, fontSize: 14 }}>
              {assets.length} assets mapped to your organization
            </p>
          </div>
          <Target size={20} color="var(--blue)" />
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(300px, 1fr))", gap: 16 }}>
          {loading && Array.from({ length: 3 }).map((_, i) => (
            <div key={i} style={{
              background: "var(--bg-card)", border: "1px solid var(--border)",
              borderRadius: 12, padding: 24, height: 120,
              animation: "pulse 1.5s ease-in-out infinite",
            }} />
          ))}

          {!loading && assets.length === 0 && (
            <div style={{
              gridColumn: "1/-1", padding: 60, textAlign: "center",
              color: "var(--text-muted)", fontSize: 14
            }}>
              No assets discovered yet. Run a scan to start mapping your attack surface.
            </div>
          )}

          {assets.map(asset => (
            <div key={asset.asset_id} style={{
              background: "var(--bg-card)", border: "1px solid var(--border)",
              borderRadius: 12, padding: 24,
              transition: "border-color 0.15s, background 0.15s",
            }}
              onMouseEnter={e => {
                (e.currentTarget as HTMLDivElement).style.borderColor = "rgba(59,130,246,0.4)";
                (e.currentTarget as HTMLDivElement).style.background = "var(--bg-card-hover)";
              }}
              onMouseLeave={e => {
                (e.currentTarget as HTMLDivElement).style.borderColor = "var(--border)";
                (e.currentTarget as HTMLDivElement).style.background = "var(--bg-card)";
              }}
            >
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 16 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                  <div style={{
                    width: 36, height: 36, borderRadius: 8,
                    background: "var(--blue-glow)", display: "flex", alignItems: "center", justifyContent: "center"
                  }}>
                    <Target size={16} color="var(--blue)" />
                  </div>
                  <div>
                    <div style={{ fontFamily: "monospace", fontSize: 14, fontWeight: 600 }}>{asset.target}</div>
                    <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 2 }}>{asset.asset_type}</div>
                  </div>
                </div>
                <ExternalLink size={14} color="var(--text-muted)" />
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
                <div style={{ background: "var(--bg-surface)", borderRadius: 8, padding: "10px 12px" }}>
                  <div style={{ fontSize: 10, color: "var(--text-muted)", marginBottom: 4, textTransform: "uppercase", letterSpacing: "0.06em" }}>Scans</div>
                  <div style={{ fontSize: 18, fontWeight: 700 }}>{asset.scan_count}</div>
                </div>
                <div style={{ background: "var(--bg-surface)", borderRadius: 8, padding: "10px 12px" }}>
                  <div style={{ fontSize: 10, color: "var(--text-muted)", marginBottom: 4, textTransform: "uppercase", letterSpacing: "0.06em" }}>Last Risk</div>
                  {asset.last_risk_score ? (
                    <span className={`risk-${asset.last_risk_score.toLowerCase()}`}
                      style={{ fontSize: 11, fontWeight: 700, padding: "2px 8px", borderRadius: 4 }}>
                      {asset.last_risk_score}
                    </span>
                  ) : <span style={{ fontSize: 12, color: "var(--text-muted)" }}>None</span>}
                </div>
              </div>

              <div style={{ marginTop: 12, fontSize: 11, color: "var(--text-muted)" }}>
                Discovered {asset.discovered_at ? new Date(asset.discovered_at).toLocaleDateString() : "Unknown"}
              </div>
            </div>
          ))}
        </div>
      </main>
    </div>
  );
}
