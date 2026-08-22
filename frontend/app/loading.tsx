import { Activity } from "lucide-react";
import Sidebar from "./components/Sidebar";

export default function Loading() {
  return (
    <div style={{ display: "flex", minHeight: "100vh", background: "var(--bg-main)" }}>
      <Sidebar />
      <main style={{ marginLeft: 220, flex: 1, display: "flex", alignItems: "center", justifyContent: "center" }}>
        <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 16 }}>
          <Activity size={32} color="var(--accent-primary)" style={{ animation: "pulse 1.5s infinite" }} />
          <span style={{ color: "var(--text-muted)", fontSize: 14, fontWeight: 500, letterSpacing: 0.5 }}>
            Loading modules...
          </span>
        </div>
      </main>
    </div>
  );
}
