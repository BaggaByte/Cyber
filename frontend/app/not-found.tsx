import Link from "next/link";
import { Search } from "lucide-react";
import Sidebar from "./components/Sidebar";

export default function NotFound() {
  return (
    <div style={{ display: "flex", minHeight: "100vh", background: "var(--bg-main)" }}>
      <Sidebar />
      <main style={{ marginLeft: 220, flex: 1, display: "flex", alignItems: "center", justifyContent: "center", padding: 40 }}>
        <div style={{ textAlign: "center", maxWidth: 400 }}>
          <div style={{ display: "flex", justifyContent: "center", marginBottom: 20 }}>
            <div style={{ padding: 20, background: "rgba(148, 163, 184, 0.1)", borderRadius: "50%" }}>
              <Search size={40} color="var(--text-muted)" />
            </div>
          </div>
          <h1 style={{ fontSize: 48, fontWeight: 800, marginBottom: 8, color: "var(--text-primary)" }}>404</h1>
          <h2 style={{ fontSize: 20, fontWeight: 600, marginBottom: 16 }}>Page Not Found</h2>
          <p style={{ color: "var(--text-secondary)", marginBottom: 32, fontSize: 15 }}>
            The page you are looking for doesn't exist or has been moved.
          </p>
          <Link href="/dashboard" className="btn-primary" style={{ display: "inline-block", textDecoration: "none" }}>
            Return to Dashboard
          </Link>
        </div>
      </main>
    </div>
  );
}
