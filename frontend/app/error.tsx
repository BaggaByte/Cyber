"use client";
import { useEffect } from "react";
import { AlertTriangle } from "lucide-react";
import Sidebar from "./components/Sidebar";

export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    // Log the error to an error reporting service in production
    console.error("Global Error Boundary caught:", error);
  }, [error]);

  return (
    <div style={{ display: "flex", minHeight: "100vh", background: "var(--bg-main)" }}>
      <Sidebar />
      <main style={{ marginLeft: 220, flex: 1, display: "flex", alignItems: "center", justifyContent: "center", padding: 40 }}>
        <div className="glass-card" style={{ padding: 40, textAlign: "center", maxWidth: 500, borderColor: "rgba(239, 68, 68, 0.4)" }}>
          <div style={{ display: "flex", justifyContent: "center", marginBottom: 20 }}>
            <div style={{ padding: 16, background: "rgba(239, 68, 68, 0.1)", borderRadius: "50%" }}>
              <AlertTriangle size={32} color="#ef4444" />
            </div>
          </div>
          <h2 style={{ fontSize: 24, fontWeight: 700, marginBottom: 12 }}>Something went wrong</h2>
          <p style={{ color: "var(--text-secondary)", marginBottom: 24, fontSize: 14 }}>
            An unexpected error occurred in the application. We've logged this issue for review.
          </p>
          <div style={{ display: "flex", gap: 12, justifyContent: "center" }}>
            <button
              onClick={() => reset()}
              className="btn-primary"
            >
              Try again
            </button>
            <button
              onClick={() => window.location.href = "/dashboard"}
              style={{
                padding: "10px 20px", background: "var(--bg-base)", color: "var(--text-primary)",
                border: "1px solid var(--border)", borderRadius: 8, fontWeight: 600, cursor: "pointer"
              }}
            >
              Return to Dashboard
            </button>
          </div>
        </div>
      </main>
    </div>
  );
}
