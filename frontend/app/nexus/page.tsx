"use client";
import { useEffect, useState } from "react";
import Cookies from "js-cookie";
import Link from "next/link";
import { ArrowLeft } from "lucide-react";

export default function NexusPage() {
  const [token, setToken] = useState<string | null>(null);

  useEffect(() => {
    const savedToken = Cookies.get("token");
    if (!savedToken) {
      window.location.href = "/";
    } else {
      setToken(savedToken);
    }
  }, []);

  if (!token) return <div style={{ color: "white", padding: "40px" }}>Authenticating...</div>;

  return (
    <div style={{ display: "flex", height: "100vh", backgroundColor: "var(--bg-base)", position: "relative" }}>

      <div style={{ flexGrow: 1, overflow: "hidden" }}>
        <iframe 
          src="http://localhost:5173/" 
          style={{ width: "100%", height: "100%", border: "none" }}
          title="Nexus AI Dashboard"
        />
      </div>
    </div>
  );
}
