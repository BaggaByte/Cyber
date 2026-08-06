"use client";
import { useState, useRef, useEffect } from "react";
import Cookies from "js-cookie";
import { Send, Bot, User, Activity } from "lucide-react";
import Sidebar from "../components/Sidebar";

const API = "";

interface Message {
  role: "user" | "assistant";
  content: string;
  scans?: any[];
  timestamp: Date;
}

export default function ChatPage() {
  const [messages, setMessages] = useState<Message[]>([
    {
      role: "assistant",
      content: "**SentinelAI Copilot online.**\n\nI am connected to the autonomous orchestration engine. Tell me what you want to scan.\n\n*Example:* \"Map the attack surface of example.com\"",
      timestamp: new Date(),
    }
  ]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);
  const token = Cookies.get("token");

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const extractTarget = (text: string) => {
    const match = text.match(/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
    return match ? match[1] : "127.0.0.1"; // Default fallback
  };

  const sendMessage = async () => {
    if (!input.trim() || loading) return;
    const userMsg: Message = { role: "user", content: input, timestamp: new Date() };
    setMessages(prev => [...prev, userMsg]);
    const currentInput = input;
    setInput("");
    setLoading(true);

    try {
      const target = extractTarget(currentInput);
      
      const res = await fetch(`${API}/api/orchestrate`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({
          goal: currentInput,
          target: target,
        }),
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Orchestration failed");
      }
      
      const data = await res.json();
      
      let reply = `I have analyzed your goal: **"${data.goal}"** against target \`${target}\`.\n\n`;
      reply += `**AI Reasoning:**\n${data.planner_reasoning}\n\n`;
      reply += `Dispatched **${data.tasks_dispatched}** scan tasks.`;

      setMessages(prev => [...prev, { 
        role: "assistant", 
        content: reply, 
        scans: data.scans,
        timestamp: new Date() 
      }]);
    } catch (err: any) {
      setMessages(prev => [...prev, {
        role: "assistant",
        content: `⚠️ **Error triggering orchestration:** ${err.message}`,
        timestamp: new Date(),
      }]);
    } finally {
      setLoading(false);
    }
  };

  const formatMessage = (content: string) => {
    return content
      .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
      .replace(/\*(.*?)\*/g, '<em>$1</em>')
      .replace(/`(.*?)`/g, '<code class="mono text-gradient" style="background:var(--bg-card);padding:2px 6px;border-radius:4px;font-size:12px">$1</code>')
      .replace(/\n/g, '<br/>');
  };

  return (
    <div style={{ display: "flex", minHeight: "100vh" }}>
      <Sidebar />
      <main style={{ marginLeft: "240px", flex: 1, display: "flex", flexDirection: "column", height: "100vh", position: "relative" }}>
        
        {/* Header */}
        <div className="glass-panel" style={{
          padding: "24px 40px", borderBottom: "1px solid var(--border)",
          display: "flex", alignItems: "center", gap: "16px", zIndex: 10
        }}>
          <div style={{
            width: "48px", height: "48px", borderRadius: "12px",
            background: "linear-gradient(135deg, var(--accent-primary), var(--accent-secondary))",
            display: "flex", alignItems: "center", justifyContent: "center",
            boxShadow: "0 0 20px var(--glow-accent)"
          }}>
            <Bot size={24} color="#fff" />
          </div>
          <div>
            <div style={{ fontWeight: 800, fontSize: "18px", letterSpacing: "-0.5px" }}>SentinelAI Copilot</div>
            <div style={{ fontSize: "13px", color: "var(--text-muted)", marginTop: "2px" }}>Autonomous Orchestration Engine · CrewAI Powered</div>
          </div>
          <div style={{
            marginLeft: "auto", display: "flex", alignItems: "center", gap: "8px",
            fontSize: "12px", color: "var(--emerald)", fontWeight: 600,
            background: "rgba(16,185,129,0.1)", padding: "6px 12px", borderRadius: "20px",
            border: "1px solid rgba(16,185,129,0.2)"
          }}>
            <div style={{ width: 8, height: 8, borderRadius: "50%", background: "var(--emerald)", boxShadow: "0 0 8px var(--emerald)" }} />
            Engine Online
          </div>
        </div>

        {/* Messages Container */}
        <div style={{ flex: 1, overflowY: "auto", padding: "32px 40px", display: "flex", flexDirection: "column", gap: "24px" }}>
          {messages.map((msg, i) => (
            <div key={i} style={{
              display: "flex", gap: "16px", alignItems: "flex-start",
              flexDirection: msg.role === "user" ? "row-reverse" : "row",
            }}>
              <div style={{
                width: "40px", height: "40px", borderRadius: "12px", flexShrink: 0,
                background: msg.role === "assistant" ? "linear-gradient(135deg, var(--accent-primary), var(--accent-secondary))" : "var(--bg-card)",
                border: msg.role === "user" ? "1px solid var(--border)" : "none",
                display: "flex", alignItems: "center", justifyContent: "center",
                boxShadow: msg.role === "assistant" ? "0 4px 12px var(--glow-accent)" : "none"
              }}>
                {msg.role === "assistant" ? <Bot size={20} color="#fff" /> : <User size={20} color="var(--text-secondary)" />}
              </div>
              
              <div style={{ display: "flex", flexDirection: "column", gap: "12px", maxWidth: "75%", alignItems: msg.role === "user" ? "flex-end" : "flex-start" }}>
                <div className="glass-card" style={{
                  background: msg.role === "user" ? "rgba(59, 130, 246, 0.15)" : "var(--bg-card)",
                  borderColor: msg.role === "user" ? "rgba(59, 130, 246, 0.3)" : "var(--border)",
                  padding: "16px 20px",
                  fontSize: "14px", lineHeight: 1.6, color: "var(--text-primary)",
                  borderBottomRightRadius: msg.role === "user" ? 0 : "16px",
                  borderBottomLeftRadius: msg.role === "assistant" ? 0 : "16px",
                }}
                  dangerouslySetInnerHTML={{ __html: formatMessage(msg.content) }}
                />

                {/* Display Dispatched Scans visually if present */}
                {msg.scans && msg.scans.length > 0 && (
                  <div style={{ display: "flex", flexWrap: "wrap", gap: "12px", marginTop: "4px" }}>
                    {msg.scans.map((scan: any) => (
                      <div key={scan.scan_id} className="glass-panel" style={{
                        display: "flex", alignItems: "center", gap: "12px",
                        padding: "10px 14px", borderRadius: "8px",
                        borderLeft: "3px solid var(--accent-primary)"
                      }}>
                        <Activity size={16} color="var(--accent-primary)" />
                        <div>
                          <div style={{ fontSize: "12px", fontWeight: "bold", textTransform: "uppercase" }}>{scan.tool}</div>
                          <div className="mono" style={{ fontSize: "10px", color: "var(--text-muted)" }}>ID: {scan.scan_id}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          ))}
          
          {loading && (
            <div style={{ display: "flex", gap: "16px", alignItems: "center" }}>
              <div style={{
                width: "40px", height: "40px", borderRadius: "12px",
                background: "linear-gradient(135deg, var(--accent-primary), var(--accent-secondary))",
                display: "flex", alignItems: "center", justifyContent: "center",
                boxShadow: "0 4px 12px var(--glow-accent)"
              }}>
                <Bot size={20} color="#fff" />
              </div>
              <div className="glass-card" style={{ padding: "16px 20px", display: "flex", gap: "6px" }}>
                {[0, 1, 2].map(j => (
                  <div key={j} style={{
                    width: 8, height: 8, borderRadius: "50%", background: "var(--accent-primary)",
                    animation: `pulse-dot 1.4s infinite ease-in-out both`,
                    animationDelay: `${j * 0.16}s`
                  }} />
                ))}
              </div>
            </div>
          )}
          <div ref={bottomRef} />
        </div>

        {/* Input Area */}
        <div className="glass-panel" style={{
          padding: "24px 40px", borderTop: "1px solid var(--border)",
          zIndex: 10
        }}>
          <div style={{ display: "flex", gap: "16px", position: "relative" }}>
            <input
              type="text" value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={e => e.key === "Enter" && !e.shiftKey && sendMessage()}
              placeholder="E.g. Identify subdomains and scan for critical vulnerabilities on example.com..."
              className="input-glass"
              style={{ flex: 1, padding: "18px 24px", fontSize: "15px", borderRadius: "16px", paddingRight: "70px" }}
              disabled={loading}
            />
            <button onClick={sendMessage} disabled={loading || !input.trim()}
              className="btn-primary"
              style={{
                position: "absolute", right: "8px", top: "8px", bottom: "8px",
                borderRadius: "10px", padding: "0 20px",
                opacity: loading || !input.trim() ? 0.5 : 1,
              }}>
              <Send size={18} />
            </button>
          </div>
          <div style={{ marginTop: "12px", fontSize: "12px", color: "var(--text-muted)", textAlign: "center", fontWeight: 500 }}>
            Press Enter to orchestrate • Requests are dispatched to the multi-agent AI engine
          </div>
        </div>
      </main>

      <style>{`
        @keyframes pulse-dot {
          0%, 80%, 100% { transform: scale(0); opacity: 0.5; }
          40% { transform: scale(1); opacity: 1; }
        }
      `}</style>
    </div>
  );
}
