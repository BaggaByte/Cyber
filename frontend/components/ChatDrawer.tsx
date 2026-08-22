"use client";
import { useState, useRef, useEffect } from "react";
import Cookies from "js-cookie";
import { Send, Bot, User, Activity, X } from "lucide-react";
import { useChatStore } from "../store/useChatStore";
import { usePathname } from "next/navigation";

export default function ChatDrawer() {
  const { isOpen, toggleDrawer, messages, addMessage, context } = useChatStore();
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);
  const token = Cookies.get("token");
  const pathname = usePathname();

  // Add initial message if empty
  useEffect(() => {
    if (messages.length === 0) {
      addMessage({
        role: "assistant",
        content: "**SentinelAI Copilot online.**\n\nI am connected to the autonomous orchestration engine. Tell me what you want to scan.\n\n*Example:* \"Map the attack surface of example.com\"",
      });
    }
  }, [messages.length, addMessage]);

  useEffect(() => {
    if (isOpen) {
      bottomRef.current?.scrollIntoView({ behavior: "smooth" });
    }
  }, [messages, isOpen]);

  // Global shortcut to toggle drawer (Cmd+K)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        toggleDrawer();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [toggleDrawer]);

  const extractTarget = (text: string) => {
    const match = text.match(/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
    return match ? match[1] : "127.0.0.1";
  };

  const sendMessage = async () => {
    if (!input.trim() || loading) return;
    addMessage({ role: "user", content: input });
    const currentInput = input;
    setInput("");
    setLoading(true);

    try {
      const target = extractTarget(currentInput);
      
      const payload = {
        goal: currentInput,
        target: target,
        context: `User is on page: ${pathname}. ${context ? `Context: ${context}` : ''}`
      };

      const res = await fetch(`/api/orchestrate`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Authorization": `Bearer ${token}` },
        body: JSON.stringify(payload),
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Orchestration failed");
      }
      
      const data = await res.json();
      
      let reply = `I have analyzed your goal: **"${data.goal}"** against target \`${target}\`.\n\n`;
      reply += `**AI Reasoning:**\n${data.planner_reasoning}\n\n`;
      reply += `Dispatched **${data.tasks_dispatched}** scan tasks.`;

      addMessage({ 
        role: "assistant", 
        content: reply, 
        // @ts-ignore
        scans: data.scans,
      });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      addMessage({
        role: "assistant",
        content: `⚠️ **Error:** ${msg}`,
      });
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

  if (!isOpen) return null;

  return (
    <>
      <div 
        style={{
          position: "fixed", inset: 0, background: "rgba(0,0,0,0.5)",
          backdropFilter: "blur(4px)", zIndex: 9998,
          willChange: "opacity"
        }}
        onClick={toggleDrawer}
      />
      <div 
        className="glass-panel"
        style={{
          position: "fixed", right: 0, top: 0, bottom: 0, width: "450px",
          display: "flex", flexDirection: "column",
          zIndex: 9999, borderLeft: "1px solid var(--border)",
          transform: "translateX(0)", transition: "transform 0.3s ease-out",
          willChange: "transform"
        }}
      >
        <div style={{
          padding: "20px 24px", borderBottom: "1px solid var(--border)",
          display: "flex", alignItems: "center", justifyContent: "space-between"
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <div style={{
              width: 36, height: 36, borderRadius: 10,
              background: "linear-gradient(135deg, var(--accent-primary), var(--accent-secondary))",
              display: "flex", alignItems: "center", justifyContent: "center",
              boxShadow: "0 0 16px var(--glow-accent)"
            }}>
              <Bot size={18} color="#fff" />
            </div>
            <div>
              <div style={{ fontWeight: 700, fontSize: 16 }}>Nexus AI</div>
              <div style={{ fontSize: 11, color: "var(--text-muted)" }}>Context-Aware Copilot</div>
            </div>
          </div>
          <button 
            onClick={toggleDrawer}
            style={{ background: "transparent", border: "none", color: "var(--text-muted)", cursor: "pointer" }}
          >
            <X size={20} />
          </button>
        </div>

        <div style={{ flex: 1, overflowY: "auto", padding: "24px", display: "flex", flexDirection: "column", gap: 20 }}>
          {messages.map((msg, i) => (
            <div key={i} style={{
              display: "flex", gap: 12, alignItems: "flex-start",
              flexDirection: msg.role === "user" ? "row-reverse" : "row",
            }}>
              <div style={{
                width: 32, height: 32, borderRadius: 10, flexShrink: 0,
                background: msg.role === "assistant" ? "linear-gradient(135deg, var(--accent-primary), var(--accent-secondary))" : "var(--bg-card)",
                border: msg.role === "user" ? "1px solid var(--border)" : "none",
                display: "flex", alignItems: "center", justifyContent: "center"
              }}>
                {msg.role === "assistant" ? <Bot size={16} color="#fff" /> : <User size={16} color="var(--text-secondary)" />}
              </div>
              
              <div style={{ display: "flex", flexDirection: "column", gap: 8, maxWidth: "80%", alignItems: msg.role === "user" ? "flex-end" : "flex-start" }}>
                <div className="glass-card" style={{
                  background: msg.role === "user" ? "rgba(59, 130, 246, 0.15)" : "var(--bg-card)",
                  borderColor: msg.role === "user" ? "rgba(59, 130, 246, 0.3)" : "var(--border)",
                  padding: "12px 16px",
                  fontSize: 13, lineHeight: 1.5, color: "var(--text-primary)",
                  borderBottomRightRadius: msg.role === "user" ? 0 : 12,
                  borderBottomLeftRadius: msg.role === "assistant" ? 0 : 12,
                }}
                  dangerouslySetInnerHTML={{ __html: formatMessage(msg.content) }}
                />

                {/* @ts-ignore */}
                {msg.scans && msg.scans.length > 0 && (
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
                    {/* @ts-ignore */}
                    {msg.scans.map((scan) => (
                      <div key={String(scan.scan_id)} className="glass-panel" style={{
                        display: "flex", alignItems: "center", gap: 8, padding: "8px 12px", borderRadius: 6,
                        borderLeft: "2px solid var(--accent-primary)"
                      }}>
                        <Activity size={14} color="var(--accent-primary)" />
                        <div>
                          <div style={{ fontSize: 11, fontWeight: "bold", textTransform: "uppercase" }}>{scan.tool_used}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          ))}
          {loading && (
             <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
               <div style={{ width: 32, height: 32, borderRadius: 10, background: "var(--accent-primary)", display: "flex", alignItems: "center", justifyContent: "center" }}><Bot size={16} color="#fff" /></div>
               <div className="glass-card" style={{ padding: "12px 16px", display: "flex", gap: 6 }}>
                 {[0, 1, 2].map(j => <div key={j} style={{ width: 6, height: 6, borderRadius: "50%", background: "var(--accent-primary)", animation: `pulse-dot 1.4s infinite ease-in-out both`, animationDelay: `${j * 0.16}s` }} />)}
               </div>
             </div>
          )}
          <div ref={bottomRef} />
        </div>

        <div style={{ padding: "20px 24px", borderTop: "1px solid var(--border)" }}>
          <div style={{ display: "flex", gap: 12, position: "relative" }}>
            <input
              type="text" value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={e => e.key === "Enter" && !e.shiftKey && sendMessage()}
              placeholder="Ask Copilot (Cmd+K)..."
              className="input-glass"
              style={{ flex: 1, padding: "14px 18px", fontSize: 13, borderRadius: 12, paddingRight: 50 }}
              disabled={loading}
            />
            <button onClick={sendMessage} disabled={loading || !input.trim()}
              className="btn-primary"
              style={{
                position: "absolute", right: 6, top: 6, bottom: 6,
                borderRadius: 8, padding: "0 14px",
                opacity: loading || !input.trim() ? 0.5 : 1,
              }}>
              <Send size={14} />
            </button>
          </div>
        </div>
      </div>
    </>
  );
}
