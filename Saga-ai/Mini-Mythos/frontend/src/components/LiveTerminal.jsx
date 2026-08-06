import React, { useEffect, useRef, useState, useCallback } from 'react';
import { Terminal, Trash2, ArrowDown, Wifi, WifiOff } from 'lucide-react';
import { wsUrl } from '../config';

function classifyLog(msg, component) {
  const c = (component || '').toLowerCase();
  const m = (msg || '').toLowerCase();
  if (c === 'system') return 'log-line-system';
  if (c === 'orchestrator') return 'log-line-orchestrator';
  if (c === 'mcp') return 'log-line-mcp';
  if (c === 'recon' || m.includes('recon') || m.includes('crawl')) return 'log-line-recon';
  if (c === 'grc') return 'log-line-grc';
  if (m.includes('error') || m.includes('fail') || m.includes('critical')) return 'log-line-error';
  if (m.includes('warn')) return 'log-line-warning';
  return 'log-line-default';
}

export default function LiveTerminal() {
  const [logs, setLogs] = useState([]);
  const [connected, setConnected] = useState(false);
  const [autoScroll, setAutoScroll] = useState(true);
  const [filter, setFilter] = useState('');
  const bodyRef = useRef(null);
  const wsRef = useRef(null);

  const connect = useCallback(() => {
    if (wsRef.current) {
      wsRef.current.close();
    }
    const ws = new WebSocket(wsUrl('/ws/global'));
    wsRef.current = ws;

    ws.onopen = () => setConnected(true);
    ws.onclose = () => {
      setConnected(false);
      // Reconnect after 3s
      setTimeout(connect, 3000);
    };
    ws.onerror = () => ws.close();
    ws.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data);
        if (data.message === 'keepalive') return;
        setLogs(prev => [...prev.slice(-500), { // keep last 500 lines
          id: Date.now() + Math.random(),
          timestamp: data.timestamp || new Date().toISOString(),
          level: data.level || 'INFO',
          component: data.component || '',
          message: data.message || '',
        }]);
      } catch {}
    };
  }, []);

  useEffect(() => {
    connect();
    return () => wsRef.current?.close();
  }, [connect]);

  // Auto-scroll
  useEffect(() => {
    if (autoScroll && bodyRef.current) {
      bodyRef.current.scrollTop = bodyRef.current.scrollHeight;
    }
  }, [logs, autoScroll]);

  const handleScroll = () => {
    if (!bodyRef.current) return;
    const { scrollTop, scrollHeight, clientHeight } = bodyRef.current;
    setAutoScroll(scrollHeight - scrollTop - clientHeight < 60);
  };

  const displayed = filter
    ? logs.filter(l =>
        l.message.toLowerCase().includes(filter.toLowerCase()) ||
        l.component.toLowerCase().includes(filter.toLowerCase())
      )
    : logs;

  const fmtTime = (iso) => {
    try {
      return new Date(iso).toLocaleTimeString('en-US', { hour12: false });
    } catch { return ''; }
  };

  return (
    <div className="flex-col" style={{ gap: 'var(--sp-4)' }}>
      {/* Controls */}
      <div className="card" style={{ padding: 'var(--sp-3) var(--sp-5)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--sp-4)', flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            {connected
              ? <Wifi size={14} style={{ color: 'var(--c-emerald)' }} />
              : <WifiOff size={14} style={{ color: 'var(--c-critical)' }} />
            }
            <span style={{ fontSize: 12, color: connected ? 'var(--c-emerald)' : 'var(--c-critical)' }}>
              {connected ? 'Live — System Feed Connected' : 'Reconnecting...'}
            </span>
          </div>

          <div className="search-input-wrap" style={{ minWidth: 220 }}>
            <input
              type="text"
              placeholder="Filter logs..."
              value={filter}
              onChange={e => setFilter(e.target.value)}
              style={{ paddingLeft: 12 }}
            />
          </div>

          <div style={{ display: 'flex', gap: 8, marginLeft: 'auto' }}>
            <button
              className="btn btn-ghost"
              style={{ padding: '4px 12px', fontSize: 12 }}
              onClick={() => setAutoScroll(v => !v)}
              title="Toggle auto-scroll"
            >
              <ArrowDown size={13} style={{ color: autoScroll ? 'var(--c-primary)' : 'inherit' }} />
              {autoScroll ? 'Auto-Scroll ON' : 'Auto-Scroll OFF'}
            </button>
            <button
              className="btn btn-ghost"
              style={{ padding: '4px 12px', fontSize: 12 }}
              onClick={() => setLogs([])}
            >
              <Trash2 size={13} />
              Clear
            </button>
          </div>
        </div>
      </div>

      {/* Terminal Window */}
      <div className="terminal-window">
        <div className="terminal-topbar">
          <div className="terminal-dots">
            <div className="terminal-dot terminal-dot-red" />
            <div className="terminal-dot terminal-dot-amber" />
            <div className="terminal-dot terminal-dot-green" />
          </div>
          <span className="terminal-title">NEXUS AI — SYSTEM TERMINAL v2.0</span>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'rgba(56,189,248,0.4)' }}>
            {displayed.length} lines
          </span>
        </div>

        <div className="terminal-body" ref={bodyRef} onScroll={handleScroll}>
          {displayed.length === 0 && (
            <span className="log-line-default">
              {connected ? '> Waiting for system events...' : '> Connecting to system feed...'}
            </span>
          )}
          {displayed.map(log => (
            <span key={log.id} className={`log-line ${classifyLog(log.message, log.component)}`}>
              <span className="log-timestamp">{fmtTime(log.timestamp)}</span>
              {log.component && (
                <span className="log-component">[{log.component}]</span>
              )}
              {log.message}
            </span>
          ))}
          {connected && logs.length > 0 && (
            <span className="log-line log-line-system" style={{ opacity: 0.4 }}>
              {'> '}
              <span style={{ animation: 'pulse 1s infinite' }}>█</span>
            </span>
          )}
        </div>
      </div>
    </div>
  );
}
