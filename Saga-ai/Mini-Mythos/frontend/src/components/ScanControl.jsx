import React, { useState, useRef, useEffect } from 'react';
import { Play, Square, Activity, Terminal, Settings2, Zap, ChevronDown, ChevronUp } from 'lucide-react';
import { API_BASE, wsUrl } from '../config';

// Estimate scan progress from log content
function estimateProgress(logs) {
  const markers = [
    { text: 'run_recon_crawl', pct: 15 },
    { text: "Tool 'run_recon_crawl' completed", pct: 30 },
    { text: 'execute_nuclei_fuzz', pct: 40 },
    { text: "Tool 'execute_nuclei_fuzz' completed", pct: 60 },
    { text: 'execute_custom_fuzzer', pct: 65 },
    { text: "Tool 'execute_custom_fuzzer' completed", pct: 80 },
    { text: 'generate_hypothesis', pct: 85 },
    { text: 'GRC Report saved', pct: 95 },
    { text: 'Audit Cycle Completed', pct: 100 },
  ];
  let best = 5;
  for (const log of logs) {
    const msg = log.message || '';
    for (const m of markers) {
      if (msg.includes(m.text) && m.pct > best) best = m.pct;
    }
  }
  return best;
}

function classifyLine(log) {
  const c = (log.component || '').toLowerCase();
  const m = (log.message || '').toLowerCase();
  if (log.level === 'ERROR' || m.includes('error') || m.includes('fail')) return 'log-line-error';
  if (log.level === 'WARNING') return 'log-line-warning';
  if (c === 'system') return 'log-line-system';
  if (c === 'orchestrator') return 'log-line-orchestrator';
  if (c === 'mcp') return 'log-line-mcp';
  if (c === 'grc') return 'log-line-grc';
  if (c === 'recon' || m.includes('crawl') || m.includes('recon')) return 'log-line-recon';
  return 'log-line-default';
}

export default function ScanControl({ onScanComplete }) {
  const [target, setTarget] = useState('');
  const [status, setStatus] = useState('IDLE');
  const [logs, setLogs] = useState([]);
  const [error, setError] = useState(null);
  const [progress, setProgress] = useState(0);
  const [showOptions, setShowOptions] = useState(false);
  const [depth, setDepth] = useState('full');   // 'quick' | 'full'
  const [scanId, setScanId] = useState(null);
  const ws = useRef(null);
  const logEndRef = useRef(null);

  const startScan = async (e) => {
    e.preventDefault();
    if (!target) return;
    setStatus('STARTING');
    setError(null);
    setLogs([]);
    setProgress(5);

    try {
      const res = await fetch(`${API_BASE}/api/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target }),
      });
      if (!res.ok) {
        let detail = await res.text();
        try {
          const parsed = JSON.parse(detail);
          detail = parsed.detail?.[0]?.msg || parsed.detail || detail;
        } catch { /* keep raw text */ }
        throw new Error(detail);
      }
      const data = await res.json();
      setScanId(data.scan_id);
      connectWebSocket(data.scan_id);
      setStatus('RUNNING');
    } catch (err) {
      setError(`Failed to connect to backend: ${err.message}`);
      setStatus('IDLE');
      setProgress(0);
    }
  };

  const cancelScan = async () => {
    if (!scanId) return;
    try {
      await fetch(`${API_BASE}/api/scan/${scanId}/cancel`, { method: 'POST' });
    } catch {}
    ws.current?.close();
    setStatus('IDLE');
    setProgress(0);
  };

  const connectWebSocket = (id) => {
    ws.current = new WebSocket(wsUrl(`/ws/scan/${id}`));
    ws.current.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        if (msg.message === 'keepalive') return;
        setLogs(prev => {
          const next = [...prev, msg];
          setProgress(estimateProgress(next));
          return next;
        });
        if (msg.message && (msg.message.includes('Audit Cycle Completed') || msg.message.includes('FAILED'))) {
          setStatus('COMPLETED');
          setProgress(100);
          onScanComplete?.();
        }
      } catch {
        setLogs(prev => [...prev, { level: 'INFO', component: 'SYSTEM', message: event.data }]);
      }
    };
    ws.current.onclose = () => {
      if (status !== 'COMPLETED') setStatus(s => s === 'RUNNING' ? 'COMPLETED' : s);
    };
  };

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  useEffect(() => {
    return () => { if (ws.current) ws.current.close(); };
  }, []);

  const isRunning = status === 'RUNNING';

  return (
    <div className="card" style={{ marginBottom: 'var(--sp-8)' }}>
      <div className="card-header">
        <h2 className="card-title">
          <Activity size={16} style={{ color: 'var(--c-emerald)' }} />
          Autonomous Audit Engine
        </h2>
        {isRunning && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, color: 'var(--c-primary)' }}>
            <span className="spin-slow" style={{ display: 'inline-block' }}>
              <Zap size={13} />
            </span>
            AI Scanning — {progress}%
          </div>
        )}
      </div>

      <div className="card-body">
        {/* Input row */}
        <form onSubmit={startScan} style={{ display: 'flex', gap: 'var(--sp-3)', marginBottom: 'var(--sp-4)' }}>
          <div className="flex-1 form-group" style={{ marginBottom: 0 }}>
            <input
              type="url"
              required
              placeholder="https://target.com"
              value={target}
              onChange={e => setTarget(e.target.value)}
              disabled={isRunning}
              className="form-input"
            />
          </div>
          <button
            type="button"
            className="btn btn-ghost"
            style={{ padding: '0 12px' }}
            onClick={() => setShowOptions(v => !v)}
            title="Scan options"
          >
            <Settings2 size={16} />
            {showOptions ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
          </button>
          {isRunning ? (
            <button type="button" onClick={cancelScan} className="btn btn-ghost" style={{ color: 'var(--c-critical)', borderColor: 'var(--c-critical)' }}>
              <Square size={16} /> Cancel
            </button>
          ) : (
            <button type="submit" disabled={isRunning} className="btn btn-primary">
              <Play size={16} />
              {status === 'STARTING' ? 'Starting...' : 'Launch Scan'}
            </button>
          )}
        </form>

        {/* Options panel */}
        {showOptions && (
          <div className="scan-options" style={{ marginBottom: 'var(--sp-4)' }}>
            <div className="scan-option-group">
              <label>Depth</label>
              <div className="depth-toggle">
                <button className={depth === 'quick' ? 'active' : ''} onClick={() => setDepth('quick')}>Quick</button>
                <button className={depth === 'full' ? 'active' : ''} onClick={() => setDepth('full')}>Full</button>
              </div>
            </div>
            <div className="scan-option-group">
              <label style={{ color: 'var(--c-text-muted)', fontSize: 11 }}>
                {depth === 'quick'
                  ? '⚡ Quick: Recon + basic fuzz (~2–3 min)'
                  : '🔬 Full: All tools + AI hypothesis (~8–12 min)'}
              </label>
            </div>
          </div>
        )}

        {/* Progress bar */}
        {(isRunning || (status === 'COMPLETED' && progress > 0)) && (
          <div style={{ marginBottom: 'var(--sp-4)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, color: 'var(--c-text-muted)', marginBottom: 4 }}>
              <span>{status === 'COMPLETED' ? 'Scan Complete' : 'Scan in Progress'}</span>
              <span style={{ fontFamily: 'var(--font-mono)' }}>{progress}%</span>
            </div>
            <div className="progress-bar-wrapper">
              <div className="progress-bar-fill" style={{ width: `${progress}%` }} />
            </div>
          </div>
        )}

        {error && <div className="log-critical" style={{ marginBottom: 'var(--sp-4)' }}>{error}</div>}

        {/* Terminal */}
        <div className="terminal-window" style={{ height: 320 }}>
          <div className="terminal-topbar">
            <div className="terminal-dots">
              <div className="terminal-dot terminal-dot-red" />
              <div className="terminal-dot terminal-dot-amber" />
              <div className="terminal-dot terminal-dot-green" />
            </div>
            <span className="terminal-title">
              <Terminal size={11} style={{ display: 'inline', marginRight: 6 }} />
              SCAN_LOGS {scanId ? `— Scan #${scanId}` : ''}
            </span>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'rgba(56,189,248,0.4)' }}>
              {logs.length} events
            </span>
          </div>
          <div className="terminal-body">
            {logs.length === 0 && (
              <span className="log-line-default">{'> Awaiting target initialization...'}</span>
            )}
            {logs.map((log, i) => (
              <span key={i} className={`log-line ${classifyLine(log)}`}>
                <span className="log-component">[{log.component || 'SYSTEM'}]</span>
                {log.message}
              </span>
            ))}
            <div ref={logEndRef} />
          </div>
        </div>
      </div>
    </div>
  );
}
