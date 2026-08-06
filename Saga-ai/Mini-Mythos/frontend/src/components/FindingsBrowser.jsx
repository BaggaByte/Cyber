import React, { useEffect, useState } from 'react';
import { ShieldAlert, AlertTriangle, AlertCircle, Info, Search, ChevronDown, ChevronRight, Download } from 'lucide-react';
import { API_BASE } from '../config';

const SEVERITIES = ['all', 'critical', 'high', 'medium', 'low'];

function getSeverityBadge(severity) {
  const s = (severity || '').toLowerCase();
  if (s === 'critical') return <span className="badge badge-critical"><ShieldAlert size={11}/> Critical</span>;
  if (s === 'high')     return <span className="badge badge-high"><AlertTriangle size={11}/> High</span>;
  if (s === 'medium')   return <span className="badge badge-medium"><AlertCircle size={11}/> Medium</span>;
  return <span className="badge badge-low"><Info size={11}/> Low</span>;
}

function buildCodeSnippet(f) {
  if (f.payload_used) {
    return `# Payload injected at: ${f.endpoint || f.url || 'N/A'}\n${f.payload_used}`;
  }
  if (f.notes && f.notes.length > 20) {
    return `# Evidence:\n${f.notes.slice(0, 400)}`;
  }
  return null;
}

function FindingRow({ f }) {
  const [open, setOpen] = useState(false);
  const snippet = buildCodeSnippet(f);

  return (
    <div className="accordion-item">
      <div
        className="accordion-header"
        onClick={() => setOpen(v => !v)}
        style={{ cursor: 'pointer' }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flex: 1, minWidth: 0 }}>
          {open ? <ChevronDown size={14} style={{ flexShrink: 0 }} /> : <ChevronRight size={14} style={{ flexShrink: 0 }} />}
          <span style={{ fontWeight: 600, fontSize: 13, color: 'var(--c-text)', minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {f.vuln_name || f.vuln_type || 'Unknown Finding'}
          </span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--c-text-dim)' }}>#{f.scan_id}</span>
          {getSeverityBadge(f.severity)}
        </div>
      </div>

      {open && (
        <div className="finding-expand-row">
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 12, marginBottom: 12 }}>
            {f.endpoint && (
              <div>
                <div style={{ fontSize: 10, color: 'var(--c-text-dim)', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 2 }}>Endpoint</div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--c-text)', wordBreak: 'break-all' }}>{f.endpoint}</div>
              </div>
            )}
            {f.cwe && (
              <div>
                <div style={{ fontSize: 10, color: 'var(--c-text-dim)', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 2 }}>CWE</div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--c-high)' }}>{f.cwe}</div>
              </div>
            )}
            {f.source && (
              <div>
                <div style={{ fontSize: 10, color: 'var(--c-text-dim)', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 2 }}>Source</div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--c-text-muted)' }}>{f.source}</div>
              </div>
            )}
            {f.confidence && (
              <div>
                <div style={{ fontSize: 10, color: 'var(--c-text-dim)', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 2 }}>Confidence</div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--c-emerald)' }}>{f.confidence}</div>
              </div>
            )}
          </div>

          {f.description && (
            <p style={{ fontSize: 12, color: 'var(--c-text-muted)', marginBottom: snippet ? 12 : 0, lineHeight: 1.6 }}>
              {f.description}
            </p>
          )}

          {snippet && (
            <div>
              <div style={{ fontSize: 10, color: 'var(--c-text-dim)', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 4 }}>
                Evidence / Payload
              </div>
              <div className="code-snippet">{snippet}</div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function FindingsBrowser({ refreshKey = 0 }) {
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [severityFilter, setSeverityFilter] = useState('all');
  const [search, setSearch] = useState('');

  useEffect(() => {
    setLoading(true);
    fetch(`${API_BASE}/api/findings?limit=100`)
      .then(r => r.json())
      .then(d => setFindings(d.findings || []))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [refreshKey]);

  const filtered = findings.filter(f => {
    if (severityFilter !== 'all' && (f.severity || '').toLowerCase() !== severityFilter) return false;
    if (search) {
      const q = search.toLowerCase();
      return (
        (f.vuln_name || '').toLowerCase().includes(q) ||
        (f.vuln_type || '').toLowerCase().includes(q) ||
        (f.endpoint || '').toLowerCase().includes(q) ||
        (f.description || '').toLowerCase().includes(q)
      );
    }
    return true;
  });

  const counts = findings.reduce((acc, f) => {
    const s = (f.severity || 'low').toLowerCase();
    acc[s] = (acc[s] || 0) + 1;
    return acc;
  }, {});

  const severityColors = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e' };

  return (
    <div className="card" style={{ maxHeight: 800, display: 'flex', flexDirection: 'column' }}>
      <div className="card-header" style={{ flexShrink: 0 }}>
        <h2 className="card-title">
          <ShieldAlert size={16} style={{ color: '#ef4444' }} />
          Vulnerability Findings
          <span style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--c-text-muted)', fontWeight: 400 }}>
            ({filtered.length}/{findings.length})
          </span>
        </h2>
        {findings.length > 0 && (
          <a
            href={`${API_BASE}/api/findings/${findings[0]?.scan_id}/export?fmt=csv`}
            className="btn btn-ghost"
            style={{ padding: '4px 10px', fontSize: 11, textDecoration: 'none' }}
            title="Export as CSV"
          >
            <Download size={12} /> Export
          </a>
        )}
      </div>

      {/* Filters */}
      <div style={{ padding: '0 var(--sp-5) var(--sp-3)', flexShrink: 0 }}>
        <div className="filter-bar">
          {SEVERITIES.map(s => {
            const count = s === 'all' ? findings.length : (counts[s] || 0);
            const activeClass = severityFilter === s
              ? s === 'all' ? 'active' : `active-${s}`
              : '';
            return (
              <button
                key={s}
                className={`filter-pill ${activeClass}`}
                onClick={() => setSeverityFilter(s)}
                style={{ borderColor: s !== 'all' && severityFilter !== s ? severityColors[s] + '44' : undefined }}
              >
                {s === 'all' ? 'All' : s} {count > 0 && <span style={{ opacity: 0.7 }}>({count})</span>}
              </button>
            );
          })}
          <div className="search-input-wrap">
            <Search size={13} className="search-icon" />
            <input
              type="text"
              placeholder="Search findings..."
              value={search}
              onChange={e => setSearch(e.target.value)}
            />
          </div>
        </div>
      </div>

      {/* List */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '0 var(--sp-5) var(--sp-5)' }}>
        {loading && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {[1,2,3].map(i => <div key={i} className="skeleton" style={{ height: 52 }} />)}
          </div>
        )}
        {!loading && filtered.length === 0 && (
          <div className="empty-state">
            <div className="empty-state-text">
              {findings.length === 0 ? 'No vulnerabilities found yet' : 'No results match your filter'}
            </div>
          </div>
        )}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          {filtered.map(f => <FindingRow key={f.id} f={f} />)}
        </div>
      </div>
    </div>
  );
}
