import React, { useEffect, useState, useCallback } from 'react';
import { History, ExternalLink, CheckCircle, XCircle, Clock, Loader, Trash2, RefreshCw } from 'lucide-react';
import { API_BASE } from '../config';

const STATUS_MAP = {
  COMPLETED: { badge: 'badge badge-low',      icon: <CheckCircle size={12}/> },
  FAILED:    { badge: 'badge badge-critical',  icon: <XCircle size={12}/>    },
  QUEUED:    { badge: 'badge badge-medium',    icon: <Clock size={12}/>       },
  ENGAGED:   { badge: 'badge badge-high',      icon: <Loader size={12} style={{ animation: 'spin-slow 1s linear infinite' }}/> },
  CANCELLED: { badge: 'badge',                 icon: <XCircle size={12}/>    },
};

export default function ScanHistory({ refreshKey = 0, onRefresh }) {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [deleting, setDeleting] = useState(null);

  const load = useCallback(() => {
    setLoading(true);
    fetch(`${API_BASE}/api/scans?limit=20`)
      .then(r => r.json())
      .then(d => setScans(d.scans || []))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => { load(); }, [refreshKey, load]);

  const handleDelete = async (id) => {
    if (!window.confirm(`Delete scan #${id} and all its findings?`)) return;
    setDeleting(id);
    try {
      const res = await fetch(`${API_BASE}/api/scan/${id}`, { method: 'DELETE' });
      if (res.ok) {
        setScans(prev => prev.filter(s => s.id !== id));
        onRefresh?.();
      }
    } catch {}
    setDeleting(null);
  };

  const fmtDate = (iso) => {
    try {
      return new Date(iso).toLocaleString('en-US', {
        month: 'short', day: '2-digit',
        hour: '2-digit', minute: '2-digit',
      });
    } catch { return iso; }
  };

  return (
    <div className="card">
      <div className="card-header">
        <h2 className="card-title">
          <History size={16} style={{ color: '#38bdf8' }} />
          Audit History
          {loading && <Loader size={12} style={{ animation: 'spin-slow 1s linear infinite', opacity: 0.5 }} />}
        </h2>
        <button className="btn btn-ghost" style={{ padding: '4px 10px', fontSize: 11 }} onClick={load} title="Refresh">
          <RefreshCw size={12} />
        </button>
      </div>

      <div style={{ overflowX: 'auto' }}>
        <table className="data-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Target</th>
              <th>Status</th>
              <th>Findings</th>
              <th>Date</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading && scans.length === 0 && (
              [1,2,3].map(i => (
                <tr key={i}>
                  <td colSpan={6}><div className="skeleton" style={{ height: 20, borderRadius: 4 }} /></td>
                </tr>
              ))
            )}
            {!loading && scans.length === 0 && (
              <tr>
                <td colSpan={6}>
                  <div className="empty-state"><div className="empty-state-text">No scans yet</div></div>
                </td>
              </tr>
            )}
            {scans.map(scan => {
              const s = STATUS_MAP[scan.status] || STATUS_MAP.QUEUED;
              return (
                <tr key={scan.id}>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>#{scan.id}</td>
                  <td style={{ maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {scan.target}
                  </td>
                  <td>
                    <span className={s.badge} style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                      {s.icon} {scan.status}
                    </span>
                  </td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                    {scan.vulns_found > 0 ? (
                      <span style={{ color: scan.critical_count > 0 ? 'var(--c-critical)' : 'var(--c-high)' }}>
                        {scan.vulns_found}
                        {scan.critical_count > 0 && ` (${scan.critical_count}C)`}
                      </span>
                    ) : '—'}
                  </td>
                  <td style={{ color: 'var(--c-text-muted)', fontSize: 11 }}>{fmtDate(scan.timestamp)}</td>
                  <td>
                    <div style={{ display: 'flex', gap: 4 }}>
                      {scan.report_filename && (
                        <a
                          href={`${API_BASE}/api/scan/${scan.id}/report`}
                          target="_blank"
                          rel="noreferrer"
                          className="btn btn-ghost"
                          style={{ padding: '3px 8px', fontSize: 11 }}
                        >
                          <ExternalLink size={11} /> Report
                        </a>
                      )}
                      <button
                        className="btn btn-ghost"
                        style={{ padding: '3px 8px', fontSize: 11, color: 'var(--c-critical)' }}
                        onClick={() => handleDelete(scan.id)}
                        disabled={deleting === scan.id}
                        title="Delete scan"
                      >
                        <Trash2 size={11} />
                      </button>
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
