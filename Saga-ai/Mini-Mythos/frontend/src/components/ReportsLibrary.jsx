import React, { useEffect, useState } from 'react';
import { FileText, Eye, Download, Trash2, ShieldAlert, AlertTriangle } from 'lucide-react';
import { API_BASE } from '../config';

function ScanBadge({ status }) {
  const map = {
    COMPLETED: { label: 'Completed', cls: 'badge badge-low' },
    FAILED: { label: 'Failed', cls: 'badge badge-critical' },
    QUEUED: { label: 'Queued', cls: 'badge badge-medium' },
    ENGAGED: { label: 'Running', cls: 'badge badge-high' },
    CANCELLED: { label: 'Cancelled', cls: 'badge badge-medium' },
  };
  const b = map[status] || { label: status, cls: 'badge' };
  return <span className={b.cls}>{b.label}</span>;
}

export default function ReportsLibrary() {
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(true);
  const [previewScanId, setPreviewScanId] = useState(null);

  const load = () => {
    setLoading(true);
    fetch(`${API_BASE}/api/reports`)
      .then(r => r.json())
      .then(d => setReports(d.reports || []))
      .catch(() => setReports([]))
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  const fmtDate = (iso) => {
    if (!iso) return '—';
    try {
      return new Date(iso).toLocaleString('en-US', {
        year: 'numeric', month: 'short', day: '2-digit',
        hour: '2-digit', minute: '2-digit',
      });
    } catch { return iso; }
  };

  return (
    <div className="card">
      <div className="card-header">
        <h2 className="card-title">
          <FileText size={16} style={{ color: 'var(--c-primary)' }} />
          GRC Reports Library
        </h2>
        <span style={{ fontSize: 12, color: 'var(--c-text-muted)' }}>
          {reports.length} report{reports.length !== 1 ? 's' : ''}
        </span>
      </div>

      <div className="card-body">
        {loading && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {[1,2,3].map(i => (
              <div key={i} className="skeleton" style={{ height: 64, borderRadius: 'var(--r-md)' }} />
            ))}
          </div>
        )}

        {!loading && reports.length === 0 && (
          <div style={{ textAlign: 'center', padding: 'var(--sp-10)', color: 'var(--c-text-muted)' }}>
            <FileText size={40} style={{ margin: '0 auto 12px', opacity: 0.3 }} />
            <p style={{ fontSize: 14 }}>No reports yet</p>
            <p style={{ fontSize: 12, marginTop: 4 }}>Run a scan to generate your first GRC report</p>
          </div>
        )}

        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-3)' }}>
          {reports.map(r => (
            <div key={r.scan_id} className="report-card">
              {/* Left: meta */}
              <div className="report-card-meta">
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                  <ScanBadge status={r.status} />
                  <span style={{ fontSize: 11, color: 'var(--c-text-dim)', fontFamily: 'var(--font-mono)' }}>
                    #{r.scan_id}
                  </span>
                  {(r.critical_count > 0) && (
                    <span style={{ display: 'flex', alignItems: 'center', gap: 3, fontSize: 11, color: 'var(--c-critical)' }}>
                      <ShieldAlert size={11} /> {r.critical_count} Critical
                    </span>
                  )}
                  {(r.high_count > 0) && (
                    <span style={{ display: 'flex', alignItems: 'center', gap: 3, fontSize: 11, color: 'var(--c-high)' }}>
                      <AlertTriangle size={11} /> {r.high_count} High
                    </span>
                  )}
                </div>
                <div className="report-card-target">{r.target}</div>
                <div className="report-card-date">{fmtDate(r.completed_at || r.timestamp)}</div>
              </div>

              {/* Right: actions */}
              <div className="report-card-actions">
                {r.exists && (
                  <>
                    <button
                      className="btn btn-ghost"
                      style={{ padding: '6px 12px', fontSize: 12 }}
                      onClick={() => setPreviewScanId(r.scan_id)}
                      title="Preview report"
                    >
                      <Eye size={13} /> Preview
                    </button>
                    <a
                      href={`${API_BASE}/api/scan/${r.scan_id}/report`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="btn btn-ghost"
                      style={{ padding: '6px 12px', fontSize: 12, textDecoration: 'none' }}
                      title="Download report"
                    >
                      <Download size={13} /> Download
                    </a>
                  </>
                )}
                {!r.exists && (
                  <span style={{ fontSize: 11, color: 'var(--c-text-dim)', fontFamily: 'var(--font-mono)' }}>
                    File missing
                  </span>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Preview Modal */}
      {previewScanId && (
        <div className="modal-overlay" onClick={e => e.target === e.currentTarget && setPreviewScanId(null)}>
          <div className="modal-content">
            <div className="modal-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <FileText size={16} style={{ color: 'var(--c-primary)' }} />
                <span style={{ fontWeight: 600 }}>GRC Report — Scan #{previewScanId}</span>
              </div>
              <div style={{ display: 'flex', gap: 8 }}>
                <a
                  href={`${API_BASE}/api/scan/${previewScanId}/report`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="btn btn-ghost"
                  style={{ padding: '6px 12px', fontSize: 12, textDecoration: 'none' }}
                >
                  <Download size={13} /> Open in New Tab
                </a>
                <button
                  className="btn btn-ghost"
                  style={{ padding: '6px 12px', fontSize: 12 }}
                  onClick={() => setPreviewScanId(null)}
                >
                  ✕ Close
                </button>
              </div>
            </div>
            <div className="modal-iframe-wrap">
              <iframe
                className="modal-iframe"
                src={`${API_BASE}/api/scan/${previewScanId}/report`}
                title={`GRC Report Scan #${previewScanId}`}
              />
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
