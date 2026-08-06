import React, { useEffect, useState } from 'react';
import { ShieldAlert, AlertTriangle, TrendingUp, Target, BarChart3 } from 'lucide-react';
import { API_BASE } from '../config';

/* ── SVG Donut Chart ──────────────────────────────────────────── */
function DonutChart({ slices, size = 160, thickness = 28 }) {
  const r = (size - thickness) / 2;
  const cx = size / 2;
  const cy = size / 2;
  const circumference = 2 * Math.PI * r;

  let offset = 0;
  const total = slices.reduce((s, sl) => s + sl.value, 0) || 1;

  return (
    <svg width={size} height={size} style={{ transform: 'rotate(-90deg)' }}>
      {/* Track */}
      <circle cx={cx} cy={cy} r={r} fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth={thickness} />
      {slices.map((sl, i) => {
        const dashArr = (sl.value / total) * circumference;
        const el = (
          <circle
            key={i}
            cx={cx} cy={cy} r={r}
            fill="none"
            stroke={sl.color}
            strokeWidth={thickness}
            strokeDasharray={`${dashArr} ${circumference}`}
            strokeDashoffset={-offset}
            strokeLinecap="butt"
            style={{ transition: 'stroke-dasharray 0.6s ease', filter: `drop-shadow(0 0 6px ${sl.color}66)` }}
          />
        );
        offset += dashArr;
        return el;
      })}
    </svg>
  );
}

/* ── Risk Gauge ───────────────────────────────────────────────── */
function RiskGauge({ score }) {
  const size = 180;
  const r = 72;
  const cx = size / 2;
  const cy = size / 2 + 20;
  const startAngle = -210;
  const totalAngle = 240;
  const sweepAngle = (score / 100) * totalAngle;

  const polar = (angle) => {
    const rad = (angle * Math.PI) / 180;
    return {
      x: cx + r * Math.cos(rad),
      y: cy + r * Math.sin(rad),
    };
  };

  const arcPath = (start, end) => {
    const s = polar(start);
    const e = polar(end);
    const large = end - start > 180 ? 1 : 0;
    return `M ${s.x} ${s.y} A ${r} ${r} 0 ${large} 1 ${e.x} ${e.y}`;
  };

  const color = score >= 70 ? '#ef4444' : score >= 40 ? '#f97316' : '#22c55e';
  const label = score >= 70 ? 'HIGH RISK' : score >= 40 ? 'MEDIUM' : 'LOW RISK';

  return (
    <div className="gauge-container">
      <div style={{ position: 'relative' }}>
        <svg width={size} height={size * 0.72} style={{ overflow: 'visible' }}>
          {/* Track */}
          <path
            d={arcPath(startAngle, startAngle + totalAngle)}
            fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth={16} strokeLinecap="round"
          />
          {/* Value arc */}
          {score > 0 && (
            <path
              d={arcPath(startAngle, startAngle + sweepAngle)}
              fill="none" stroke={color} strokeWidth={16} strokeLinecap="round"
              style={{ filter: `drop-shadow(0 0 8px ${color}88)`, transition: 'all 0.6s ease' }}
            />
          )}
          {/* Tick marks */}
          {[0, 25, 50, 75, 100].map(v => {
            const angle = startAngle + (v / 100) * totalAngle;
            const inner = polar(angle);
            const outerR = r + 10;
            const outer = { x: cx + outerR * Math.cos(angle * Math.PI / 180), y: cy + outerR * Math.sin(angle * Math.PI / 180) };
            return (
              <line key={v} x1={inner.x} y1={inner.y} x2={outer.x} y2={outer.y}
                stroke="rgba(255,255,255,0.15)" strokeWidth={1} />
            );
          })}
        </svg>
        {/* Center overlay */}
        <div style={{
          position: 'absolute', bottom: 0, left: '50%', transform: 'translateX(-50%)',
          textAlign: 'center', paddingBottom: 4,
        }}>
          <div style={{ fontSize: 36, fontWeight: 900, letterSpacing: '-0.04em', color, lineHeight: 1 }}>
            {score}
          </div>
          <div style={{ fontSize: 9, color: 'var(--c-text-muted)', letterSpacing: '0.15em', marginTop: 2 }}>
            {label}
          </div>
        </div>
      </div>
    </div>
  );
}

/* ── Trend Sparkline ──────────────────────────────────────────── */
function TrendBars({ series }) {
  if (!series || series.length === 0) return null;
  const maxVal = Math.max(...series.map(d => d.total), 1);
  const barH = 60;
  const barW = 100 / series.length;

  return (
    <svg viewBox={`0 0 100 80`} preserveAspectRatio="none" className="trend-chart">
      {series.map((d, i) => {
        const h = (d.completed / maxVal) * barH;
        const hFail = (d.failed / maxVal) * barH;
        const x = i * barW;
        const showLabel = i === 0 || i === series.length - 1 || i === Math.floor(series.length / 2);
        return (
          <g key={d.date}>
            {/* Total bar (faint) */}
            <rect x={x + 0.5} y={80 - (d.total / maxVal) * barH} width={barW - 1} height={(d.total / maxVal) * barH}
              fill="rgba(56,189,248,0.1)" />
            {/* Completed bar */}
            <rect x={x + 0.5} y={80 - h} width={barW - 1} height={h}
              fill="rgba(52,211,153,0.7)" className="trend-bar" />
            {/* Failed bar */}
            {d.failed > 0 && (
              <rect x={x + 0.5} y={80 - h - hFail} width={barW - 1} height={hFail}
                fill="rgba(239,68,68,0.6)" className="trend-bar" />
            )}
            {showLabel && (
              <text x={x + barW / 2} y={78} textAnchor="middle" className="trend-x-label">
                {d.date.slice(5)}
              </text>
            )}
          </g>
        );
      })}
    </svg>
  );
}

/* ── Main Component ──────────────────────────────────────────── */
export default function ThreatIntelligence({ stats }) {
  const [trend, setTrend] = useState(null);

  useEffect(() => {
    fetch(`${API_BASE}/api/stats/trend`)
      .then(r => r.json())
      .then(setTrend)
      .catch(() => {});
  }, []);

  const critical = stats?.critical_count ?? 0;
  const high = stats?.high_count ?? 0;
  const totalFindings = stats?.total_findings ?? 0;
  const medium = Math.max(0, totalFindings - critical - high);
  const low = 0; // could compute from API
  const riskScore = stats?.risk_score ?? 0;

  const severitySlices = [
    { label: 'Critical', value: critical, color: '#ef4444' },
    { label: 'High',     value: high,     color: '#f97316' },
    { label: 'Medium',   value: medium,   color: '#eab308' },
    { label: 'Low',      value: low,      color: '#22c55e' },
  ].filter(s => s.value > 0);

  const hasFindings = totalFindings > 0;

  return (
    <div className="flex-col" style={{ gap: 'var(--sp-6)' }}>

      {/* Row 1: Risk Gauge + Donut */}
      <div className="grid-2">
        {/* Risk Score */}
        <div className="card">
          <div className="card-header">
            <h2 className="card-title">
              <ShieldAlert size={16} style={{ color: 'var(--c-critical)' }} />
              Risk Score
            </h2>
          </div>
          <div className="card-body" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 'var(--sp-6)' }}>
            <RiskGauge score={riskScore} />
          </div>
          <div style={{ padding: '0 var(--sp-5) var(--sp-5)', textAlign: 'center' }}>
            <p style={{ fontSize: 11, color: 'var(--c-text-muted)' }}>
              Composite score based on critical × 15 pts + high × 5 pts
            </p>
          </div>
        </div>

        {/* Severity Donut */}
        <div className="card">
          <div className="card-header">
            <h2 className="card-title">
              <AlertTriangle size={16} style={{ color: 'var(--c-high)' }} />
              Severity Breakdown
            </h2>
          </div>
          <div className="card-body" style={{ display: 'flex', alignItems: 'center', gap: 'var(--sp-6)' }}>
            {hasFindings ? (
              <>
                <div className="donut-chart-wrap">
                  <DonutChart slices={severitySlices} size={150} thickness={24} />
                  <div className="donut-center-text">
                    <div className="donut-total">{totalFindings}</div>
                    <div className="donut-label">Total</div>
                  </div>
                </div>
                <div className="severity-legend">
                  {[
                    { label: 'Critical', value: critical, color: '#ef4444' },
                    { label: 'High',     value: high,     color: '#f97316' },
                    { label: 'Medium',   value: medium,   color: '#eab308' },
                  ].map(s => (
                    <div key={s.label} className="severity-legend-row">
                      <div className="severity-dot" style={{ background: s.color }} />
                      <span className="severity-legend-label">{s.label}</span>
                      <div className="severity-legend-bar">
                        <div className="severity-legend-bar-fill"
                          style={{ width: `${(s.value / totalFindings) * 100}%`, background: s.color }} />
                      </div>
                      <span className="severity-legend-value" style={{ color: s.color }}>{s.value}</span>
                    </div>
                  ))}
                </div>
              </>
            ) : (
              <div style={{ width: '100%', textAlign: 'center', color: 'var(--c-text-muted)', fontSize: 13 }}>
                No findings yet. Run a scan to see severity breakdown.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Row 2: 14-day Trend */}
      <div className="card">
        <div className="card-header">
          <h2 className="card-title">
            <TrendingUp size={16} style={{ color: 'var(--c-emerald)' }} />
            14-Day Scan Activity
          </h2>
          <div style={{ display: 'flex', gap: 16, fontSize: 11, color: 'var(--c-text-muted)' }}>
            <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
              <span style={{ display: 'inline-block', width: 10, height: 10, borderRadius: 2, background: 'rgba(52,211,153,0.7)' }} />
              Completed
            </span>
            <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
              <span style={{ display: 'inline-block', width: 10, height: 10, borderRadius: 2, background: 'rgba(239,68,68,0.6)' }} />
              Failed
            </span>
          </div>
        </div>
        <div className="card-body" style={{ padding: 'var(--sp-4) var(--sp-5)' }}>
          {trend ? (
            <TrendBars series={trend.series} />
          ) : (
            <div className="skeleton" style={{ height: 80 }} />
          )}
        </div>
      </div>

      {/* Row 3: Stats Summary */}
      <div className="grid-4">
        {[
          { label: 'Total Scans',   value: stats?.total_scans ?? 0,     icon: BarChart3,      color: '#38bdf8' },
          { label: 'Completed',     value: stats?.completed_scans ?? 0,  icon: Target,         color: '#34d399' },
          { label: 'Critical',      value: critical,                     icon: ShieldAlert,    color: '#ef4444' },
          { label: 'High',          value: high,                         icon: AlertTriangle,  color: '#f97316' },
        ].map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="stat-card" style={{ flexDirection: 'column', alignItems: 'flex-start' }}>
            <Icon size={20} style={{ color, marginBottom: 8 }} />
            <div className="stat-value" style={{ color }}>{value}</div>
            <div className="stat-label">{label}</div>
          </div>
        ))}
      </div>
    </div>
  );
}
