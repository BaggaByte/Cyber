import { useEffect, useState } from 'react';
import {
  Activity, Shield, Zap, AlertTriangle,
  LayoutDashboard, Terminal, BookOpen, ShieldAlert,
  Wifi, WifiOff
} from 'lucide-react';
import ScanControl from './components/ScanControl';
import ScanHistory from './components/ScanHistory';
import FindingsBrowser from './components/FindingsBrowser';
import ThreatIntelligence from './components/ThreatIntelligence';
import LiveTerminal from './components/LiveTerminal';
import ReportsLibrary from './components/ReportsLibrary';
import { API_BASE } from './config';

const TABS = [
  { id: 'dashboard',     label: 'Dashboard',          Icon: LayoutDashboard },
  { id: 'threat',        label: 'Threat Intel',        Icon: ShieldAlert     },
  { id: 'terminal',      label: 'Live Terminal',       Icon: Terminal        },
  { id: 'reports',       label: 'Reports Library',     Icon: BookOpen        },
];

export default function Dashboard() {
  const [stats, setStats] = useState(null);
  const [health, setHealth] = useState(null);
  const [refreshKey, setRefreshKey] = useState(0);
  const [activeTab, setActiveTab] = useState('dashboard');

  const refreshDashboard = () => setRefreshKey(k => k + 1);

  useEffect(() => {
    fetch(`${API_BASE}/api/stats`)
      .then(r => r.json())
      .then(setStats)
      .catch(() => setStats(null));

    fetch(`${API_BASE}/api/health`)
      .then(r => r.json())
      .then(setHealth)
      .catch(() => setHealth(null));
  }, [refreshKey]);

  const statCards = [
    { label: 'Total Scans',  value: stats?.total_scans     ?? '—', icon: Activity,      color: 'var(--c-primary)'  },
    { label: 'Completed',    value: stats?.completed_scans ?? '—', icon: Shield,        color: '#34d399'            },
    { label: 'Active',       value: stats?.active_scans    ?? '—', icon: Zap,           color: '#a78bfa'            },
    { label: 'Findings',     value: stats?.total_findings  ?? '—', icon: AlertTriangle, color: '#f97316'            },
  ];

  const isOnline = health?.status === 'ok';

  return (
    <div className="app-shell">
      {/* Animated Background */}
      <div className="bg-canvas">
        <div className="bg-grid"></div>
        <div className="bg-orb bg-orb-1"></div>
        <div className="bg-orb bg-orb-2"></div>
        <div className="bg-orb bg-orb-3"></div>
      </div>

      <main className="main-content" style={{ marginLeft: 0 }}>
        {/* Page Header */}
        <div className="page-header">
          <div>
            <h1 className="page-title">
              Nexus AI <span className="text-gradient">Enterprise</span>
            </h1>
            <p className="page-subtitle">
              Autonomous DevSecOps &amp; GRC Orchestration Platform
            </p>
          </div>
          <div className="sidebar-status">
            {isOnline
              ? <Wifi size={14} style={{ color: '#34d399' }} />
              : <WifiOff size={14} style={{ color: '#ef4444' }} />
            }
            <span className={`status-dot ${isOnline ? 'online' : 'offline'}`} />
            <span style={{ fontSize: 12, color: isOnline ? '#34d399' : '#ef4444' }}>
              {isOnline ? 'Backend Online' : 'Backend Offline'}
            </span>
            {health?.model && (
              <span style={{ fontSize: 11, color: 'var(--c-text-dim)', marginLeft: 4 }}>
                · {health.model}
              </span>
            )}
          </div>
        </div>

        {/* Tab Navigation */}
        <nav className="tab-nav">
          {TABS.map(({ id, label, Icon }) => (
            <button
              key={id}
              className={`tab-btn ${activeTab === id ? 'active' : ''}`}
              onClick={() => setActiveTab(id)}
            >
              <Icon size={15} />
              {label}
            </button>
          ))}
        </nav>

        {/* ── Tab: Dashboard ─────────────────────────────────── */}
        {activeTab === 'dashboard' && (
          <div className="flex-col">
            {/* Stats Grid */}
            <div className="grid-4">
              {statCards.map(({ label, value, icon: Icon, color }) => (
                <div key={label} className="stat-card" style={{ display: 'flex', alignItems: 'center', gap: 'var(--sp-4)' }}>
                  <div style={{
                    width: 44, height: 44, borderRadius: 'var(--r-md)',
                    background: `${color}1a`, display: 'flex', alignItems: 'center', justifyContent: 'center',
                    flexShrink: 0,
                  }}>
                    <Icon size={20} style={{ color }} />
                  </div>
                  <div>
                    <div className="stat-value">{value}</div>
                    <div className="stat-label" style={{ marginBottom: 0 }}>{label}</div>
                  </div>
                </div>
              ))}
            </div>

            <ScanControl onScanComplete={refreshDashboard} />

            <div className="grid-2">
              <ScanHistory refreshKey={refreshKey} onRefresh={refreshDashboard} />
              <FindingsBrowser refreshKey={refreshKey} />
            </div>
          </div>
        )}

        {/* ── Tab: Threat Intelligence ────────────────────────── */}
        {activeTab === 'threat' && (
          <ThreatIntelligence stats={stats} />
        )}

        {/* ── Tab: Live Terminal ──────────────────────────────── */}
        {activeTab === 'terminal' && (
          <LiveTerminal />
        )}

        {/* ── Tab: Reports Library ────────────────────────────── */}
        {activeTab === 'reports' && (
          <ReportsLibrary />
        )}
      </main>
    </div>
  );
}
