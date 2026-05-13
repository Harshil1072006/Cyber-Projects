'use client';
import { Scan, ToolConfig } from '../lib/api';

const TOOL_ICONS: Record<string, string> = {
  nmap: '📡', gobuster: '🔍', hydra: '🔑', nuclei: '🐛', subfinder: '🌐', httpx: '⚡',
};

interface Props {
  scans: Scan[];
  tools: Record<string, ToolConfig>;
  onNavigate: (view: string, toolId?: string) => void;
  backendOnline: boolean;
}

export default function Dashboard({ scans, tools, onNavigate, backendOnline }: Props) {
  const total = scans.length;
  const done = scans.filter(s => s.status === 'done').length;
  const errors = scans.filter(s => s.status === 'error').length;

  const recentScans = scans.slice(0, 5);

  const toolList = Object.values(tools);

  return (
    <div className="fade-up">
      {/* Backend status banner */}
      {!backendOnline && (
        <div style={{ padding: '10px 18px', borderRadius: 10, background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.3)', marginBottom: 20, fontSize: '0.83rem', color: 'var(--red)', display: 'flex', alignItems: 'center', gap: 10 }}>
          <span>⚠️</span>
          <span>Backend offline. Start the server: <code style={{ fontFamily: 'JetBrains Mono, monospace' }}>uvicorn backend.main:app --port 8001 --reload</code></span>
        </div>
      )}

      {/* Hero */}
      <div className="card" style={{ padding: 32, marginBottom: 20, background: 'linear-gradient(135deg, rgba(99,102,241,0.08), rgba(34,211,238,0.04))', borderColor: 'rgba(99,102,241,0.3)', position: 'relative', overflow: 'hidden' }}>
        <div style={{ position: 'absolute', top: -40, right: -40, width: 200, height: 200, borderRadius: '50%', background: 'radial-gradient(circle, rgba(99,102,241,0.15), transparent)', pointerEvents: 'none' }} />
        <h1 style={{ fontSize: '2rem', fontWeight: 900, marginBottom: 8 }}>
          <span className="glow-text">VAPT</span> <span style={{ color: 'var(--text-secondary)', fontWeight: 400 }}>Command Center</span>
        </h1>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginBottom: 24 }}>
          Local-first penetration testing intelligence platform. One target → full attack surface.
        </p>
        <div style={{ display: 'flex', gap: 10 }}>
          <button className="btn btn-primary" onClick={() => onNavigate('workflow')}>🔄 Run Automated Workflow</button>
          <button className="btn btn-ghost" onClick={() => onNavigate('scans')}>📋 View Scan History</button>
        </div>
      </div>

      {/* Stats */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 14, marginBottom: 20 }}>
        {[
          { label: 'Total Scans', value: total, icon: '📊', color: 'var(--accent)' },
          { label: 'Completed', value: done, icon: '✅', color: 'var(--green)' },
          { label: 'Errors', value: errors, icon: '❌', color: 'var(--red)' },
          { label: 'Tools Ready', value: toolList.length, icon: '🛠️', color: 'var(--cyan)' },
        ].map(s => (
          <div key={s.label} className="card" style={{ padding: '20px 24px' }}>
            <div style={{ fontSize: '1.8rem', marginBottom: 4 }}>{s.icon}</div>
            <div style={{ fontSize: '2rem', fontWeight: 900, color: s.color }}>{s.value}</div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>{s.label}</div>
          </div>
        ))}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }}>
        {/* Recent scans */}
        <div className="card">
          <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border)' }}>
            <div className="section-title"><span>🕐</span> Recent Scans</div>
          </div>
          <div>
            {recentScans.length === 0 ? (
              <div style={{ padding: 24, textAlign: 'center', color: 'var(--text-dim)', fontSize: '0.83rem' }}>No scans yet</div>
            ) : recentScans.map(s => (
              <div key={s.id} className="scan-row" onClick={() => onNavigate('scans')}>
                <div>
                  <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.82rem', color: 'var(--cyan)' }}>{s.target}</div>
                  <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)' }}>{s.tool} · {new Date(s.created_at).toLocaleTimeString()}</div>
                </div>
                <span className={`status-${s.status}`} style={{ fontWeight: 700, fontSize: '0.75rem' }}>{s.status}</span>
              </div>
            ))}
          </div>
          {total > 5 && (
            <div style={{ padding: '12px 20px', borderTop: '1px solid var(--border)' }}>
              <button className="btn btn-ghost btn-sm" onClick={() => onNavigate('scans')}>View all {total} scans →</button>
            </div>
          )}
        </div>

        {/* Tool grid */}
        <div className="card">
          <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border)' }}>
            <div className="section-title"><span>🛠️</span> Available Tools</div>
          </div>
          <div style={{ padding: 16, display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
            {toolList.map(t => (
              <button key={t.id} className="card card-hover" onClick={() => onNavigate('tool', t.id)}
                style={{ padding: '14px 16px', textAlign: 'left', border: '1px solid var(--border)', background: 'var(--bg-primary)', cursor: 'pointer' }}>
                <div style={{ fontSize: '1.4rem', marginBottom: 6 }}>{TOOL_ICONS[t.id] || '🔧'}</div>
                <div style={{ fontWeight: 700, fontSize: '0.85rem' }}>{t.name}</div>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)', marginTop: 2 }}>{t.category}</div>
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
