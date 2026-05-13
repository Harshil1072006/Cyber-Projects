'use client';
import { ToolConfig } from '../lib/api';

const CATEGORY_COLORS: Record<string, string> = {
  Recon: '#22d3ee', Scanning: '#6366f1', Web: '#a78bfa',
  Vulnerability: '#f97316', Auth: '#ef4444', Other: '#94a3b8',
};

const ICONS: Record<string, string> = {
  nmap: '📡', gobuster: '🔍', hydra: '🔑', nuclei: '🐛',
  subfinder: '🌐', httpx: '⚡',
};

interface Props {
  tools: Record<string, ToolConfig>;
  selectedTool: string | null;
  onSelectTool: (id: string) => void;
  activeView: string;
  onSetView: (v: string) => void;
  scanCount: number;
}

export default function Sidebar({ tools, selectedTool, onSelectTool, activeView, onSetView, scanCount }: Props) {
  const categories = [...new Set(Object.values(tools).map(t => t.category))];

  return (
    <div className="sidebar">
      {/* Logo */}
      <div style={{ padding: '24px 20px 16px', borderBottom: '1px solid var(--border)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 4 }}>
          <div style={{
            width: 32, height: 32, borderRadius: 8,
            background: 'linear-gradient(135deg,#6366f1,#22d3ee)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: 16, flexShrink: 0,
          }}>⚔️</div>
          <div>
            <div style={{ fontSize: '0.88rem', fontWeight: 800, color: 'var(--text-primary)', lineHeight: 1.2 }}>VAPT</div>
            <div style={{ fontSize: '0.65rem', color: 'var(--text-dim)', fontWeight: 600, letterSpacing: '0.12em', textTransform: 'uppercase' }}>Command Center</div>
          </div>
        </div>
      </div>

      {/* Nav */}
      <div style={{ padding: '12px 12px 0' }}>
        <p className="label" style={{ paddingLeft: 8 }}>Navigation</p>
        {[
          { id: 'dashboard', icon: '🏠', label: 'Dashboard' },
          { id: 'scans', icon: '📋', label: 'Scan History', badge: scanCount },
          { id: 'workflow', icon: '🔄', label: 'Auto Workflow' },
        ].map(item => (
          <button
            key={item.id}
            onClick={() => onSetView(item.id)}
            className="btn btn-ghost"
            style={{
              width: '100%', justifyContent: 'flex-start', marginBottom: 4,
              background: activeView === item.id ? 'var(--accent-dim)' : 'transparent',
              borderColor: activeView === item.id ? 'var(--border-bright)' : 'transparent',
              color: activeView === item.id ? 'var(--text-primary)' : 'var(--text-secondary)',
            }}
          >
            <span>{item.icon}</span>
            <span style={{ flex: 1, textAlign: 'left' }}>{item.label}</span>
            {item.badge ? (
              <span style={{
                background: 'var(--accent)', color: '#fff', borderRadius: 10,
                padding: '1px 7px', fontSize: '0.7rem', fontWeight: 700,
              }}>{item.badge}</span>
            ) : null}
          </button>
        ))}
      </div>

      {/* Tools */}
      <div style={{ padding: '16px 12px 0', flex: 1 }}>
        <p className="label" style={{ paddingLeft: 8 }}>Tools</p>
        {categories.map(cat => (
          <div key={cat} style={{ marginBottom: 8 }}>
            <p style={{ fontSize: '0.65rem', color: CATEGORY_COLORS[cat] || '#94a3b8', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.1em', paddingLeft: 8, marginBottom: 4 }}>{cat}</p>
            {Object.values(tools).filter(t => t.category === cat).map(tool => (
              <button
                key={tool.id}
                onClick={() => { onSelectTool(tool.id); onSetView('tool'); }}
                className="btn btn-ghost"
                style={{
                  width: '100%', justifyContent: 'flex-start', marginBottom: 2,
                  background: selectedTool === tool.id && activeView === 'tool' ? 'var(--accent-dim)' : 'transparent',
                  borderColor: selectedTool === tool.id && activeView === 'tool' ? 'var(--border-bright)' : 'transparent',
                  color: selectedTool === tool.id && activeView === 'tool' ? 'var(--text-primary)' : 'var(--text-secondary)',
                  fontSize: '0.82rem',
                }}
              >
                <span>{ICONS[tool.id] || '🔧'}</span>
                <span>{tool.name}</span>
              </button>
            ))}
          </div>
        ))}
      </div>

      {/* Footer */}
      <div style={{ padding: '12px 20px', borderTop: '1px solid var(--border)', marginTop: 'auto' }}>
        <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)' }}>v1.0.0 · Local-First</div>
      </div>
    </div>
  );
}
