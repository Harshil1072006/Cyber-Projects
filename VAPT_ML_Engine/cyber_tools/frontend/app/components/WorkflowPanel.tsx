'use client';
import { useState } from 'react';
import { api } from '../lib/api';

const WORKFLOWS = [
  {
    id: 'quick_look',
    icon: '⚡',
    name: 'Quick Look',
    desc: 'Nmap port scan + httpx probing. Fast overview of any target.',
    tools: ['nmap', 'httpx'],
    color: '#22d3ee',
  },
  {
    id: 'deep_web',
    icon: '🕸️',
    name: 'Deep Web Audit',
    desc: 'Full web recon: ports, directories, tech stack, vulnerabilities.',
    tools: ['nmap', 'httpx', 'gobuster', 'nuclei'],
    color: '#6366f1',
  },
  {
    id: 'full_audit',
    icon: '🔍',
    name: 'Full Audit',
    desc: 'Complete VAPT pipeline from subdomain discovery to CVE scanning.',
    tools: ['subfinder', 'nmap', 'httpx', 'gobuster', 'nuclei'],
    color: '#f97316',
  },
];

interface Props {
  onScanLaunched: () => void;
}

export default function WorkflowPanel({ onScanLaunched }: Props) {
  const [target, setTarget] = useState('');
  const [running, setRunning] = useState<string | null>(null);
  const [result, setResult] = useState<{ wf: string; ids: string[] } | null>(null);
  const [error, setError] = useState('');

  const launch = async (wfId: string) => {
    if (!target.trim()) { setError('Enter a target first.'); return; }
    setRunning(wfId); setError(''); setResult(null);
    try {
      const res = await api.workflow(target.trim(), wfId);
      setResult({ wf: wfId, ids: res.scan_ids });
      onScanLaunched();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to launch workflow');
    } finally { setRunning(null); }
  };

  return (
    <div className="fade-up">
      {/* Header */}
      <div className="card" style={{ padding: 24, marginBottom: 20 }}>
        <div className="section-title" style={{ marginBottom: 16 }}><span>🔄</span> One-Click Automated Workflows</div>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginBottom: 16 }}>
          Enter a single target and let the pipeline run all tools automatically in sequence.
        </p>
        <div style={{ display: 'flex', gap: 10 }}>
          <input className="input" placeholder="e.g. target.com or 192.168.1.1"
            value={target} onChange={e => setTarget(e.target.value)} />
        </div>
        {error && <div style={{ marginTop: 10, fontSize: '0.8rem', color: 'var(--red)' }}>⚠️ {error}</div>}
        {result && (
          <div style={{ marginTop: 12, padding: '10px 14px', borderRadius: 8, background: 'rgba(16,185,129,0.08)', border: '1px solid rgba(16,185,129,0.3)', fontSize: '0.82rem', fontFamily: 'JetBrains Mono, monospace' }}>
            ✅ Workflow &quot;{result.wf}&quot; launched — {result.ids.length} scans queued.
          </div>
        )}
      </div>

      {/* Workflow cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 16 }}>
        {WORKFLOWS.map(wf => (
          <div key={wf.id} className="card card-hover" style={{ padding: 24, cursor: 'default', borderTop: `3px solid ${wf.color}` }}>
            <div style={{ fontSize: '2rem', marginBottom: 12 }}>{wf.icon}</div>
            <h3 style={{ fontWeight: 800, fontSize: '1rem', marginBottom: 6, color: wf.color }}>{wf.name}</h3>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: 16, lineHeight: 1.6 }}>{wf.desc}</p>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 20 }}>
              {wf.tools.map(t => (
                <span key={t} style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.7rem', padding: '3px 8px', borderRadius: 6, background: 'var(--accent-dim)', color: 'var(--accent)', border: '1px solid var(--border)' }}>{t}</span>
              ))}
            </div>
            <button className="btn btn-primary" style={{ width: '100%', justifyContent: 'center', background: `linear-gradient(135deg, ${wf.color}cc, ${wf.color}88)` }}
              onClick={() => launch(wf.id)}
              disabled={!!running}>
              {running === wf.id ? <><span className="spinner" /> Running...</> : `▶ Launch ${wf.name}`}
            </button>
          </div>
        ))}
      </div>

      {/* Pipeline visualizer */}
      <div className="card" style={{ padding: 24, marginTop: 20 }}>
        <div className="section-title" style={{ marginBottom: 16 }}><span>📊</span> Pipeline Flow</div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, overflowX: 'auto', paddingBottom: 8 }}>
          {['Subfinder', 'httpx', 'Nmap', 'Gobuster', 'Nuclei', 'Correlator', 'Report'].map((step, i, arr) => (
            <div key={step} style={{ display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
              <div style={{
                padding: '8px 16px', borderRadius: 20, border: '1px solid var(--border)',
                background: 'var(--bg-card)', fontSize: '0.78rem', fontWeight: 600,
                color: i === 0 ? 'var(--cyan)' : i === arr.length - 1 ? 'var(--green)' : 'var(--text-secondary)',
              }}>{step}</div>
              {i < arr.length - 1 && <span style={{ color: 'var(--text-dim)', fontSize: '1.2rem' }}>→</span>}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
