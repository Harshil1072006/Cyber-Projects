'use client';
import { useState, useCallback } from 'react';
import { ToolConfig, ToolControl, api } from '../lib/api';

interface Props {
  tool: ToolConfig;
  onScanLaunched: (scanId: string) => void;
}

function buildDefaults(controls: ToolControl[]): Record<string, unknown> {
  const d: Record<string, unknown> = {};
  for (const c of controls) {
    if (c.default !== undefined) d[c.id] = c.default;
  }
  return d;
}

export default function ToolCockpit({ tool, onScanLaunched }: Props) {
  const [target, setTarget] = useState('');
  const [options, setOptions] = useState<Record<string, unknown>>(() => buildDefaults(tool.controls));
  const [running, setRunning] = useState(false);
  const [feedback, setFeedback] = useState('');

  const set = useCallback((id: string, val: unknown) => setOptions(p => ({ ...p, [id]: val })), []);

  // Build live command preview
  const buildPreview = () => {
    const parts: string[] = [tool.id];
    if (target) parts.push(target);
    for (const c of tool.controls) {
      const v = options[c.id];
      if (c.type === 'toggle' && v && c.flag) parts.push(c.flag);
      if (c.type === 'slider' && v !== undefined) parts.push(`-T${v}`);
      if ((c.type === 'text' || c.type === 'number') && v) parts.push(`${v}`);
      if (c.type === 'select' && v) parts.push(`[${v}]`);
    }
    return parts.join(' ');
  };

  const launch = async () => {
    if (!target.trim()) { setFeedback('⚠️ Enter a target first.'); return; }
    setRunning(true); setFeedback('');
    try {
      const res = await api.launch(target.trim(), tool.id, options);
      setFeedback(`✅ Scan launched! Found ${res.findings_count} findings.`);
      onScanLaunched(res.scan_id);
    } catch (e: unknown) {
      setFeedback(`❌ ${e instanceof Error ? e.message : 'Error launching scan'}`);
    } finally { setRunning(false); }
  };

  const renderControl = (c: ToolControl) => {
    const val = options[c.id];
    switch (c.type) {
      case 'toggle':
        return (
          <div key={c.id} className="toggle-wrap" style={{ padding: '8px 0', borderBottom: '1px solid var(--border)' }}>
            <div>
              <div style={{ fontSize: '0.83rem', fontWeight: 600, color: 'var(--text-primary)' }}>{c.label}</div>
              {c.flag && <div style={{ fontSize: '0.7rem', color: 'var(--accent)', fontFamily: 'JetBrains Mono, monospace' }}>{c.flag}</div>}
            </div>
            <label className="toggle">
              <input type="checkbox" checked={!!val} onChange={e => set(c.id, e.target.checked)} />
              <span className="toggle-slider" />
            </label>
          </div>
        );
      case 'slider':
        return (
          <div key={c.id} style={{ padding: '8px 0', borderBottom: '1px solid var(--border)' }}>
            <div className="toggle-wrap" style={{ marginBottom: 6 }}>
              <div style={{ fontSize: '0.83rem', fontWeight: 600, color: 'var(--text-primary)' }}>{c.label}</div>
              <span style={{ fontSize: '0.82rem', fontWeight: 700, color: 'var(--accent)', fontFamily: 'monospace' }}>{val as number ?? c.default}</span>
            </div>
            <input type="range" min={c.min ?? 1} max={c.max ?? 10}
              value={(val as number) ?? (c.default as number) ?? 1}
              onChange={e => set(c.id, Number(e.target.value))} />
          </div>
        );
      case 'select':
        return (
          <div key={c.id} style={{ padding: '8px 0', borderBottom: '1px solid var(--border)' }}>
            <div className="label">{c.label}</div>
            <select className="input" value={(val as string) ?? ''} onChange={e => set(c.id, e.target.value)}>
              {c.options?.map(o => <option key={o} value={o}>{o}</option>)}
            </select>
          </div>
        );
      case 'multi-select':
        return (
          <div key={c.id} style={{ padding: '8px 0', borderBottom: '1px solid var(--border)' }}>
            <div className="label">{c.label}</div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 6 }}>
              {c.options?.map(o => {
                const sel = ((val as string[]) ?? (c.default as string[]) ?? []).includes(o);
                return (
                  <button key={o} onClick={() => {
                    const cur: string[] = (val as string[]) ?? (c.default as string[]) ?? [];
                    set(c.id, sel ? cur.filter(x => x !== o) : [...cur, o]);
                  }} className="btn btn-sm" style={{
                    background: sel ? 'var(--accent)' : 'var(--accent-dim)',
                    color: sel ? '#fff' : 'var(--text-secondary)',
                    border: `1px solid ${sel ? 'var(--accent)' : 'var(--border)'}`,
                  }}>{o}</button>
                );
              })}
            </div>
          </div>
        );
      case 'text':
      case 'number':
        return (
          <div key={c.id} style={{ padding: '8px 0', borderBottom: '1px solid var(--border)' }}>
            <div className="label">{c.label}</div>
            <input className="input" type={c.type === 'number' ? 'number' : 'text'}
              placeholder={c.placeholder ?? ''} value={(val as string) ?? ''}
              onChange={e => set(c.id, e.target.value)} />
          </div>
        );
      default: return null;
    }
  };

  return (
    <div className="card fade-up" style={{ padding: 24 }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 14, marginBottom: 24 }}>
        <div style={{
          width: 48, height: 48, borderRadius: 12,
          background: 'linear-gradient(135deg,var(--accent),var(--cyan))',
          display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 22,
        }}>🛡️</div>
        <div>
          <h2 style={{ fontSize: '1.3rem', fontWeight: 800 }}>{tool.name}</h2>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.83rem' }}>{tool.description}</p>
        </div>
        <span style={{ marginLeft: 'auto' }} className={`badge badge-${tool.category === 'Auth' ? 'high' : 'info'}`}>{tool.category}</span>
      </div>

      {/* Target Input */}
      <div style={{ marginBottom: 20 }}>
        <div className="label">Target (IP / URL / Domain)</div>
        <div style={{ display: 'flex', gap: 10 }}>
          <input className="input" placeholder="e.g. 192.168.1.1 or https://target.com"
            value={target} onChange={e => setTarget(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && launch()}
            style={{ fontFamily: 'JetBrains Mono, monospace' }} />
          <button className="btn btn-primary" onClick={launch} disabled={running} style={{ flexShrink: 0 }}>
            {running ? <span className="spinner" /> : '▶ Run'}
          </button>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24 }}>
        {/* Controls */}
        <div>
          <div className="section-title" style={{ marginBottom: 12 }}>
            <span>🕹️</span> Flag Cockpit
          </div>
          <div>{tool.controls.map(renderControl)}</div>
        </div>

        {/* Command Preview */}
        <div>
          <div className="section-title" style={{ marginBottom: 12 }}>
            <span>⌨️</span> Live Command Preview
          </div>
          <div className="terminal" style={{ maxHeight: 'none', minHeight: 120 }}>
            <span style={{ color: 'var(--text-dim)' }}>$ </span>
            <span style={{ color: '#a3e635' }}>{buildPreview()}</span>
            <span style={{ animation: 'pulse 1s infinite', color: '#a3e635' }}>█</span>
          </div>

          {feedback && (
            <div style={{
              marginTop: 12, padding: '10px 14px', borderRadius: 8,
              background: feedback.startsWith('✅') ? 'rgba(16,185,129,0.08)' : feedback.startsWith('⚠') ? 'rgba(245,158,11,0.08)' : 'rgba(239,68,68,0.08)',
              border: `1px solid ${feedback.startsWith('✅') ? 'rgba(16,185,129,0.3)' : feedback.startsWith('⚠') ? 'rgba(245,158,11,0.3)' : 'rgba(239,68,68,0.3)'}`,
              fontSize: '0.82rem', fontFamily: 'JetBrains Mono, monospace',
            }}>{feedback}</div>
          )}
        </div>
      </div>
    </div>
  );
}
