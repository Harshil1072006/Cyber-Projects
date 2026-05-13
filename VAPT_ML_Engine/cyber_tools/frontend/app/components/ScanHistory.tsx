'use client';
import { useState } from 'react';
import { Scan, Finding, api } from '../lib/api';

const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

interface Props {
  scans: Scan[];
  onRefresh: () => void;
  onSelectScan: (id: string) => void;
  selectedScanId: string | null;
  selectedScanDetail: Scan | null;
  loading: boolean;
}

export default function ScanHistory({ scans, onRefresh, onSelectScan, selectedScanId, selectedScanDetail, loading }: Props) {
  const [deleting, setDeleting] = useState<string | null>(null);

  const del = async (e: React.MouseEvent, id: string) => {
    e.stopPropagation();
    setDeleting(id);
    try { await api.deleteScan(id); onRefresh(); } catch { /* ignore */ }
    setDeleting(null);
  };

  const findings = (selectedScanDetail?.findings ?? [])
    .slice().sort((a: Finding, b: Finding) => (SEV_ORDER[a.severity] ?? 5) - (SEV_ORDER[b.severity] ?? 5));

  const fmt = (d: string) => new Date(d).toLocaleString();

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1.4fr', gap: 20, alignItems: 'start' }}>
      {/* Scan list */}
      <div className="card">
        <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div className="section-title"><span>📋</span> Scan History</div>
          <button className="btn btn-ghost btn-sm" onClick={onRefresh} disabled={loading}>
            {loading ? <span className="spinner" /> : '↻ Refresh'}
          </button>
        </div>
        <div style={{ maxHeight: 600, overflowY: 'auto' }}>
          {scans.length === 0 && (
            <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-dim)' }}>
              <div style={{ fontSize: '2rem', marginBottom: 8 }}>📭</div>
              No scans yet. Run your first scan!
            </div>
          )}
          {scans.map(s => (
            <div key={s.id} className="scan-row" onClick={() => onSelectScan(s.id)}
              style={{ background: selectedScanId === s.id ? 'var(--accent-dim)' : undefined }}>
              <div>
                <div style={{ fontWeight: 600, fontSize: '0.85rem', fontFamily: 'JetBrains Mono, monospace', color: 'var(--cyan)' }}>{s.target}</div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', marginTop: 2 }}>
                  {s.tool.toUpperCase()}{s.workflow ? ` · ${s.workflow}` : ''} · {fmt(s.created_at)}
                </div>
              </div>
              <span className={`badge badge-${s.tool === 'hydra' ? 'high' : 'info'}`} style={{ fontSize: '0.65rem' }}>{s.tool}</span>
              <span className={`status-${s.status}`} style={{ fontSize: '0.75rem', fontWeight: 700, whiteSpace: 'nowrap' }}>
                {s.status === 'running' && '⟳ '}{s.status === 'done' && '✓ '}{s.status === 'error' && '✗ '}{s.status}
              </span>
              <button className="btn btn-danger btn-sm"
                onClick={e => del(e, s.id)}
                disabled={deleting === s.id}
                style={{ padding: '4px 8px', fontSize: '0.7rem' }}>
                {deleting === s.id ? '...' : '🗑'}
              </button>
            </div>
          ))}
        </div>
      </div>

      {/* Detail panel */}
      <div>
        {!selectedScanDetail ? (
          <div className="card" style={{ padding: 40, textAlign: 'center', color: 'var(--text-dim)' }}>
            <div style={{ fontSize: '2.5rem', marginBottom: 12 }}>🔬</div>
            <p>Select a scan to view findings</p>
          </div>
        ) : (
          <div className="card fade-up">
            {/* scan meta */}
            <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div>
                  <div style={{ fontFamily: 'JetBrains Mono, monospace', color: 'var(--cyan)', fontWeight: 700, fontSize: '1rem' }}>{selectedScanDetail.target}</div>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', marginTop: 4 }}>
                    {selectedScanDetail.tool.toUpperCase()} · {fmt(selectedScanDetail.created_at)}
                  </div>
                </div>
                <span className={`status-${selectedScanDetail.status}`} style={{ fontWeight: 700, fontSize: '0.82rem' }}>{selectedScanDetail.status}</span>
              </div>
              {selectedScanDetail.command && (
                <div style={{ marginTop: 10, padding: '8px 12px', background: 'var(--bg-primary)', borderRadius: 8, fontFamily: 'JetBrains Mono, monospace', fontSize: '0.73rem', color: 'var(--text-secondary)', wordBreak: 'break-all' }}>
                  $ {selectedScanDetail.command}
                </div>
              )}
            </div>

            {/* stats */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 1, borderBottom: '1px solid var(--border)' }}>
              {(['critical','high','medium','low'] as const).map(sev => {
                const cnt = findings.filter(f => f.severity === sev).length;
                return (
                  <div key={sev} style={{ padding: '12px 16px', borderRight: '1px solid var(--border)', textAlign: 'center' }}>
                    <div style={{ fontSize: '1.3rem', fontWeight: 800, color: `var(--sev-${sev})` }}>{cnt}</div>
                    <div style={{ fontSize: '0.65rem', textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-dim)' }}>{sev}</div>
                  </div>
                );
              })}
            </div>

            {/* findings */}
            <div style={{ maxHeight: 340, overflowY: 'auto' }}>
              {findings.length === 0 ? (
                <div style={{ padding: 24, textAlign: 'center', color: 'var(--text-dim)', fontSize: '0.83rem' }}>No structured findings. Check raw output.</div>
              ) : findings.map(f => (
                <div key={f.id} style={{ padding: '12px 20px', borderBottom: '1px solid var(--border)' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                    <span className={`badge badge-${f.severity}`}>{f.severity}</span>
                    <span style={{ fontSize: '0.83rem', fontWeight: 600 }}>{f.title}</span>
                  </div>
                  {(f.host || f.port) && (
                    <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', fontFamily: 'JetBrains Mono, monospace' }}>
                      {f.host}{f.port ? `:${f.port}` : ''}{f.service ? ` (${f.service})` : ''}
                    </div>
                  )}
                  {f.description && <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: 4 }}>{f.description}</div>}
                </div>
              ))}
            </div>

            {/* correlations */}
            {selectedScanDetail.suggestions && selectedScanDetail.suggestions.length > 0 && (
              <div style={{ padding: '12px 20px', borderTop: '1px solid var(--border)', background: 'rgba(99,102,241,0.04)' }}>
                <div className="label" style={{ marginBottom: 8, color: 'var(--accent)' }}>🔗 Correlation Engine Suggestions</div>
                {selectedScanDetail.suggestions.map((s, i) => (
                  <div key={i} style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', padding: '4px 0', borderBottom: '1px solid var(--border)' }}>
                    ▸ {s}
                  </div>
                ))}
              </div>
            )}

            {/* raw output */}
            {selectedScanDetail.raw_output && (
              <details style={{ padding: '0 20px 16px' }}>
                <summary style={{ cursor: 'pointer', fontSize: '0.78rem', color: 'var(--text-dim)', padding: '12px 0', userSelect: 'none' }}>
                  Raw Terminal Output
                </summary>
                <pre className="terminal" style={{ maxHeight: 200, marginTop: 8 }}>{selectedScanDetail.raw_output}</pre>
              </details>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
