'use client';
import { useState, useEffect, useCallback } from 'react';
import { api, Scan, ToolConfig } from './lib/api';
import Sidebar from './components/Sidebar';
import Dashboard from './components/Dashboard';
import ToolCockpit from './components/ToolCockpit';
import ScanHistory from './components/ScanHistory';
import WorkflowPanel from './components/WorkflowPanel';

type View = 'dashboard' | 'tool' | 'scans' | 'workflow';

export default function Page() {
  const [view, setView] = useState<View>('dashboard');
  const [tools, setTools] = useState<Record<string, ToolConfig>>({});
  const [scans, setScans] = useState<Scan[]>([]);
  const [selectedTool, setSelectedTool] = useState<string | null>(null);
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
  const [selectedScanDetail, setSelectedScanDetail] = useState<Scan | null>(null);
  const [backendOnline, setBackendOnline] = useState(false);
  const [loadingScans, setLoadingScans] = useState(false);
  const [clock, setClock] = useState(''); // empty string on SSR to avoid hydration mismatch

  const loadTools = useCallback(async () => {
    try { setTools(await api.tools()); } catch { /* offline */ }
  }, []);

  const loadScans = useCallback(async () => {
    setLoadingScans(true);
    try { setScans(await api.scans()); } catch { /* offline */ }
    setLoadingScans(false);
  }, []);

  const checkHealth = useCallback(async () => {
    try { await api.health(); setBackendOnline(true); } catch { setBackendOnline(false); }
  }, []);

  useEffect(() => {
    checkHealth();
    loadTools();
    loadScans();
    const interval = setInterval(() => { checkHealth(); loadScans(); }, 10000);
    return () => clearInterval(interval);
  }, [checkHealth, loadTools, loadScans]);

  // Clock: only runs on client so it never mismatches SSR output
  useEffect(() => {
    const tick = () => setClock(new Date().toLocaleTimeString());
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, []);

  const handleSelectScan = useCallback(async (id: string) => {
    setSelectedScanId(id);
    setSelectedScanDetail(null);
    try { setSelectedScanDetail(await api.scan(id)); } catch { /* ignore */ }
  }, []);

  const handleScanLaunched = useCallback(async (scanId: string) => {
    await loadScans();
    setSelectedScanId(scanId);
    setView('scans');
    try { setSelectedScanDetail(await api.scan(scanId)); } catch { /* ignore */ }
  }, [loadScans]);

  const navigate = (v: string, toolId?: string) => {
    if (toolId) setSelectedTool(toolId);
    setView(v as View);
  };

  const renderMain = () => {
    switch (view) {
      case 'dashboard':
        return <Dashboard scans={scans} tools={tools} onNavigate={navigate} backendOnline={backendOnline} />;
      case 'tool':
        if (!selectedTool || !tools[selectedTool]) return (
          <div className="card" style={{ padding: 40, textAlign: 'center', color: 'var(--text-dim)' }}>
            Select a tool from the sidebar
          </div>
        );
        return <ToolCockpit key={selectedTool} tool={tools[selectedTool]} onScanLaunched={handleScanLaunched} />;
      case 'scans':
        return <ScanHistory scans={scans} onRefresh={loadScans} onSelectScan={handleSelectScan}
          selectedScanId={selectedScanId} selectedScanDetail={selectedScanDetail} loading={loadingScans} />;
      case 'workflow':
        return <WorkflowPanel onScanLaunched={loadScans} />;
      default:
        return null;
    }
  };

  return (
    <div className="layout">
      <Sidebar
        tools={tools}
        selectedTool={selectedTool}
        onSelectTool={t => { setSelectedTool(t); setView('tool'); }}
        activeView={view}
        onSetView={v => setView(v as View)}
        scanCount={scans.length}
      />
      <main className="main-content">
        {/* Top bar */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexShrink: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontSize: '0.78rem', color: 'var(--text-dim)' }}>Status:</span>
            <span style={{
              display: 'inline-flex', alignItems: 'center', gap: 5,
              fontSize: '0.78rem', fontWeight: 700,
              color: backendOnline ? 'var(--green)' : 'var(--red)',
            }}>
              <span style={{
                width: 8, height: 8, borderRadius: '50%',
                background: backendOnline ? 'var(--green)' : 'var(--red)',
                boxShadow: `0 0 6px ${backendOnline ? 'var(--green-glow)' : 'var(--red-glow)'}`,
                animation: backendOnline ? 'pulse 2s infinite' : 'none',
              }} />
              {backendOnline ? 'Backend Online' : 'Backend Offline'}
            </span>
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', fontFamily: 'JetBrains Mono, monospace' }}>
            localhost:8001 · {clock}
          </div>
        </div>

        {/* Main view */}
        {renderMain()}
      </main>
    </div>
  );
}
