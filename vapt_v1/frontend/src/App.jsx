import React, { useState, useEffect, useRef, useCallback } from 'react';
import axios from 'axios';
import {
  ShieldCheck, AlertTriangle, UploadCloud, Activity,
  Terminal, ShieldAlert, CheckCircle2, ChevronRight, ChevronDown,
  Trash2, Globe, Wifi, WifiOff, X, Search, Loader2,
  Download, FileJson, FileText, Settings, Zap, Cpu, Info
} from 'lucide-react';
import './index.css';

const API_BASE = 'http://127.0.0.1:8484/api';

const formatIST = (isoStr) => {
  if (!isoStr) return 'N/A';
  try {
    return new Date(isoStr).toLocaleString('en-IN', { timeZone: 'Asia/Kolkata', dateStyle: 'medium', timeStyle: 'short' });
  } catch { return new Date(isoStr).toLocaleString(); }
};

/* ═══════ Toast System ═══════ */
let toastIdCounter = 0;
function useToast() {
  const [toasts, setToasts] = useState([]);
  const addToast = useCallback((message, type = 'info') => {
    const id = ++toastIdCounter;
    setToasts(prev => [...prev, { id, message, type }]);
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 4000);
  }, []);
  const removeToast = useCallback((id) => setToasts(prev => prev.filter(t => t.id !== id)), []);
  return { toasts, addToast, removeToast };
}

function ToastContainer({ toasts, onRemove }) {
  return (
    <div className="toast-container">
      {toasts.map(t => (
        <div key={t.id} className={`toast toast-${t.type}`}>
          {t.type === 'success' && <CheckCircle2 size={18} color="var(--success)" />}
          {t.type === 'error' && <AlertTriangle size={18} color="var(--danger)" />}
          {t.type === 'info' && <Info size={18} color="var(--primary)" />}
          <span style={{ flex: 1 }}>{t.message}</span>
          <button className="toast-close" onClick={() => onRemove(t.id)}><X size={14} /></button>
        </div>
      ))}
    </div>
  );
}

/* ═══════ Main App ═══════ */
function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [scans, setScans] = useState([]);
  const [currentScanId, setCurrentScanId] = useState(null);
  const [scanDetails, setScanDetails] = useState(null);
  const [health, setHealth] = useState(null);
  const [deleteModal, setDeleteModal] = useState(null);
  const [bulkDeleteModal, setBulkDeleteModal] = useState(false);
  const [aiMode, setAiMode] = useState('offline');
  const [groqKey, setGroqKey] = useState('');
  const { toasts, addToast, removeToast } = useToast();

  useEffect(() => {
    fetchScans(); fetchHealth(); fetchAISettings();
    const i1 = setInterval(fetchScans, 5000);
    const i2 = setInterval(fetchHealth, 30000);
    return () => { clearInterval(i1); clearInterval(i2); };
  }, []);

  const fetchScans = async () => { try { const r = await axios.get(`${API_BASE}/scans`); setScans(r.data.scans); } catch {} };
  const fetchHealth = async () => { try { const r = await axios.get(`${API_BASE}/health`); setHealth(r.data.tools); } catch {} };
  const fetchAISettings = async () => { try { const r = await axios.get(`${API_BASE}/settings/ai`); if (r.data.online_available) setAiMode('online'); } catch {} };

  const fetchScanDetails = async (id) => {
    try { const r = await axios.get(`${API_BASE}/scan/${id}`); setScanDetails(r.data); setCurrentScanId(id); setActiveTab('results'); } catch { addToast('Failed to load scan details', 'error'); }
  };

  const handleDeleteScan = async (scanId, force = false) => {
    try {
      await axios.delete(`${API_BASE}/scan/${scanId}?force=${force}`);
      setDeleteModal(null);
      if (currentScanId === scanId) { setCurrentScanId(null); setScanDetails(null); setActiveTab('dashboard'); }
      fetchScans();
      addToast('Scan deleted successfully', 'success');
    } catch (e) {
      const detail = e.response?.data?.detail || 'Failed to delete scan';
      if (e.response?.status === 409) { addToast(detail + ' — use force delete.', 'error'); }
      else { addToast(detail, 'error'); }
    }
  };

  const handleBulkDelete = async () => {
    try {
      const r = await axios.delete(`${API_BASE}/scans/all?force=true`);
      setBulkDeleteModal(false);
      setCurrentScanId(null); setScanDetails(null); setActiveTab('dashboard');
      fetchScans();
      addToast(`Deleted ${r.data.deleted} scans`, 'success');
    } catch { addToast('Bulk delete failed', 'error'); }
  };

  const saveGroqKey = async (key) => {
    try {
      const r = await axios.post(`${API_BASE}/settings/ai`, { groq_api_key: key });
      if (r.data.online_available) { setAiMode('online'); addToast('Groq API key saved! Online AI ready.', 'success'); }
      else { addToast('Key saved but online AI not available', 'error'); }
      fetchHealth();
    } catch { addToast('Failed to save API key', 'error'); }
  };

  return (
    <div className="flex" style={{ minHeight: '100vh' }}>
      <ToastContainer toasts={toasts} onRemove={removeToast} />

      {/* Sidebar */}
      <div className="glass-panel" style={{ width: '280px', margin: '16px', padding: '24px', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
        <div>
          <div className="flex" style={{ alignItems: 'center', gap: '12px', marginBottom: '40px' }}>
            <div style={{ background: 'linear-gradient(135deg, var(--primary), var(--secondary))', padding: '10px', borderRadius: '14px', boxShadow: '0 4px 15px rgba(99, 102, 241, 0.3)' }}>
              <ShieldAlert size={26} color="white" />
            </div>
            <div>
              <h2 style={{ fontSize: '1.2rem', fontWeight: 800, margin: 0, letterSpacing: '-0.5px' }}>VAPT Engine</h2>
              <span style={{ fontSize: '0.7rem', color: 'var(--accent)', fontWeight: 600, letterSpacing: '0.05em' }}>v1.1.1</span>
            </div>
          </div>

          <nav style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            <NavItem icon={<Activity size={19} />} label="Dashboard" active={activeTab === 'dashboard'} onClick={() => setActiveTab('dashboard')} />
            <NavItem icon={<UploadCloud size={19} />} label="File Scan" active={activeTab === 'new'} onClick={() => setActiveTab('new')} />
            <NavItem icon={<Globe size={19} />} label="URL Scan" active={activeTab === 'url'} onClick={() => setActiveTab('url')} badge="Online" />
            <NavItem icon={<Terminal size={19} />} label="Results" active={activeTab === 'results'} onClick={() => setActiveTab('results')} disabled={!currentScanId} />
            <NavItem icon={<Settings size={19} />} label="Settings" active={activeTab === 'settings'} onClick={() => setActiveTab('settings')} />
          </nav>
        </div>

        {health && (
          <div style={{ borderTop: '1px solid rgba(255,255,255,0.06)', paddingTop: '16px', marginTop: '16px' }}>
            <p style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '10px' }}>Tool Status</p>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
              <HealthRow label="Nuclei" ok={health.nuclei} />
              <HealthRow label="Trivy" ok={health.trivy} />
              <HealthRow label="Radare2" ok={health.radare2} />
              <HealthRow label="ZAP" ok={health.zap} />
              <HealthRow label="AI Local" ok={health.ai_loaded} />
              <HealthRow label="AI Online" ok={health.ai_online} />
            </div>
          </div>
        )}
      </div>

      {/* Main */}
      <main style={{ flex: 1, padding: '16px 24px 16px 0', overflowY: 'auto' }}>
        {activeTab === 'dashboard' && <DashboardTab scans={scans} onSelectScan={fetchScanDetails} onDeleteScan={id => setDeleteModal(id)} onBulkDelete={() => setBulkDeleteModal(true)} />}
        {activeTab === 'new' && <NewScanTab aiMode={aiMode} setAiMode={setAiMode} health={health} onScanStarted={id => { fetchScans(); fetchScanDetails(id); }} addToast={addToast} />}
        {activeTab === 'url' && <URLScanTab aiMode={aiMode} setAiMode={setAiMode} health={health} onScanStarted={id => { fetchScans(); fetchScanDetails(id); }} addToast={addToast} />}
        {activeTab === 'results' && <ResultsTab scanDetails={scanDetails} onRefresh={() => fetchScanDetails(currentScanId)} onDeleteScan={id => setDeleteModal(id)} addToast={addToast} />}
        {activeTab === 'settings' && <SettingsTab groqKey={groqKey} setGroqKey={setGroqKey} onSave={saveGroqKey} health={health} aiMode={aiMode} setAiMode={setAiMode} addToast={addToast} />}
      </main>

      {/* Delete Modal */}
      {deleteModal && (
        <div className="modal-overlay" onClick={() => setDeleteModal(null)}>
          <div className="modal-content" onClick={e => e.stopPropagation()}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
              <h3 style={{ fontSize: '1.15rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '10px' }}><Trash2 size={20} color="var(--danger)" /> Delete Scan</h3>
              <button onClick={() => setDeleteModal(null)} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}><X size={20} /></button>
            </div>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.95rem', lineHeight: 1.6, marginBottom: '24px' }}>This will permanently delete the scan, all findings, AI analysis, and files. This action cannot be undone.</p>
            <div style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end' }}>
              <button className="btn-ghost" onClick={() => setDeleteModal(null)}>Cancel</button>
              <button className="btn-danger" style={{ padding: '10px 24px', fontSize: '0.9rem' }} onClick={() => handleDeleteScan(deleteModal, true)}><Trash2 size={16} /> Delete</button>
            </div>
          </div>
        </div>
      )}

      {/* Bulk Delete Modal */}
      {bulkDeleteModal && (
        <div className="modal-overlay" onClick={() => setBulkDeleteModal(false)}>
          <div className="modal-content" onClick={e => e.stopPropagation()}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
              <h3 style={{ fontSize: '1.15rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '10px' }}><Trash2 size={20} color="var(--danger)" /> Clear All Scans</h3>
              <button onClick={() => setBulkDeleteModal(false)} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}><X size={20} /></button>
            </div>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.95rem', lineHeight: 1.6, marginBottom: '24px' }}>This will permanently delete ALL {scans.length} scans. This cannot be undone.</p>
            <div style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end' }}>
              <button className="btn-ghost" onClick={() => setBulkDeleteModal(false)}>Cancel</button>
              <button className="btn-danger" style={{ padding: '10px 24px', fontSize: '0.9rem' }} onClick={handleBulkDelete}><Trash2 size={16} /> Delete All</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

/* ═══════ Helpers ═══════ */
function NavItem({ icon, label, active, onClick, disabled, badge }) {
  return (
    <button onClick={onClick} disabled={disabled} style={{
      display: 'flex', alignItems: 'center', gap: '12px', padding: '11px 14px',
      backgroundColor: active ? 'rgba(99, 102, 241, 0.12)' : 'transparent',
      color: active ? 'var(--primary)' : disabled ? 'var(--border)' : 'var(--text-muted)',
      border: active ? '1px solid rgba(99, 102, 241, 0.2)' : '1px solid transparent',
      borderRadius: '10px', cursor: disabled ? 'not-allowed' : 'pointer',
      fontWeight: 600, fontSize: '0.9rem', transition: 'all 0.2s', textAlign: 'left', width: '100%'
    }}>
      {icon}{label}
      {badge && <span style={{ marginLeft: 'auto', fontSize: '0.6rem', fontWeight: 700, background: 'rgba(34, 211, 238, 0.15)', color: '#22d3ee', padding: '2px 8px', borderRadius: '100px' }}>{badge}</span>}
    </button>
  );
}

function HealthRow({ label, ok }) {
  return (<div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.78rem', color: 'var(--text-muted)' }}><span className={`health-dot ${ok ? 'online' : 'offline'}`} />{label}</div>);
}

function Badge({ status }) {
  const map = {
    pending: { bg: 'rgba(255,255,255,0.08)', color: '#94a3b8', label: 'Pending' },
    processing_files: { bg: 'rgba(59, 130, 246, 0.15)', color: '#93c5fd', label: 'Processing' },
    scanning: { bg: 'rgba(234, 179, 8, 0.15)', color: '#fde047', label: 'Scanning' },
    ai_analysis: { bg: 'rgba(139, 92, 246, 0.15)', color: '#c4b5fd', label: 'AI Analysis' },
    completed: { bg: 'rgba(34, 197, 94, 0.15)', color: '#86efac', label: 'Completed' },
    failed: { bg: 'rgba(239, 68, 68, 0.15)', color: '#fca5a5', label: 'Failed' },
  };
  const c = map[status] || map.pending;
  return (<span style={{ background: c.bg, color: c.color, padding: '4px 12px', borderRadius: '100px', fontSize: '0.72rem', fontWeight: 600 }}>{c.label}</span>);
}

function StatCard({ title, value, icon, accent }) {
  return (
    <div className="glass-panel glass-panel-hover" style={{ padding: '22px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
      <div>
        <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem', marginBottom: '6px', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>{title}</p>
        <h2 style={{ fontSize: '2.2rem', margin: 0, fontWeight: 800 }}>{value}</h2>
      </div>
      <div style={{ background: `${accent}10`, padding: '14px', borderRadius: '14px', border: `1px solid ${accent}20` }}>{icon}</div>
    </div>
  );
}

function MiniStat({ label, count, color }) {
  return (
    <div className="glass-panel" style={{ padding: '14px 18px', display: 'flex', alignItems: 'center', gap: '12px' }}>
      <div style={{ width: '4px', height: '32px', borderRadius: '2px', background: color }} />
      <div>
        <p style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase' }}>{label}</p>
        <p style={{ fontSize: '1.4rem', fontWeight: 800, color }}>{count}</p>
      </div>
    </div>
  );
}

function AIToggle({ aiMode, setAiMode, health }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
      <span style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-muted)' }}>AI Mode:</span>
      <div className="toggle-container">
        <button className={`toggle-option ${aiMode === 'offline' ? 'active' : ''}`} onClick={() => setAiMode('offline')}><Cpu size={14} /> Offline (Local)</button>
        <button className={`toggle-option ${aiMode === 'online' ? 'active' : ''}`} onClick={() => setAiMode('online')}><Zap size={14} /> Online (Fast)</button>
      </div>
      {aiMode === 'online' && !(health?.ai_online) && <span style={{ fontSize: '0.75rem', color: 'var(--danger)' }}>⚠ Set Groq key in Settings</span>}
    </div>
  );
}

/* ═══════ Markdown Renderer (no deps) ═══════ */
function MarkdownBlock({ text }) {
  if (!text) return null;
  const lines = text.split('\n');
  const elements = [];
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (/^### /.test(line)) { elements.push(<h3 key={i} style={{fontSize:'1rem',fontWeight:700,color:'var(--primary)',marginTop:'18px',marginBottom:'6px'}}>{line.replace(/^### /,'')}</h3>); }
    else if (/^## /.test(line)) { elements.push(<h2 key={i} style={{fontSize:'1.1rem',fontWeight:700,color:'var(--accent)',marginTop:'22px',marginBottom:'8px'}}>{line.replace(/^## /,'')}</h2>); }
    else if (/^# /.test(line)) { elements.push(<h1 key={i} style={{fontSize:'1.25rem',fontWeight:800,color:'white',marginTop:'24px',marginBottom:'10px'}}>{line.replace(/^# /,'')}</h1>); }
    else if (/^\*\*(.+)\*\*$/.test(line.trim())) { elements.push(<p key={i} style={{fontWeight:700,color:'#e2e8f0',margin:'6px 0'}}>{line.trim().replace(/\*\*/g,'')}</p>); }
    else if (/^[-*] /.test(line)) { elements.push(<li key={i} style={{marginLeft:'18px',color:'#cbd5e1',lineHeight:1.7,fontSize:'0.9rem'}}>{line.replace(/^[-*] /,'').replace(/\*\*(.+?)\*\*/g,(_,t)=>t)}</li>); }
    else if (/^\d+\./.test(line)) { elements.push(<li key={i} style={{marginLeft:'18px',color:'#cbd5e1',lineHeight:1.7,fontSize:'0.9rem',listStyleType:'decimal'}}>{line.replace(/^\d+\.\s*/,'')}</li>); }
    else if (line.trim() === '') { elements.push(<div key={i} style={{height:'8px'}} />); }
    else if (/^---+$/.test(line.trim())) { elements.push(<hr key={i} style={{border:'none',borderTop:'1px solid rgba(255,255,255,0.08)',margin:'12px 0'}} />); }
    else { elements.push(<p key={i} style={{color:'#cbd5e1',lineHeight:1.75,fontSize:'0.92rem',margin:'3px 0'}} dangerouslySetInnerHTML={{__html: line.replace(/\*\*(.+?)\*\*/g,'<strong>$1</strong>').replace(/`(.+?)`/g,'<code style="background:rgba(99,102,241,0.15);padding:1px 5px;border-radius:4px;font-size:0.85em;color:#a5b4fc">$1</code>')}} />); }
    i++;
  }
  return <div>{elements}</div>;
}

/* ═══════ Timeline Stepper ═══════ */
function ScanTimeline({ status }) {
  const steps = [
    { key: 'pending', label: 'Pending' },
    { key: 'processing_files', label: 'Processing' },
    { key: 'scanning', label: 'Scanning' },
    { key: 'ai_analysis', label: 'AI Analysis' },
    { key: 'completed', label: 'Completed' },
  ];
  const currentIdx = steps.findIndex(s => s.key === status);
  const isFailed = status === 'failed';

  return (
    <div className="glass-panel" style={{ padding: '16px 24px', marginBottom: '24px' }}>
      <div className="timeline-stepper">
        {steps.map((step, i) => (
          <React.Fragment key={step.key}>
            <div className="timeline-step">
              <div className={`step-dot ${isFailed && i === currentIdx ? 'failed' : i < currentIdx ? 'completed' : i === currentIdx ? 'active' : 'pending'}`}>
                {i < currentIdx ? '✓' : isFailed && i === currentIdx ? '✕' : i + 1}
              </div>
              <span className={`step-label ${i === currentIdx ? 'active-label' : i < currentIdx ? 'completed-label' : ''}`}>{step.label}</span>
            </div>
            {i < steps.length - 1 && <div className={`timeline-connector ${i < currentIdx ? 'completed' : ''}`} />}
          </React.Fragment>
        ))}
      </div>
    </div>
  );
}

/* ═══════ Live Scan Log Console ═══════ */
const ACTIVE_STATUSES = ['pending','processing_files','scanning','ai_analysis'];

function ScanLiveLog({ scanId, scanStatus }) {
  const [logs, setLogs] = useState([]);
  const [percent, setPercent] = useState(0);
  const bottomRef = useRef(null);
  const isActive = ACTIVE_STATUSES.includes(scanStatus);

  const offsetRef = useRef(0);
  useEffect(() => {
    if (!scanId) return;
    let cancelled = false;
    offsetRef.current = 0;
    setLogs([]);
    setPercent(0);

    const poll = async () => {
      try {
        const r = await axios.get(`${API_BASE}/scan/${scanId}/logs?since=${offsetRef.current}`);
        if (cancelled) return;
        const newLogs = r.data.logs || [];
        if (newLogs.length > 0) {
          setLogs(prev => [...prev, ...newLogs]);
          offsetRef.current = r.data.total;
          const lastPct = [...newLogs].reverse().find(l => l.percent !== undefined);
          if (lastPct) setPercent(lastPct.percent);
        }
      } catch {}
    };

    poll();
    const interval = isActive ? setInterval(poll, 1500) : null;
    return () => { cancelled = true; if (interval) clearInterval(interval); };
  }, [scanId, scanStatus]);

  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [logs]);

  if (!scanId || logs.length === 0) return null;

  const levelColor = { info: '#94a3b8', success: '#4ade80', error: '#f87171', warning: '#fbbf24' };
  const levelIcon = { info: '●', success: '✓', error: '✕', warning: '⚠' };

  return (
    <div className="glass-panel" style={{ marginBottom: '24px', overflow: 'hidden' }}>
      <div style={{ padding: '14px 20px', borderBottom: '1px solid rgba(255,255,255,0.06)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <Terminal size={16} color="var(--primary)" />
          <span style={{ fontSize: '0.88rem', fontWeight: 700 }}>Live Scan Console</span>
          {isActive && <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#4ade80', boxShadow: '0 0 8px #4ade80', animation: 'pulse 1.5s infinite' }} />}
        </div>
        <span style={{ fontSize: '0.78rem', color: 'var(--accent)', fontWeight: 700 }}>{percent}%</span>
      </div>
      {/* Progress Bar */}
      <div style={{ height: '3px', background: 'rgba(255,255,255,0.05)' }}>
        <div style={{ height: '100%', width: `${percent}%`, background: 'linear-gradient(90deg, var(--primary), var(--accent))', transition: 'width 0.6s ease', borderRadius: '0 2px 2px 0' }} />
      </div>
      <div style={{ padding: '16px 20px', maxHeight: '260px', overflowY: 'auto', fontFamily: 'monospace', fontSize: '0.82rem' }}>
        {logs.map((entry, i) => (
          <div key={i} style={{ display: 'flex', gap: '10px', marginBottom: '5px', color: levelColor[entry.level] || '#94a3b8' }}>
            <span style={{ opacity: 0.5, flexShrink: 0 }}>{new Date(entry.ts).toLocaleTimeString('en-IN',{hour12:false,hour:'2-digit',minute:'2-digit',second:'2-digit'})}</span>
            <span style={{ flexShrink: 0 }}>{levelIcon[entry.level] || '●'}</span>
            <span style={{ flex: 1 }}>{entry.message}</span>
            {entry.percent !== undefined && <span style={{ flexShrink: 0, opacity: 0.5 }}>[{entry.percent}%]</span>}
          </div>
        ))}
        <div ref={bottomRef} />
      </div>
    </div>
  );
}

/* ═══════ Dashboard Tab ═══════ */
function DashboardTab({ scans, onSelectScan, onDeleteScan, onBulkDelete }) {
  const [searchTerm, setSearchTerm] = useState('');
  const activeScans = scans.filter(s => ['scanning', 'processing_files', 'ai_analysis'].includes(s.status)).length;
  const completedScans = scans.filter(s => s.status === 'completed').length;
  const failedScans = scans.filter(s => s.status === 'failed').length;
  const filtered = scans.filter(s => s.filename.toLowerCase().includes(searchTerm.toLowerCase()));

  return (
    <div className="animate-fade-in" style={{ padding: '24px 0' }}>
      <header style={{ marginBottom: '40px' }}>
        <h1 className="heading-xl">Security <span className="text-gradient">Overview</span></h1>
        <p className="text-muted" style={{ marginTop: '8px', fontSize: '1.05rem' }}>Monitor and analyze your infrastructure vulnerabilities.</p>
      </header>

      <div className="grid" style={{ gridTemplateColumns: 'repeat(4, 1fr)', gap: '20px', marginBottom: '40px' }}>
        <StatCard title="Total Scans" value={scans.length} icon={<Activity color="#3b82f6" />} accent="#3b82f6" />
        <StatCard title="Active" value={activeScans} icon={<ShieldCheck color="#eab308" />} accent="#eab308" />
        <StatCard title="Completed" value={completedScans} icon={<CheckCircle2 color="#22c55e" />} accent="#22c55e" />
        <StatCard title="Failed" value={failedScans} icon={<AlertTriangle color="#ef4444" />} accent="#ef4444" />
      </div>

      <div className="glass-panel" style={{ padding: '24px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
          <h3 style={{ fontSize: '1.2rem', fontWeight: 700 }}>Recent Activity</h3>
          <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
            <div style={{ position: 'relative' }}>
              <Search size={16} style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
              <input className="search-input" placeholder="Search scans..." value={searchTerm} onChange={e => setSearchTerm(e.target.value)} style={{ width: '220px' }} />
            </div>
            {scans.length > 0 && <button className="btn-danger" onClick={onBulkDelete} style={{ padding: '8px 14px' }}><Trash2 size={14} /> Clear All</button>}
          </div>
        </div>

        {filtered.length === 0 ? (
          <div style={{ padding: '48px', textAlign: 'center', color: 'var(--text-muted)' }}>
            <UploadCloud size={48} style={{ marginBottom: '16px', opacity: 0.3 }} />
            <p>{searchTerm ? 'No scans match your search.' : 'No scans found. Start a new scan to see results here.'}</p>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {filtered.map(scan => (
              <div key={scan.id} className="glass-panel-hover" style={{
                display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                padding: '14px 18px', background: 'rgba(255,255,255,0.02)', borderRadius: '12px',
                cursor: 'pointer', border: '1px solid rgba(255,255,255,0.04)', transition: 'all 0.2s'
              }}>
                <div onClick={() => onSelectScan(scan.id)} style={{ display: 'flex', alignItems: 'center', gap: '14px', flex: 1 }}>
                  <div style={{
                    width: '10px', height: '10px', borderRadius: '50%',
                    background: scan.status === 'completed' ? '#22c55e' : scan.status === 'failed' ? '#ef4444' : '#eab308',
                    boxShadow: ['scanning', 'processing_files'].includes(scan.status) ? '0 0 10px #eab308' : 'none'
                  }} />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <h4 style={{ margin: 0, fontSize: '0.95rem', fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{scan.filename}</h4>
                    <div style={{ display: 'flex', gap: '8px', alignItems: 'center', marginTop: '4px', flexWrap: 'wrap' }}>
                      <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{formatIST(scan.created_at)}</span>
                      <span className={`mode-${scan.scan_mode || 'offline'}`}>{scan.scan_mode || 'offline'}</span>
                      <span className={`ai-${scan.ai_mode || 'offline'}`}>AI: {scan.ai_mode || 'offline'}</span>
                    </div>
                  </div>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <Badge status={scan.status} />
                  <button className="btn-danger" onClick={e => { e.stopPropagation(); onDeleteScan(scan.id); }} title="Delete" style={{ padding: '6px 8px', minWidth: 'auto' }}><Trash2 size={14} /></button>
                  <ChevronRight size={18} color="var(--text-muted)" style={{ cursor: 'pointer' }} onClick={() => onSelectScan(scan.id)} />
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

/* ═══════ New (File) Scan Tab ═══════ */
function NewScanTab({ aiMode, setAiMode, health, onScanStarted, addToast }) {
  const [file, setFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const fileInputRef = useRef(null);

  const handleDrop = (e) => { e.preventDefault(); if (e.dataTransfer.files?.[0]) setFile(e.dataTransfer.files[0]); };

  const startScan = async () => {
    if (!file) return;
    setUploading(true);
    const formData = new FormData();
    formData.append('file', file);
    try {
      const res = await axios.post(`${API_BASE}/scan/upload?ai_mode=${aiMode}`, formData, { headers: { 'Content-Type': 'multipart/form-data' } });
      setFile(null);
      addToast(`Scan started (AI: ${aiMode})`, 'success');
      onScanStarted(res.data.scan_id);
    } catch { addToast('Upload failed', 'error'); }
    setUploading(false);
  };

  return (
    <div className="animate-slide-up" style={{ padding: '24px 0', maxWidth: '800px', margin: '0 auto' }}>
      <header style={{ marginBottom: '32px', textAlign: 'center' }}>
        <h1 className="heading-lg">Initiate <span className="text-gradient">Offline Scan</span></h1>
        <p className="text-muted" style={{ marginTop: '8px' }}>Upload source code, APKs, Docker archives, or project files.</p>
      </header>

      <div style={{ display: 'flex', justifyContent: 'center', marginBottom: '28px' }}><AIToggle aiMode={aiMode} setAiMode={setAiMode} health={health} /></div>

      <div className="glass-panel" style={{ padding: '64px 40px', textAlign: 'center', borderStyle: 'dashed', borderWidth: '2px', borderColor: file ? 'var(--primary)' : 'rgba(255,255,255,0.08)', transition: 'border-color 0.3s' }}
        onDragOver={e => e.preventDefault()} onDrop={handleDrop}>
        <UploadCloud size={56} color={file ? "var(--primary)" : "var(--text-muted)"} style={{ margin: '0 auto 24px', opacity: file ? 1 : 0.4 }} />
        {file ? (
          <div>
            <h3 style={{ fontSize: '1.15rem', marginBottom: '6px', fontWeight: 700 }}>{file.name}</h3>
            <p className="text-muted" style={{ marginBottom: '32px' }}>{(file.size / 1024 / 1024).toFixed(2)} MB</p>
            <button className="btn-primary" style={{ width: '100%', padding: '14px', fontSize: '1rem' }} onClick={startScan} disabled={uploading}>
              {uploading ? <span style={{ display: 'inline-flex', alignItems: 'center', gap: '8px' }}><Loader2 size={18} style={{ animation: 'spin 1s linear infinite' }} /> Initializing...</span> : 'Start Autonomous Scan'}
            </button>
          </div>
        ) : (
          <div>
            <h3 style={{ fontSize: '1.15rem', marginBottom: '12px' }}>Drag and drop your target file here</h3>
            <p className="text-muted" style={{ marginBottom: '24px', fontSize: '0.9rem' }}>Supports .zip, .tar.gz, .apk, or plain files.</p>
            <button className="btn-ghost" onClick={() => fileInputRef.current.click()}>Browse Files</button>
            <input type="file" ref={fileInputRef} style={{ display: 'none' }} onChange={e => setFile(e.target.files[0])} />
          </div>
        )}
      </div>
    </div>
  );
}

/* ═══════ URL Scan Tab ═══════ */
function URLScanTab({ aiMode, setAiMode, health, onScanStarted, addToast }) {
  const [url, setUrl] = useState('');
  const [scanning, setScanning] = useState(false);

  const startUrlScan = async () => {
    if (!url.trim()) return;
    if (!url.startsWith('http://') && !url.startsWith('https://')) { addToast('URL must start with http:// or https://', 'error'); return; }
    setScanning(true);
    try {
      const res = await axios.post(`${API_BASE}/scan/url?target_url=${encodeURIComponent(url)}&ai_mode=${aiMode}`);
      setUrl('');
      addToast(`URL scan started (AI: ${aiMode})`, 'success');
      onScanStarted(res.data.scan_id);
    } catch (e) { addToast(e.response?.data?.detail || 'Failed to start scan', 'error'); }
    setScanning(false);
  };

  return (
    <div className="animate-slide-up" style={{ padding: '24px 0', maxWidth: '800px', margin: '0 auto' }}>
      <header style={{ marginBottom: '32px', textAlign: 'center' }}>
        <h1 className="heading-lg">Online <span className="text-gradient">URL Scan</span></h1>
        <p className="text-muted" style={{ marginTop: '8px' }}>Scan a live website or API using Nuclei & ZAP.</p>
        <span className="mode-online" style={{ marginTop: '12px', display: 'inline-block' }}><Wifi size={10} style={{ marginRight: '4px', verticalAlign: 'middle' }} /> Requires Internet</span>
      </header>

      <div style={{ display: 'flex', justifyContent: 'center', marginBottom: '28px' }}><AIToggle aiMode={aiMode} setAiMode={setAiMode} health={health} /></div>

      <div className="glass-panel" style={{ padding: '48px 40px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' }}><Globe size={22} color="var(--accent)" /><h3 style={{ fontSize: '1.05rem', fontWeight: 700 }}>Target URL</h3></div>
        <div style={{ display: 'flex', gap: '12px', marginBottom: '16px' }}>
          <input className="url-input" type="text" value={url} onChange={e => setUrl(e.target.value)} onKeyDown={e => e.key === 'Enter' && startUrlScan()} placeholder="https://example.com" style={{ flex: 1 }} />
          <button className="btn-primary" onClick={startUrlScan} disabled={scanning || !url.trim()} style={{ whiteSpace: 'nowrap', padding: '12px 28px' }}>
            {scanning ? <span style={{ display: 'inline-flex', alignItems: 'center', gap: '8px' }}><Loader2 size={16} style={{ animation: 'spin 1s linear infinite' }} /> Scanning...</span>
              : <span style={{ display: 'inline-flex', alignItems: 'center', gap: '8px' }}><Search size={16} /> Scan URL</span>}
          </button>
        </div>
        <div style={{ marginTop: '32px', padding: '20px', background: 'rgba(255,255,255,0.02)', borderRadius: '10px', border: '1px solid rgba(255,255,255,0.04)' }}>
          <h4 style={{ fontSize: '0.85rem', fontWeight: 700, marginBottom: '12px', color: 'var(--text-muted)' }}>What this scan does:</h4>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '0.85rem', color: 'var(--text-muted)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}><span className="health-dot online" /> <strong style={{ color: 'var(--text-main)' }}>Nuclei</strong> — CVEs, misconfigs, default creds</div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}><span className="health-dot online" /> <strong style={{ color: 'var(--text-main)' }}>ZAP</strong> — XSS, SQL injection, CSRF</div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}><span className="health-dot online" /> <strong style={{ color: 'var(--text-main)' }}>AI</strong> — Summarizes with remediation</div>
          </div>
        </div>
      </div>
    </div>
  );
}

/* ═══════ Results Tab ═══════ */
function ResultsTab({ scanDetails, onRefresh, onDeleteScan, addToast }) {
  const [expandedRow, setExpandedRow] = useState(null);
  const [severityFilter, setSeverityFilter] = useState('all');
  const [falsePositives, setFalsePositives] = useState(new Set());

  if (!scanDetails) return <div style={{ color: 'white', padding: '40px' }}>Loading...</div>;
  const { scan, findings, ai_analysis } = scanDetails;

  const severityOrder = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
  const filteredFindings = findings.filter(f => (severityFilter === 'all' || f.severity === severityFilter) && !falsePositives.has(f.id));
  const sortedFindings = [...filteredFindings].sort((a, b) => (severityOrder[a.severity] ?? 5) - (severityOrder[b.severity] ?? 5));
  const fpCount = falsePositives.size;

  const criticalCount = filteredFindings.filter(f => f.severity === 'Critical').length;
  const highCount = filteredFindings.filter(f => f.severity === 'High').length;
  const mediumCount = filteredFindings.filter(f => f.severity === 'Medium').length;
  const lowCount = filteredFindings.filter(f => f.severity === 'Low').length;

  const toggleFP = (id, e) => { e.stopPropagation(); setFalsePositives(prev => { const s = new Set(prev); s.has(id) ? s.delete(id) : s.add(id); return s; }); };

  const exportReport = async (fmt) => {
    try {
      const r = await axios.get(`${API_BASE}/scan/${scan.id}/export?format=${fmt}`);
      const content = fmt === 'text' ? r.data.report : JSON.stringify(r.data, null, 2);
      const blob = new Blob([content], { type: fmt === 'text' ? 'text/plain' : 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = `vapt_report_${scan.id}.${fmt === 'text' ? 'txt' : 'json'}`; a.click();
      URL.revokeObjectURL(url);
      addToast(`Report exported as ${fmt.toUpperCase()}`, 'success');
    } catch { addToast('Export failed', 'error'); }
  };

  const isActive = ['pending','processing_files','scanning','ai_analysis'].includes(scan.status);

  return (
    <div className="animate-fade-in" style={{ padding: '24px 0' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '24px', flexWrap: 'wrap', gap: '16px' }}>
        <div>
          <h1 className="heading-lg" style={{ marginBottom: '8px', wordBreak: 'break-all' }}>{scan.filename}</h1>
          <div style={{ display: 'flex', gap: '10px', alignItems: 'center', flexWrap: 'wrap' }}>
            <Badge status={scan.status} />
            <span className={`mode-${scan.scan_mode || 'offline'}`}>{scan.scan_mode || 'offline'}</span>
            <span className={`ai-${scan.ai_mode || 'offline'}`}>AI: {scan.ai_mode || 'offline'}</span>
            <span className="text-muted" style={{ fontSize: '0.85rem' }}>Started: {formatIST(scan.created_at)}</span>
            {scan.completed_at && <span className="text-muted" style={{ fontSize: '0.85rem' }}>Completed: {formatIST(scan.completed_at)}</span>}
          </div>
        </div>
        <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
          <button className="btn-ghost" onClick={onRefresh}><Activity size={14} /> Refresh</button>
          <button className="btn-accent" onClick={() => exportReport('json')}><FileJson size={14} /> Export JSON</button>
          <button className="btn-accent" onClick={() => exportReport('text')}><FileText size={14} /> Export Report</button>
          <button className="btn-danger" style={{ padding: '8px 16px' }} onClick={() => onDeleteScan(scan.id)}><Trash2 size={14} /> Delete</button>
        </div>
      </div>

      {/* Timeline */}
      <ScanTimeline status={scan.status} />

      {/* Live Console — shown while active */}
      {isActive && <ScanLiveLog scanId={scan.id} scanStatus={scan.status} />}

      {/* Severity Summary */}
      {findings.length > 0 && (
        <div className="grid" style={{ gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px', marginBottom: '28px' }}>
          <MiniStat label="Critical" count={criticalCount} color="var(--severity-critical)" />
          <MiniStat label="High" count={highCount} color="var(--severity-high)" />
          <MiniStat label="Medium" count={mediumCount} color="var(--severity-medium)" />
          <MiniStat label="Low" count={lowCount} color="var(--severity-low)" />
        </div>
      )}

      {/* AI Executive Summary */}
      {ai_analysis && (
        <div className="glass-panel" style={{ padding: '28px', marginBottom: '28px', borderLeft: '3px solid var(--primary)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '20px' }}>
            <div style={{ background: 'linear-gradient(135deg,var(--primary),var(--secondary))', padding: '8px', borderRadius: '10px' }}>
              <Terminal size={18} color="white" />
            </div>
            <div>
              <h2 style={{ fontSize: '1.15rem', margin: 0, fontWeight: 800 }}>AI Executive Summary</h2>
              <p style={{ margin: 0, fontSize: '0.75rem', color: 'var(--text-muted)' }}>Generated by {scan.ai_mode === 'online' ? 'Groq (LLaMA-3 70B)' : 'Local LLaMA-3 8B'}</p>
            </div>
          </div>
          <div style={{ background: 'rgba(0,0,0,0.2)', borderRadius: '10px', padding: '20px 24px' }}>
            <MarkdownBlock text={ai_analysis} />
          </div>
        </div>
      )}

      {/* Findings */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px', flexWrap: 'wrap', gap: '12px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
          <h2 style={{ fontSize: '1.25rem', fontWeight: 700 }}>Vulnerabilities ({sortedFindings.length})</h2>
          {fpCount > 0 && <span style={{ fontSize: '0.75rem', background: 'rgba(234,179,8,0.12)', color: '#fde047', padding: '3px 10px', borderRadius: '100px' }}>{fpCount} false positive{fpCount > 1 ? 's' : ''} hidden</span>}
        </div>
        <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
          {['all', 'Critical', 'High', 'Medium', 'Low', 'Info'].map(s => (
            <button key={s} className={`filter-chip ${severityFilter === s ? 'active' : ''}`} onClick={() => setSeverityFilter(s)}>{s === 'all' ? 'All' : s}</button>
          ))}
        </div>
      </div>

      <div className="glass-panel" style={{ overflow: 'hidden' }}>
        {sortedFindings.length === 0 ? (
          <div style={{ padding: '48px', textAlign: 'center', color: 'var(--text-muted)' }}>
            <ShieldCheck size={40} style={{ marginBottom: '12px', opacity: 0.3 }} />
            <p>{severityFilter !== 'all' ? `No ${severityFilter} findings.` : 'No vulnerabilities found yet.'}</p>
          </div>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
            <thead style={{ background: 'rgba(255,255,255,0.02)' }}>
              <tr>
                <th style={{ padding: '14px 20px', color: 'var(--text-muted)', fontWeight: 600, fontSize: '0.8rem', textTransform: 'uppercase', width: '30px' }}></th>
                <th style={{ padding: '14px 20px', color: 'var(--text-muted)', fontWeight: 600, fontSize: '0.8rem', textTransform: 'uppercase' }}>Severity</th>
                <th style={{ padding: '14px 20px', color: 'var(--text-muted)', fontWeight: 600, fontSize: '0.8rem', textTransform: 'uppercase' }}>Vulnerability</th>
                <th style={{ padding: '14px 20px', color: 'var(--text-muted)', fontWeight: 600, fontSize: '0.8rem', textTransform: 'uppercase' }}>File</th>
                <th style={{ padding: '14px 20px', color: 'var(--text-muted)', fontWeight: 600, fontSize: '0.8rem', textTransform: 'uppercase' }}>Tool</th>
                <th style={{ padding: '14px 20px', color: 'var(--text-muted)', fontWeight: 600, fontSize: '0.8rem', textTransform: 'uppercase' }}>FP</th>
              </tr>
            </thead>
            <tbody>
              {sortedFindings.map((f, i) => (
                <React.Fragment key={f.id || i}>
                  <tr className="expandable-row" onClick={() => setExpandedRow(expandedRow === i ? null : i)}
                    style={{ borderTop: '1px solid rgba(255,255,255,0.04)' }}>
                    <td style={{ padding: '14px 12px 14px 20px' }}>
                      <ChevronDown size={14} color="var(--text-muted)" style={{ transform: expandedRow === i ? 'rotate(180deg)' : 'rotate(0)', transition: 'transform 0.2s' }} />
                    </td>
                    <td style={{ padding: '14px 20px' }}><span className={`tag-${f.severity.toLowerCase()}`} style={{ padding: '4px 10px', borderRadius: '6px', fontSize: '0.75rem', fontWeight: 600 }}>{f.severity}</span></td>
                    <td style={{ padding: '14px 20px', fontWeight: 500, fontSize: '0.9rem' }}>{f.vulnerability_name}</td>
                    <td style={{ padding: '14px 20px', color: 'var(--text-muted)', fontSize: '0.8rem', wordBreak: 'break-all', maxWidth: '200px' }}>{f.file_path || 'N/A'}</td>
                    <td style={{ padding: '14px 20px' }}><span style={{ background: 'rgba(255,255,255,0.06)', padding: '4px 10px', borderRadius: '6px', fontSize: '0.75rem', fontWeight: 500 }}>{f.tool_name}</span></td>
                    <td style={{ padding: '14px 16px' }}>
                      <button onClick={e => toggleFP(f.id, e)} title="Mark as False Positive" style={{ background: falsePositives.has(f.id) ? 'rgba(234,179,8,0.15)' : 'rgba(255,255,255,0.04)', border: `1px solid ${falsePositives.has(f.id) ? 'rgba(234,179,8,0.3)' : 'rgba(255,255,255,0.08)'}`, color: falsePositives.has(f.id) ? '#fde047' : 'var(--text-muted)', borderRadius: '6px', padding: '4px 8px', cursor: 'pointer', fontSize: '0.7rem', fontWeight: 600 }}>
                        {falsePositives.has(f.id) ? '✓ FP' : 'FP'}
                      </button>
                    </td>
                  </tr>
                  {expandedRow === i && (
                    <tr><td colSpan="6" className="expand-detail">
                      <div className="expand-detail-content">
                        <div><div className="detail-label">Description</div><div className="detail-value">{f.description || 'No description available'}</div></div>
                        <div><div className="detail-label">Line Number</div><div className="detail-value">{f.line_number || 'N/A'}</div></div>
                        {f.raw_data && Object.keys(f.raw_data).length > 0 && (
                          <div className="detail-block-full"><div className="detail-label">Raw Scanner Data</div><div className="raw-data-box">{JSON.stringify(f.raw_data, null, 2)}</div></div>
                        )}
                      </div>
                    </td></tr>
                  )}
                </React.Fragment>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

/* ═══════ Settings Tab ═══════ */
function SettingsTab({ groqKey, setGroqKey, onSave, health, aiMode, setAiMode, addToast }) {
  return (
    <div className="animate-slide-up" style={{ padding: '24px 0', maxWidth: '700px', margin: '0 auto' }}>
      <header style={{ marginBottom: '40px' }}>
        <h1 className="heading-lg"><span className="text-gradient">Settings</span></h1>
        <p className="text-muted" style={{ marginTop: '8px' }}>Configure AI mode and API keys.</p>
      </header>

      <div className="glass-panel" style={{ padding: '32px', marginBottom: '24px' }}>
        <h3 style={{ fontSize: '1.1rem', fontWeight: 700, marginBottom: '20px', display: 'flex', alignItems: 'center', gap: '10px' }}><Zap size={20} color="var(--accent)" /> AI Analysis Mode</h3>
        <p style={{ color: 'var(--text-muted)', fontSize: '0.88rem', lineHeight: 1.6, marginBottom: '20px' }}>
          <strong>Offline</strong> uses the local Llama-3 model (slow but private). <strong>Online</strong> uses Groq API (fast, free, needs internet + API key).
        </p>
        <AIToggle aiMode={aiMode} setAiMode={setAiMode} health={health} />
      </div>

      <div className="glass-panel" style={{ padding: '32px' }}>
        <h3 style={{ fontSize: '1.1rem', fontWeight: 700, marginBottom: '20px', display: 'flex', alignItems: 'center', gap: '10px' }}><Settings size={20} color="var(--primary)" /> Groq API Key</h3>
        <p style={{ color: 'var(--text-muted)', fontSize: '0.88rem', lineHeight: 1.6, marginBottom: '20px' }}>
          Get a free API key from <a href="https://console.groq.com" target="_blank" rel="noreferrer" style={{ color: 'var(--accent)', textDecoration: 'underline' }}>console.groq.com</a>. This enables fast online AI analysis.
        </p>
        <div style={{ display: 'flex', gap: '12px' }}>
          <input className="settings-input" type="password" placeholder="gsk_..." value={groqKey} onChange={e => setGroqKey(e.target.value)} style={{ flex: 1 }} />
          <button className="btn-primary" onClick={() => onSave(groqKey)} disabled={!groqKey.trim()} style={{ padding: '12px 28px' }}>Save Key</button>
        </div>
        <div style={{ marginTop: '16px', display: 'flex', gap: '16px', fontSize: '0.82rem' }}>
          <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}><span className={`health-dot ${health?.ai_loaded ? 'online' : 'offline'}`} /> Offline AI: {health?.ai_loaded ? 'Ready' : 'Not loaded'}</span>
          <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}><span className={`health-dot ${health?.ai_online ? 'online' : 'offline'}`} /> Online AI: {health?.ai_online ? 'Ready' : 'Not configured'}</span>
        </div>
      </div>
    </div>
  );
}

export default App;
