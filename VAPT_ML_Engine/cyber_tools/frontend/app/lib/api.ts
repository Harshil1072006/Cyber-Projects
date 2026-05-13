const BASE = 'http://localhost:8001';

export interface ToolControl {
  id: string; label: string; type: string;
  flag?: string; default?: unknown;
  options?: string[]; min?: number; max?: number; placeholder?: string;
}
export interface ToolConfig {
  id: string; name: string; icon: string; description: string;
  category: string; controls: ToolControl[];
}
export interface Finding {
  id: string; type: string; severity: string; title: string;
  description?: string; host?: string; port?: number;
  service?: string; protocol?: string; extra?: Record<string, unknown>;
}
export interface Scan {
  id: string; target: string; tool: string; status: string;
  workflow?: string; command?: string; raw_output?: string;
  created_at: string; completed_at?: string;
  findings?: Finding[]; suggestions?: string[];
}

async function req<T>(path: string, opts?: RequestInit): Promise<T> {
  const r = await fetch(BASE + path, { headers: { 'Content-Type': 'application/json' }, ...opts });
  if (!r.ok) throw new Error(`${r.status} ${await r.text()}`);
  return r.json();
}

export const api = {
  health: () => req<{ status: string }>('/api/health'),
  tools: () => req<Record<string, ToolConfig>>('/api/tools/'),
  scans: () => req<Scan[]>('/api/scans/'),
  scan: (id: string) => req<Scan>(`/api/scans/${id}`),
  launch: (target: string, tool: string, options: Record<string, unknown>) =>
    req<{ scan_id: string; status: string; findings_count: number }>('/api/scans/launch', {
      method: 'POST', body: JSON.stringify({ target, tool, options }),
    }),
  workflow: (target: string, workflow: string) =>
    req<{ workflow: string; scan_ids: string[] }>('/api/scans/workflow', {
      method: 'POST', body: JSON.stringify({ target, workflow }),
    }),
  deleteScan: (id: string) =>
    req<{ deleted: string }>(`/api/scans/${id}`, { method: 'DELETE' }),
};

export function createWs(toolId: string, target: string, options: Record<string, unknown>) {
  const params = encodeURIComponent(JSON.stringify({ target, options }));
  return new WebSocket(`ws://localhost:8001/ws/${toolId}?payload=${params}`);
}
