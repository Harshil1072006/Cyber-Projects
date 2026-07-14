# Screenshots — Linux Server Monitoring Stack

> This file documents the dashboard layout and alert flow for the portfolio.  
> Run `docker compose up -d` and navigate to `http://localhost:3000` to see live dashboards.

---

## Dashboard Overview

### System Overview — Grafana Dashboard

The auto-provisioned `Linux Server — System Overview` dashboard appears in the  
**SRE Dashboards** folder immediately on first launch.

**Panel layout:**

```
Row 1: 📊 System Overview
┌──────────┬──────────┬──────────┬──────────┬──────────┬──────────┬──────────┬──────────┐
│Prometheus│   Node   │  Alert-  │Health Chk│  CPU %   │  Mem %   │ Disk Free│ Load/CPU │
│  UP/DOWN │ Exporter │ manager  │  Exp.    │  Stat    │  Stat    │  % Stat  │  Stat    │
└──────────┴──────────┴──────────┴──────────┴──────────┴──────────┴──────────┴──────────┘

Row 2: 🖥️ CPU
┌─────────────────────────────┬────────────────┬────────────────┐
│  CPU Usage by Mode          │   CPU Gauge    │  Load Average  │
│  (timeseries: user/sys/     │  (gauge panel) │  (1m/5m/15m   │
│   iowait/idle)              │  green→red     │  timeseries)   │
└─────────────────────────────┴────────────────┴────────────────┘

Row 3: 💾 Memory
┌─────────────────────────────┬────────────────┬────────────────┐
│  Memory Breakdown           │  Memory Gauge  │  Swap Usage %  │
│  (stacked: used/buf/cache   │  (gauge panel) │  (timeseries)  │
│   /free)                    │  green→red     │                │
└─────────────────────────────┴────────────────┴────────────────┘

Row 4: 💿 Disk
┌─────────────────────────────┬────────────────────────────────┐
│  Disk I/O Read/Write        │  Disk Free % by Mountpoint     │
│  (bytes/sec timeseries      │  (horizontal bar gauge         │
│   per device)               │   red<10% / yellow<20% / green)│
└─────────────────────────────┴────────────────────────────────┘

Row 5: 🌐 Network
┌─────────────────────────────┬────────────────────────────────┐
│  Network Throughput (bps)   │  Network Errors & Drops        │
│  (RX/TX per interface)      │  (errors/drops per interface)  │
└─────────────────────────────┴────────────────────────────────┘

Row 6: 🔍 Service Health Checks
┌─────────────────────────────┬────────────────────────────────┐
│  Service Status             │  Service Response Times        │
│  (color-coded UP/DOWN stat  │  (latency timeseries per svc)  │
│   per check target)         │                                │
└─────────────────────────────┴────────────────────────────────┘
```

---

## Alert Firing Demo

To manually trigger a `HighCPUUsage` alert for testing:

```bash
# On the Linux host — generate CPU load for 6 minutes
stress-ng --cpu $(nproc) --timeout 360s

# OR use a simple bash loop
for i in $(seq 1 $(nproc)); do
  yes > /dev/null &
done
# After 5 minutes the alert will fire. Stop with:
kill $(jobs -p)
```

Expected flow:
1. Prometheus detects CPU > 85% → state: **PENDING**
2. After 5 minutes sustained → state: **FIRING**
3. Prometheus sends alert to Alertmanager
4. Alertmanager groups and routes to Slack `#alerts-critical`
5. Grafana CPU panel turns **red**
6. When `kill` is run → alert resolves → Slack receives resolved notification

---

## Alertmanager UI

Navigate to `http://localhost:9093`:

- **Alerts tab**: Shows all currently firing alert groups
- **Silences tab**: Active and expired silences
- **Status tab**: Alertmanager cluster status and config

---

## Prometheus UI

Navigate to `http://localhost:9090`:

- **Graph**: Run ad-hoc PromQL queries
- **Alerts**: See firing/pending alert rules
- **Targets**: See all scrape targets and their health
- **Status → Configuration**: View loaded config
- **Status → Rules**: View loaded alert rules

---

## Adding a Screenshot to This File

If you're adding real screenshots for the portfolio:

1. Take a screenshot of the Grafana dashboard
2. Save to `docs/assets/grafana-overview.png`
3. Add: `![Grafana Dashboard](./assets/grafana-overview.png)`

---

## Service URLs Quick Reference

| Service | URL | Credentials |
|---------|-----|-------------|
| Grafana | http://localhost:3000 | admin / (see .env) |
| Prometheus | http://localhost:9090 | — |
| Alertmanager | http://localhost:9093 | — |
| Node Exporter | http://localhost:9100/metrics | — |
| Health Check | http://localhost:9200/metrics | — |
