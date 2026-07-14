# Architecture — Linux Server Monitoring & Alerting Stack

## Overview

This is a self-hosted, pull-based monitoring stack built on the CNCF-standard 
Prometheus ecosystem. It provides real-time visibility, historical metrics retention, 
and automated alerting for Linux hosts.

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         Docker Host (Linux)                             │
│                                                                         │
│   ┌─────────────┐     scrape      ┌──────────────────────────────────┐ │
│   │             │◄────────────────│  node_exporter (:9100)           │ │
│   │             │                 │  CPU / RAM / Disk / Net metrics   │ │
│   │             │                 └──────────────────────────────────┘ │
│   │             │                                                       │
│   │  Prometheus │     scrape      ┌──────────────────────────────────┐ │
│   │  (:9090)    │◄────────────────│  health_check_exporter (:9200)   │ │
│   │             │                 │  Python / synthetic checks        │ │
│   │  TSDB       │                 └──────────────────────────────────┘ │
│   │  (30d)      │                                                       │
│   │             │     scrape      ┌──────────────────────────────────┐ │
│   │             │◄────────────────│  prometheus (self) (:9090)        │ │
│   │             │                 └──────────────────────────────────┘ │
│   │             │                                                       │
│   │             │   alert notify  ┌──────────────────────────────────┐ │
│   │             │────────────────►│  Alertmanager (:9093)            │ │
│   └─────────────┘                 │  Routing / Grouping / Inhibition  │ │
│          │                        └────────────┬─────────────────────┘ │
│          │ query                               │                        │
│          ▼                                     │ notify                 │
│   ┌─────────────┐                             ▼                        │
│   │   Grafana   │                   ┌──────────────────┐               │
│   │   (:3000)   │                   │  Slack / Email / │               │
│   │  Dashboards │                   │  Webhook         │               │
│   └─────────────┘                   └──────────────────┘               │
│                                                                         │
│   ┌─────────────────────────────────────────────────────────────────┐  │
│   │  Bash Scripts (run on host / cron)                              │  │
│   │  disk_alert.sh  │  service_watchdog.sh  │  setup.sh            │  │
│   └─────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Component Details

| Component | Image | Port | Role |
|-----------|-------|------|------|
| Prometheus | `prom/prometheus:v2.51.2` | 9090 | Metrics store, alert evaluation |
| Node Exporter | `prom/node-exporter:v1.8.0` | 9100 | Host OS metrics |
| Health Check Exporter | Custom Python | 9200 | Synthetic/application checks |
| Alertmanager | `prom/alertmanager:v0.27.0` | 9093 | Alert routing & deduplication |
| Grafana | `grafana/grafana:10.4.2` | 3000 | Visualization & dashboards |

---

## Data Flow

### Metrics Collection (Pull Model)

```
Linux Host OS
    │
    ├── /proc, /sys, /
    │       │
    │   node_exporter  ──► :9100/metrics (Prometheus text format)
    │                                │
    │   health_check.py ──► :9200/metrics (custom + synthetic)
    │                                │
    └────────────────────────────────┘
                                     │
                              Prometheus scrapes
                              every 10–30s
                                     │
                                  TSDB
                              (30-day retention)
```

### Alerting Pipeline

```
Prometheus evaluates alert_rules.yml every 15s
    │
    ├── Rule condition true for < "for" duration → PENDING state
    │
    └── Rule condition true for ≥ "for" duration → FIRING state
                │
                ▼
        Alertmanager receives alert
                │
                ├── Groups by: alertname, instance, severity
                ├── Applies inhibition rules (suppress downstream)
                └── Routes based on severity label
                        │
                        ├── critical → Slack #alerts-critical + Email
                        └── warning  → Slack #alerts-warning
```

---

## Storage Architecture

```
prometheus_data (Docker named volume)
    └── /prometheus/
        └── <blocks>/      ← 2-hour TSDB blocks
            ├── chunks/
            ├── index
            └── meta.json
        └── wal/           ← Write-ahead log (crash recovery)

Retention: 30 days configured via --storage.tsdb.retention.time

grafana_data (Docker named volume)
    └── /var/lib/grafana/
        ├── grafana.db     ← SQLite (users, settings)
        └── plugins/
```

---

## Network Architecture

All containers share the `monitoring` bridge network:

```
monitoring (172.20.0.0/16)
    ├── prometheus          (172.20.0.2)
    ├── node_exporter       (172.20.0.3)
    ├── health_check_exporter (172.20.0.4)
    ├── alertmanager        (172.20.0.5)
    └── grafana             (172.20.0.6)
```

Inter-container communication uses container names as DNS hostnames.  
External access via mapped ports on the Docker host.

---

## Security Considerations

- Grafana admin password generated randomly by `setup.sh`
- No authentication on Prometheus/Alertmanager by default (add nginx reverse proxy for production)
- Node Exporter runs with `pid: host` to expose process metrics — do not expose port 9100 externally
- Health check exporter runs as non-root UID 1000
- All config files mounted read-only (`:ro`)
