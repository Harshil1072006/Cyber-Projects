# 🖥️ Linux Server Monitoring & Alerting Dashboard

> A production-grade, self-hosted monitoring stack for SRE portfolios — 
> real-time visibility into CPU, memory, disk, and network with automated alerting.

[![Stack](https://img.shields.io/badge/Stack-Prometheus%20%7C%20Grafana%20%7C%20Node%20Exporter-orange)](https://prometheus.io)
[![License](https://img.shields.io/badge/License-MIT-blue)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker)](https://docs.docker.com/compose/)

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│                      Linux Monitoring Stack                              │
│                                                                          │
│  ┌──────────────┐   scrape    ┌──────────────────────────────────────┐  │
│  │              │◄────────────│  node_exporter (:9100)               │  │
│  │  Prometheus  │             │  CPU · Memory · Disk · Network       │  │
│  │  (:9090)     │   scrape    ├──────────────────────────────────────┤  │
│  │              │◄────────────│  health_check_exporter (:9200)       │  │
│  │  TSDB 30d    │             │  HTTP · TCP · systemd probes         │  │
│  │              │             └──────────────────────────────────────┘  │
│  │              │  alert fire                                            │
│  │              │────────────►  Alertmanager (:9093)                    │
│  └──────┬───────┘             │  Route · Group · Inhibit               │  │
│         │ query               │  Slack ✦ Email ✦ Webhook               │  │
│         ▼                     └──────────────────────────────────────┘  │
│  ┌──────────────┐                                                        │
│  │   Grafana    │  Auto-provisioned dashboards (no clicking required)   │
│  │   (:3000)    │  CPU · Memory · Disk · Network · Service Health       │
│  └──────────────┘                                                        │
│                                                                          │
│  Bash Scripts (host):  disk_alert.sh · service_watchdog.sh · setup.sh  │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Features

| Category | What's included |
|----------|----------------|
| **Metrics** | CPU (per-mode), RAM, swap, disk I/O, filesystem usage, network bytes/errors/drops |
| **Alerting** | 13 alert rules across 6 groups; proper `for` durations to prevent flapping |
| **Routing** | Critical → Slack + Email; Warning → Slack; inhibition to suppress alert storms |
| **Visualization** | 20+ Grafana panels, auto-provisioned, color-coded to match alert thresholds |
| **Synthetic checks** | Python exporter: HTTP health probes, TCP port checks, systemd service checks |
| **Automation** | One-command setup, log rotation, service watchdog with auto-restart |
| **Documentation** | Real SRE runbook, architecture doc, design decisions |
| **Retention** | 30-day TSDB retention, persistent Docker volumes |

---

## Quickstart

### Prerequisites

- Linux host (Ubuntu 22.04+ recommended) or macOS with Docker Desktop
- Docker Engine 24+
- docker compose v2 (`docker compose version`)
- 2GB+ free RAM, 10GB+ disk

### 1. Clone and configure

```bash
git clone https://github.com/your-username/monitoring-dashboard.git
cd monitoring-dashboard

# Copy and edit environment variables
cp .env.example .env
nano .env   # Set your Slack webhook URL, SMTP credentials, Grafana password
```

### 2. Launch the stack

```bash
# One command — pulls images, builds Python exporter, starts all services
docker compose up -d

# Watch startup logs
docker compose logs -f
```

### 3. Verify everything is up

```bash
# All containers should be "healthy" within ~60 seconds
docker compose ps

# Quick endpoint check
curl -s http://localhost:9090/-/ready    # Prometheus
curl -s http://localhost:9100/metrics | head -5  # Node Exporter
curl -s http://localhost:9200/metrics | head -5  # Health Check
curl -s http://localhost:9093/-/ready   # Alertmanager
curl -s http://localhost:3000/api/health  # Grafana
```

### 4. Access the dashboards

| Service | URL | Default credentials |
|---------|-----|---------------------|
| **Grafana** | http://localhost:3000 | admin / (see `.env`) |
| **Prometheus** | http://localhost:9090 | — |
| **Alertmanager** | http://localhost:9093 | — |
| Node Exporter metrics | http://localhost:9100/metrics | — |
| Health check metrics | http://localhost:9200/metrics | — |

The **Linux Server — System Overview** dashboard appears automatically in  
Grafana under **SRE Dashboards** folder.

### 5. Test an alert (optional)

```bash
# Trigger a CPU load to test the HighCPUUsage alert path
# Requires: apt install stress-ng
stress-ng --cpu $(nproc) --timeout 360s &

# Watch Prometheus alerts: http://localhost:9090/alerts
# After 5 minutes, the alert fires → Alertmanager routes it → Slack/Email

# Stop the load test
kill %1
```

---

## Configuration

### Environment Variables (`.env`)

```bash
# Grafana
GF_ADMIN_USER=admin
GF_ADMIN_PASSWORD=your-secure-password   # auto-generated by setup.sh

# Slack
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK

# SMTP
SMTP_HOST=smtp.gmail.com:587
SMTP_FROM=alerts@your-domain.com
SMTP_USER=your@gmail.com
SMTP_PASSWORD=your-gmail-app-password
```

### Alertmanager Credentials

Edit `alertmanager/alertmanager.yml` and replace:
- `https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK` with your webhook
- `oncall-team@your-domain.com` with your on-call email
- SMTP credentials with your mail server details

---

## How to Add a New Host

### Step 1: Install Node Exporter on the remote host

```bash
# On the remote Linux host (replace VERSION as needed)
NODE_EXPORTER_VERSION="1.8.0"
wget https://github.com/prometheus/node_exporter/releases/download/v${NODE_EXPORTER_VERSION}/node_exporter-${NODE_EXPORTER_VERSION}.linux-amd64.tar.gz
tar xzf node_exporter-${NODE_EXPORTER_VERSION}.linux-amd64.tar.gz
sudo mv node_exporter-${NODE_EXPORTER_VERSION}.linux-amd64/node_exporter /usr/local/bin/

# Create systemd service
sudo tee /etc/systemd/system/node_exporter.service > /dev/null <<EOF
[Unit]
Description=Node Exporter
After=network.target

[Service]
User=nobody
ExecStart=/usr/local/bin/node_exporter
Restart=always

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now node_exporter
```

### Step 2: Open firewall port 9100

```bash
# UFW example
sudo ufw allow from <prometheus-host-ip> to any port 9100

# iptables example
iptables -A INPUT -s <prometheus-host-ip> -p tcp --dport 9100 -j ACCEPT
```

### Step 3: Add target to `prometheus/prometheus.yml`

```yaml
# Add this scrape_config block:
- job_name: "node_exporter_web01"
  scrape_interval: 10s
  static_configs:
    - targets: ["192.168.1.100:9100"]
      labels:
        host_role: "web-server"
        datacenter: "us-east-1"
        hostname: "web01"
```

### Step 4: Hot-reload Prometheus (no restart needed)

```bash
curl -X POST http://localhost:9090/-/reload
```

### Step 5: Verify in Prometheus

Navigate to `http://localhost:9090/targets` — the new host should appear with state `UP`.

---

## How to Add a New Alert Rule

### Step 1: Add your rule to `prometheus/alert_rules.yml`

```yaml
# Add to an existing group or create a new one
- name: my_custom_alerts
  rules:
    - alert: HighConnectionCount
      expr: node_netstat_Tcp_CurrEstab > 10000
      for: 5m
      labels:
        severity: warning
        team: sre
      annotations:
        summary: "High TCP connection count on {{ $labels.instance }}"
        description: >
          {{ $labels.instance }} has {{ $value }} established TCP connections.
          Check with: `ss -s` and `netstat -an | wc -l`
```

### Step 2: Validate the rule

```bash
# Check YAML syntax
python3 -c "import yaml; yaml.safe_load(open('prometheus/alert_rules.yml'))"

# Validate PromQL expression
curl -s "http://localhost:9090/api/v1/query" \
  --data-urlencode 'query=node_netstat_Tcp_CurrEstab > 10000' | jq .status
```

### Step 3: Hot-reload

```bash
curl -X POST http://localhost:9090/-/reload
```

### Step 4: Add a Runbook entry

Edit `docs/RUNBOOK.md` and add a section describing:
- What the alert means
- Likely causes
- First diagnostic commands
- Remediation steps

---

## How to Add a New Health Check

Edit `scripts/checks_config.yml` and add an entry:

```yaml
# HTTP check
- name: "my-web-app"
  type: http
  url: "https://myapp.example.com/health"
  expected_status: 200
  expected_body: '"status":"healthy"'
  timeout: 10

# TCP port check
- name: "redis"
  type: tcp
  host: "redis.internal"
  port: 6379
  timeout: 3
```

The exporter hot-reloads config every `CHECK_INTERVAL` seconds — no restart needed.

---

## Operations

### Common Commands

```bash
# Restart the full stack
docker compose restart

# Restart a single service
docker compose restart prometheus

# View live logs
docker compose logs -f grafana

# Stop the stack (data preserved in volumes)
docker compose down

# Wipe everything including data
docker compose down -v

# Hot-reload Prometheus config
curl -X POST http://localhost:9090/-/reload

# Force Grafana to re-provision dashboards
docker compose restart grafana

# Run disk check manually
./scripts/disk_alert.sh --threshold 80

# Run service watchdog manually
./scripts/service_watchdog.sh nginx postgresql
```

### Log Locations

| Component | Logs |
|-----------|------|
| Prometheus | `docker compose logs prometheus` |
| Grafana | `docker compose logs grafana` |
| Health Check | `docker compose logs health_check_exporter` |
| Disk alert | `/var/log/monitoring/disk_alert.log` |
| Watchdog | `/var/log/monitoring/service_watchdog.log` |

---

## Design Decisions & Tradeoffs

### Why Prometheus (pull model) vs. push-based (InfluxDB, Datadog)?

**Pull model advantages:**
- The monitoring server controls scrape intervals — it can't be overwhelmed by a misbehaving agent
- Target discovery is centralized (Prometheus knows what it's monitoring)
- Failed scrapes are immediately visible as `up=0`
- Easier to test: you can `curl` any exporter directly to see what it will report

**Pull model tradebacks:**
- Short-lived jobs (batch processes, cron) can't be scraped reliably — use Pushgateway for those
- Requires network access *from* Prometheus *to* exporters — firewall rules must allow this direction
- Not ideal for highly dynamic environments (use service discovery + consul/k8s SD)

### Why these specific thresholds (85% CPU, 90% memory, 10% disk)?

These aren't arbitrary — they're derived from operational experience:

- **CPU 85%**: At this level, the system still has headroom for spikes. 100% CPU means request queuing begins; 85% gives a 5-minute window to react before degradation.
- **CPU 95%** (critical): Saturation point — request timeouts become likely within minutes.
- **Memory 90%**: Below this, Linux's page reclaim is effective. Above it, swapping begins, causing 10–100x latency increases.
- **Disk 10%**: The Linux `ext4` filesystem reserves 5% for root by default. At <10%, applications start failing to write. The `20%` warning gives time for a planned response.
- **Network errors >10/s**: A small number of errors are normal on busy interfaces (driver, transient); 10/s sustained indicates a real problem.
- **"for" durations**: Chosen to filter transient spikes. CPU spikes during a deploy (5m), disk fills slowly (10m), but a host being down for 1 minute is always serious.

### Why Docker Compose and not Kubernetes?

For a single-node monitoring stack:
- Docker Compose has zero overhead vs. a full k8s cluster
- Easier to reproduce on any Linux host or laptop
- Simpler troubleshooting (no CNI, no etcd, no API server)
- Kubernetes is appropriate when you need to monitor a k8s cluster (use kube-prometheus-stack instead)

### Why a custom Python exporter instead of Blackbox Exporter?

The [Blackbox Exporter](https://github.com/prometheus/blackbox_exporter) is the standard tool for HTTP/TCP probing. The custom Python exporter here serves a different purpose:
- Demonstrates Python + Prometheus client library integration for portfolio
- Easier to extend with custom business logic (e.g., check a database query result, verify an API contract)
- Blackbox Exporter is the production recommendation — use it when you don't need custom logic

### Why 30-day TSDB retention?

- Covers typical SLA review cycles (monthly)
- At ~2-byte/sample compression, 30 days of 15-second scrapes for 1000 metrics ≈ ~2GB — manageable
- For longer retention (1 year+), add Thanos or Cortex as a long-term storage backend

---

## Project Structure

```
monitoring-dashboard/
├── docker-compose.yml              # Orchestrates all services
├── .env                            # Secrets & configurable values (git-ignored)
├── prometheus/
│   ├── prometheus.yml              # Scrape configs + alertmanager endpoint
│   └── alert_rules.yml             # 13 alert rules across 6 rule groups
├── alertmanager/
│   └── alertmanager.yml            # Routing tree, receivers, inhibition rules
├── grafana/
│   ├── provisioning/
│   │   ├── datasources/
│   │   │   └── prometheus.yml      # Auto-provision Prometheus datasource
│   │   └── dashboards/
│   │       └── dashboards.yml      # Dashboard folder provisioner
│   └── dashboards/
│       └── system-overview.json    # 20-panel system overview dashboard
├── scripts/
│   ├── health_check.py             # Custom Prometheus exporter (HTTP/TCP/systemd)
│   ├── checks_config.yml           # Targets for health_check.py
│   ├── Dockerfile.healthcheck      # Container image for health_check.py
│   ├── requirements.txt            # Python dependencies
│   ├── disk_alert.sh               # Disk threshold checker (cron-safe)
│   ├── service_watchdog.sh         # Systemd service monitor + auto-restarter
│   └── setup.sh                    # One-shot bootstrap installer
└── docs/
    ├── ARCHITECTURE.md             # System design with ASCII diagrams
    ├── RUNBOOK.md                  # On-call runbook for every alert
    └── SCREENSHOTS.md              # Dashboard layout docs + alert demo guide
```

---

## Contributing

1. Fork the repo
2. Create a feature branch: `git checkout -b feature/add-mysql-exporter`
3. Test with `docker compose up --build`
4. Submit a PR with a description of what you monitored/fixed

---

## License

MIT — use freely in your own SRE portfolio or production environments.

---

## References

- [Prometheus Documentation](https://prometheus.io/docs/)
- [Node Exporter](https://github.com/prometheus/node_exporter)
- [Alertmanager](https://prometheus.io/docs/alerting/latest/alertmanager/)
- [Grafana Dashboards](https://grafana.com/docs/grafana/latest/dashboards/)
- [Awesome Prometheus Alerts](https://awesome-prometheus-alerts.grep.to/) — community alert rules reference
- [Google SRE Book](https://sre.google/sre-book/monitoring-distributed-systems/) — monitoring philosophy
