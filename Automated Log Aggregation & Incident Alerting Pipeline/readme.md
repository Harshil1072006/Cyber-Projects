# 📋 Automated Log Aggregation & Incident Alerting Pipeline

> 🤖 **Note:** This project and its documentation were generated with the assistance of AI.

> Centralize logs from multiple Linux hosts into an ELK stack with automated
> incident tagging, searchable Kibana dashboards, and error-rate spike alerting.

[![Stack](https://img.shields.io/badge/Stack-ELK%208.13%20%7C%20Python%20%7C%20Filebeat-005571)](https://elastic.co)
[![License](https://img.shields.io/badge/License-MIT-blue)](LICENSE)

---

## Architecture

```
Linux Hosts → Filebeat → Logstash (parse+tag) → Elasticsearch → Kibana
                                                      ↑
                                          error_rate_alerter.py (Python)
                                          → Slack / stdout alerts
```

```
[app-server-1]──┐
[app-server-2]──┼──[Filebeat × 3]──[Logstash]──[Elasticsearch]──[Kibana]
[nginx-proxy-1]─┘    Beats:5044      4-stage       logs-{svc}-     Incident
                                     pipeline       {YYYY.MM.dd}    Overview
                                     ↓                              Dashboard
                               [01] beats input
                               [02] syslog / app / nginx grok
                               [03] incident tagging (11 tags)
                               [04] ES output (ECS v8)
```

---

## Features

| Category | What's included |
|----------|-----------------|
| **Ingestion** | 3 Filebeat agents simulating multi-host, host metadata preserved |
| **Parsing** | Syslog grok, ISO8601 app logs, Nginx combined, JSON structured logs |
| **Normalization** | ECS v8 fields: `@timestamp`, `log.level`, `service.name`, `host.name` |
| **Tagging** | 11 semantic tags: `auth-failure`, `5xx-error`, `oom-kill`, `disk-full`, `service-crash`, `database-error`, `ssl-error`, `rate-limited`, `slow-query`, `deploy-event`, `dependency-down` |
| **Retention** | ILM policy: hot 7d → warm → delete at 30d |
| **Alerting** | Python alerter with flat threshold + spike ratio detection |
| **Dashboards** | Auto-provisioned Kibana dashboard: volume, error rate, host breakdown, top errors |
| **Demo** | `simulate_logs.sh` generates realistic traffic + automatic incident bursts |

---

## Quickstart

### Prerequisites
- Docker Engine 24+ and docker compose v2
- 4GB+ free RAM (ELK is memory-hungry)
- Ports free: 9200, 5601, 5044, 9600

### 1. Clone and start the stack

```powershell
cd "C:\Cyber Project\Automated Log Aggregation & Incident Alerting Pipeline\log-pipeline"

# Optional: configure Slack webhook
Copy-Item .env.example .env
notepad .env

# Start everything
docker compose up -d

# Monitor startup (~90 seconds for Elasticsearch + Kibana)
docker compose ps
```

### 2. Bootstrap Elasticsearch (ILM + index template + Kibana dashboard)

```powershell
# Wait for Elasticsearch to be healthy first:
# GET http://localhost:9200/_cluster/health  → should show "green" or "yellow"

# Then run setup (from Git Bash / WSL on Windows, or Linux):
bash scripts/setup.sh
```

Or manually via PowerShell (Invoke-RestMethod equivalents are in SCREENSHOTS.md).

### 3. Start log simulation

```powershell
# Continuous traffic (baseline INFO + automatic incident bursts every 5 min)
docker exec log-simulator bash /scripts/simulate_logs.sh

# Or trigger an immediate error burst to test alerting:
docker exec log-simulator bash /scripts/simulate_logs.sh --incident-only
```

### 4. Open Kibana

Navigate to **http://localhost:5601**

→ **Dashboards** → **Incident Overview — Log Pipeline**

You should see logs flowing within 30–60 seconds.

### 5. Test the alerter

```powershell
# Single check with low threshold to see an alert fire:
docker exec error-rate-alerter python error_rate_alerter.py --once --threshold 5 --multiplier 1.0 --dry-run
```

---

## How to Onboard a New Log Source

### Step 1: Install Filebeat on the new host

```bash
# Download and install Filebeat on the remote Linux host
curl -L -O https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-8.13.4-linux-x86_64.tar.gz
tar xzf filebeat-8.13.4-linux-x86_64.tar.gz
cd filebeat-8.13.4-linux-x86_64/

# Copy the project's filebeat.yml
cp /path/to/project/filebeat/filebeat.yml .

# Set your host identity
export HOST_NAME="web-server-3"
export SERVICE_NAME="api-gateway"
export ENVIRONMENT="production"

# Point to Logstash (the monitoring host IP)
sed -i 's/logstash:5044/YOUR_LOGSTASH_IP:5044/' filebeat.yml

./filebeat -e -strict.perms=false
```

### Step 2: Open firewall port 5044 on the Logstash host

```bash
# Allow Filebeat traffic from the new host
iptables -A INPUT -s <new-host-ip> -p tcp --dport 5044 -j ACCEPT
```

### Step 3: Add a docker-compose service (if running via Docker)

```yaml
# Add to docker-compose.yml:
filebeat-web3:
  image: docker.elastic.co/beats/filebeat:8.13.4
  user: root
  command: filebeat -e -strict.perms=false
  environment:
    - HOST_NAME=web-server-3
    - SERVICE_NAME=api-gateway
  volumes:
    - ./filebeat/filebeat.yml:/usr/share/filebeat/filebeat.yml:ro
    - /path/to/web3/logs:/var/log/app:ro
  networks:
    - elk
```

Logs from `web-server-3` appear in Kibana under `host.name: web-server-3`.

---

## How to Add a New Parsing Rule

### For a new log format (Logstash grok)

Edit `logstash/pipeline/02-filter-syslog.conf` and add a new `else if` branch:

```ruby
} else if [fields][log_format] == "my-app" {
  grok {
    match => {
      "message" => "%{TIMESTAMP_ISO8601:app_ts} %{LOGLEVEL:level} \[%{DATA:request_id}\] %{GREEDYDATA:app_msg}"
    }
  }
  date {
    match => ["app_ts", "ISO8601"]
    target => "@timestamp"
  }
  mutate {
    rename => { "app_msg" => "[log][original]" }
    lowercase => ["level"]
    rename => { "level" => "[log][level]" }
    add_field => { "[log][format]" => "my-app" }
  }
}
```

Test with: `curl -X POST http://localhost:9600/_node/stats/pipelines`

### For a new incident tag

Edit `logstash/pipeline/03-filter-app-logs.conf` or `scripts/log_tagger.py`:

**In Logstash** (real-time tagging):
```ruby
if [log][original] =~ /(?i)(my-new-error-pattern|another-pattern)/ {
  mutate { add_tag => ["my-new-tag"] }
}
```

**In Python** (batch/pre-processing):
```python
# Add to TAG_RULES in log_tagger.py:
(
    "my-new-tag", "high",
    re.compile(r"(?i)(my-new-error-pattern|another-pattern)"),
),
```

Then add an entry in `docs/RUNBOOK.md` for the new tag.

---

## Design Decisions

### Why ELK vs. managed services (Datadog, Splunk, New Relic)?

| Dimension | ELK (self-hosted) | Datadog / Splunk |
|-----------|------------------|-----------------|
| **Cost** | Free (hardware cost only) | $15–$31/host/month |
| **Data ownership** | 100% — data never leaves your infra | Vendor controls storage |
| **Customization** | Full grok/pipeline control | Limited to vendor DSL |
| **Setup complexity** | High (you manage it) | Low (managed service) |
| **Retention** | ILM policy, any duration | Priced per GB/day |
| **Scale** | Manual clustering | Auto-scaling |

**Portfolio rationale:** ELK demonstrates hands-on understanding of log pipeline internals — parsing, indexing, retention. Datadog expertise is valuable too, but ELK shows you built the thing yourself.

### Why Logstash filtering vs. all-Python parsing?

| Approach | Pros | Cons |
|----------|------|------|
| **Logstash grok** | Declarative, hot-reloadable, built-in codec support, multi-threaded | Ruby DSL learning curve, grok regex can be slow |
| **Python pre-processing** | Full language power, testable, git-friendly | Another process to run, serialization overhead |
| **This project** | Both — Logstash for format parsing, Python for batch/pre-ingest use | Dual complexity |

**Recommendation for production:** Use Logstash for online real-time parsing (fast, stateless). Use Python (`log_normalizer.py` + `log_tagger.py`) for batch re-processing of historical logs and for testing parsing logic before deploying to Logstash.

### Why grok vs. structured JSON logging at the source?

**Grok** is a regex-based pattern language that parses unstructured text.
**JSON logging** means the application emits `{"level":"error","message":"...",...}` directly.

| Approach | When to use |
|----------|-------------|
| **grok parsing** | Legacy apps you can't modify, syslog, nginx, existing log formats |
| **JSON at source** | New services where you control the logging library |

**Best practice:** Migrate new services to structured JSON logging (e.g., Python `structlog`, Java `logstash-logback-encoder`). Grok becomes a compatibility layer for legacy systems.

### Why flat threshold + spike ratio in the alerter?

- **Flat threshold only:** Misses low-volume services. If a service normally has 0 errors, 5 errors = 100% spike — worth alerting even if 5 < 20.
- **Spike ratio only:** Fires on normal services at baseline. If a service normally has 50 errors/5m, a 3x spike (150) may not be a real incident.
- **Both together:** Catches the union of "abnormally high volume" AND "abnormally high spike" — each with a different false-positive profile.

---

## Project Structure

```
log-pipeline/
├── docker-compose.yml              # 7 services, shared elk network
├── elasticsearch/elasticsearch.yml # Single-node, security-off config
├── logstash/
│   ├── logstash.yml                # Pipeline workers, batch size
│   └── pipeline/
│       ├── 01-input.conf           # Beats input on :5044
│       ├── 02-filter-syslog.conf   # Format detection + grok parsing
│       ├── 03-filter-app-logs.conf # JSON, Nginx, tagging, enrichment
│       └── 04-output.conf          # Dynamic index, dead-letter queue
├── filebeat/filebeat.yml           # Two filestream inputs, env-var identity
├── kibana/
│   ├── kibana.yml                  # Kibana config
│   ├── dashboards/incident-overview.ndjson  # Auto-imported dashboard
│   └── alerting/error-rate-spike-rule.json  # Alert rule definition
├── scripts/
│   ├── log_normalizer.py           # 4-format parser → ECS JSON
│   ├── log_tagger.py               # 11 incident tags + severity
│   ├── error_rate_alerter.py       # ES query loop, dual alert logic
│   ├── simulate_logs.sh            # Realistic log generator + incident bursts
│   ├── setup.sh                    # ILM + template + Kibana bootstrap
│   ├── Dockerfile.alerter          # Python alerter container
│   └── requirements.txt
├── sample-logs/
│   ├── app-server-1.log            # Payment service (normal + DB outage + OOM)
│   ├── app-server-2.log            # Auth service (normal + brute-force + SSL error)
│   └── nginx-access.log            # Access log (200s + 5xx incident + 429)
└── docs/
    ├── ARCHITECTURE.md             # Data flow diagram, component table
    ├── RUNBOOK.md                  # Per-tag: KQL query, causes, remediation
    └── SCREENSHOTS.md              # Dashboard layout, test commands, outputs
```
