# Screenshots — Log Aggregation Pipeline

> Run `docker compose up -d`, wait ~2 minutes, start the simulator, then open Kibana at http://localhost:5601.

---

## Stack Startup Sequence

```
docker compose up -d
# Expected output (abbreviated):
# ✓ elasticsearch  healthy  (after ~60s)
# ✓ logstash       healthy  (after ~30s post-ES)
# ✓ kibana         healthy  (after ~60s post-ES)
# ✓ filebeat-app1  running
# ✓ filebeat-app2  running
# ✓ filebeat-nginx running
# ✓ log-simulator  running
# ✓ alerter        running
```

---

## Kibana Dashboard Layout — Incident Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│  📊 Incident Overview — Log Pipeline          [Last 1 hour] [Auto 30s]  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Log Volume Over Time (stacked bar: INFO/WARN/ERROR)                   │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  ████░░░░░░░░░████░░░░░░░░░████░░░░░░░░░░░░░██████████░░░░░░░  │   │
│  │  INFO          WARN             ERROR spike at 08:14            │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  Error Rate by Service (line)  │  Log Volume by Host (donut)           │
│  ┌──────────────────────────┐  │  ┌──────────────────────────────┐     │
│  │ payment-service  ─────── │  │  │  ●app-server-1  45%         │     │
│  │ auth-service     ──      │  │  │  ●app-server-2  35%         │     │
│  │ nginx            ─       │  │  │  ●nginx-proxy   20%         │     │
│  └──────────────────────────┘  │  └──────────────────────────────┘     │
│                                                                         │
│  Top Error Messages (table)                                             │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ Message                                    Service        Count │   │
│  │ Database connection failed — too many...   payment-service  12  │   │
│  │ Authentication failed — Invalid password   auth-service     8   │   │
│  │ POST /api/v1/payment → 500                 nginx            6   │   │
│  │ Out of memory: Killed process 5678         payment-service  1   │   │
│  └─────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Starting the Log Simulator

```powershell
# Start continuous log generation (Windows Docker Desktop):
docker exec log-simulator bash /scripts/simulate_logs.sh

# In a second terminal, watch logs flow into Elasticsearch:
docker compose logs -f filebeat-app1

# Trigger an immediate incident burst:
docker exec log-simulator bash /scripts/simulate_logs.sh --incident-only
```

---

## Testing the Error Rate Alerter

```powershell
# Single check — see current error count vs baseline:
docker exec error-rate-alerter python error_rate_alerter.py --once

# With dry-run (shows alert text without sending Slack):
docker exec error-rate-alerter python error_rate_alerter.py --once --dry-run

# Lower threshold to trigger alert immediately (for testing):
docker exec error-rate-alerter python error_rate_alerter.py --once --threshold 5 --multiplier 1.0
```

Expected alert output:
```
════════════════════════════════════════════════════════════
Error Rate Alert: Threshold Breach (25 errors > 20 threshold)
Time: 2026-07-13 08:14:30 UTC
Service filter: all services
Window: last 5 minutes
Current error count: 25
Baseline avg (60m): 2.3
Spike ratio: 10.9x

Top services by error count:
  • payment-service: 18 errors
  • auth-service: 5 errors
  • nginx: 2 errors

Top error messages:
  • (12x) Database connection failed — too many connections
  • (8x) Authentication failed — Invalid password
  • (5x) POST /api/v1/payment → 500
════════════════════════════════════════════════════════════
```

---

## Verifying Elasticsearch Index

```powershell
# List all log indices:
Invoke-RestMethod http://localhost:9200/_cat/indices/logs-* -Headers @{"Content-Type"="application/json"} | Format-Table

# Check document count:
Invoke-RestMethod http://localhost:9200/logs-*/_count

# View a sample document:
Invoke-RestMethod "http://localhost:9200/logs-*/_search?size=1&sort=@timestamp:desc"

# Check ILM policy applied:
Invoke-RestMethod http://localhost:9200/_ilm/policy/logs-policy
```

---

## Service URLs Quick Reference

| Service | URL |
|---------|-----|
| Kibana | http://localhost:5601 |
| Elasticsearch | http://localhost:9200 |
| Logstash API | http://localhost:9600 |
| ES cluster health | http://localhost:9200/_cluster/health |
| Logstash pipeline stats | http://localhost:9600/_node/stats/pipelines |
