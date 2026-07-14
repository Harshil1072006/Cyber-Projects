# SRE On-Call Runbook — Log Aggregation Pipeline

> **Version:** 1.0.0 | **Audience:** On-call SRE  
> When an alert fires, find it below by tag name. Each section gives you the
> Kibana query to run *first*, likely causes, and remediation steps.

---

## Table of Contents

- [error-rate-spike](#error-rate-spike)
- [auth-failure (burst)](#auth-failure-burst)
- [5xx-error](#5xx-error)
- [oom-kill](#oom-kill)
- [disk-full](#disk-full)
- [service-crash](#service-crash)
- [database-error](#database-error)
- [ssl-error](#ssl-error)
- [dependency-down](#dependency-down)
- [Kibana Alert Setup](#kibana-alert-setup)

---

## error-rate-spike

**What it means:** The `error_rate_alerter.py` detected either a flat threshold
breach (>20 errors in 5 minutes) or a rate spike (current rate > 3x the 60-minute
baseline). This is the most common alert and usually indicates an upstream failure
or a code deployment issue.

### First Kibana queries (run immediately)

```
# All errors in last 15 minutes
log.level: error AND @timestamp > now-15m

# Errors by service — which service is spiking?
log.level: error | stats count() by service.name

# Top error messages — what's the actual error?
log.level: error | stats count() by log.original.keyword | sort count desc
```

**Filter steps in Kibana:**
1. Open the **Incident Overview** dashboard
2. Set time range to **Last 15 minutes**
3. Look at the **Error Rate by Service** panel for which service is spiking
4. Click the spiking service → **Filter for value**
5. Look at **Top Error Messages** to see the root error

### Likely causes (ordered by frequency)
1. Database connection failure → all requests returning 500
2. Code deploy introduced a bug
3. Upstream dependency (Stripe, Redis, etc.) is down
4. OOM kill restarted a service → initial startup errors
5. Traffic spike overloading an under-provisioned service

### Remediation
1. Identify which service and which error message from Kibana
2. Follow the specific runbook section for that error type (database-error, 5xx-error, etc.)
3. If a deploy is in progress: roll back with `kubectl rollout undo deployment/<svc>` or equivalent
4. If OOM: see [oom-kill](#oom-kill) section
5. Once resolved: verify error rate drops in Kibana **Log Volume Over Time** panel

---

## auth-failure (burst)

**Tags:** `auth-failure`  
**What it means:** Multiple authentication failures detected. Could be a user
forgetting their password (1–2 failures) or a brute-force attack (sustained
failures from a single IP).

### First Kibana queries

```
# Auth failures in last 15 minutes
tags: auth-failure AND @timestamp > now-15m

# Failures by source IP — is one IP responsible?
tags: auth-failure | stats count() by source.ip | sort count desc

# Failures by user/service
tags: auth-failure | stats count() by service.name, user.name
```

### Distinguish between user error vs. attack

| Pattern | Likely cause |
|---------|-------------|
| 1–3 failures from user's own IP, then success | User mistyped password |
| 10+ failures from single external IP | Brute force attempt |
| Failures across many IPs for same username | Credential stuffing |
| Failures targeting many usernames from one IP | Username enumeration |

### Remediation
- **Brute force from single IP:** Block it immediately:
  ```bash
  # On nginx host:
  iptables -A INPUT -s <IP> -j DROP
  # Or via fail2ban:
  fail2ban-client set sshd banip <IP>
  ```
- **Credential stuffing:** Enable rate limiting on auth endpoints if not already active
- **Account locked:** Confirm with user, unlock via admin panel or: `passwd -u <username>`
- **Normal user error:** No action required — monitor for next 10 minutes

---

## 5xx-error

**Tags:** `5xx-error`  
**What it means:** HTTP 500–599 responses are being returned to clients.
The application is failing to handle requests.

### First Kibana queries

```
# All 5xx events
tags: "5xx-error" AND @timestamp > now-15m

# 5xx by status code (500 vs 502 vs 503 tells you a lot)
http.response.status_code: [500 TO 599] | stats count() by http.response.status_code

# Which endpoints are failing?
http.response.status_code: [500 TO 599] | stats count() by url.original | sort count desc
```

### Interpret by status code

| Status | Meaning | First check |
|--------|---------|-------------|
| **500** | App threw an unhandled exception | App logs for stack trace |
| **502** | Nginx can't reach upstream app | Is the app process running? |
| **503** | App is overloaded or circuit breaker open | CPU/memory metrics in Prometheus |
| **504** | Upstream timed out | Database/external service latency |

### Remediation
1. **500**: Find the stack trace: `log.level: error AND service.name: <svc>` → check `log.original`
2. **502/503**: Check if app containers are running: `docker compose ps`
3. **504**: Check database connection times, external API latency
4. If persistent: restart the failing service: `docker compose restart <service>`

---

## oom-kill

**Tags:** `oom-kill`  
**Severity:** Critical  
**What it means:** The Linux OOM (Out-of-Memory) killer has terminated a process.
This is a hard event — a process was forcibly killed. Check if a critical service died.

### First Kibana queries

```
# OOM events — identify what was killed
tags: "oom-kill" AND @timestamp > now-1h

# Service crashes that followed (likely the restarted process)
tags: "service-crash" AND @timestamp > now-1h

# Memory timeline from node_exporter (if Prometheus is running)
# Check Grafana Memory dashboard
```

### Remediation
1. Identify what was killed from the log: look for `killed process <PID>` and `(java|python|node)` in `log.original`
2. Check if the service restarted successfully: look for `Service started` logs after the OOM event
3. **Immediate**: Restart the killed service if it didn't auto-recover:
   ```bash
   docker compose restart <service>
   ```
4. **Short-term**: Increase container memory limit in `docker-compose.yml`:
   ```yaml
   deploy:
     resources:
       limits:
         memory: 2G
   ```
5. **Long-term**: Investigate memory leak. Check Grafana for memory trend over last 24h.
   Profile the JVM/process to find the leak.

---

## disk-full

**Tags:** `disk-full`  
**Severity:** Critical  
**What it means:** A filesystem has run out of space (`ENOSPC`). Writes are failing.
Services will start throwing errors for any operation requiring disk I/O.

### First Kibana queries

```
tags: "disk-full" AND @timestamp > now-1h
```

### Immediate action (before remediation)

```bash
# Find which filesystem is full
df -h

# Find what's consuming space
du -sh /var/* 2>/dev/null | sort -rh | head -10
du -sh /var/log/* 2>/dev/null | sort -rh | head -10

# Quick space recovery:
journalctl --vacuum-time=7d
find /var/log -name "*.gz" -mtime +7 -delete
docker system prune -f
```

### Root cause investigation

```bash
# Check Logstash dead-letter queue (likely growing if ES was unavailable)
du -sh /var/lib/docker/volumes/log-pipeline_logstash_data/

# Large Elasticsearch segments (if ES data volume fills up)
du -sh /var/lib/docker/volumes/log-pipeline_elasticsearch_data/
```

---

## service-crash

**Tags:** `service-crash`  
**Severity:** Critical  
**What it means:** A segfault, panic, or unexpected exit was detected.
The service may be unavailable.

### First Kibana queries

```
tags: "service-crash" AND @timestamp > now-1h

# See what service crashed and when
tags: "service-crash" | stats min(@timestamp), max(@timestamp) by service.name
```

### Remediation
1. Identify the crashed service from `service.name` in Kibana
2. Restart it: `docker compose restart <service>`
3. Collect the core dump if available: `find /var/crash -name "core*" -mtime -1`
4. Check if crash is recurring (same crash 3+ times = needs a code fix, not a restart)
5. Look at the preceding log lines for the root cause: filter by `service.name` and `@timestamp` just before the crash event

---

## database-error

**Tags:** `database-error`  
**What it means:** Database connectivity or query issues: connection refused,
too many connections, deadlock, query timeout.

### First Kibana queries

```
tags: "database-error" AND @timestamp > now-30m

# Specific DB error types
tags: "database-error" | stats count() by log.original.keyword | sort count desc
```

### Remediation by error type

| Error | Likely cause | First action |
|-------|-------------|-------------|
| `too many connections` | Connection pool exhausted | Reduce pool size or scale DB |
| `connection refused` | DB process down | Check: `systemctl status postgresql` |
| `deadlock detected` | App-level locking issue | Check slow queries, add retry logic |
| `query timeout` | Missing index or table lock | Run `EXPLAIN ANALYZE` on slow query |

---

## ssl-error

**Tags:** `ssl-error`  
**What it means:** SSL/TLS certificate problem — expired, self-signed, hostname mismatch.

### First Kibana queries

```
tags: "ssl-error" AND @timestamp > now-1h

# Which service/endpoint has the cert issue?
tags: "ssl-error" | stats count() by service.name, url.original
```

### Quick certificate check

```bash
# Check certificate expiry for a domain
echo | openssl s_client -connect <domain>:443 2>/dev/null | openssl x509 -noout -dates

# Check cert chain
openssl s_client -connect <domain>:443 -showcerts 2>/dev/null | head -50
```

### Remediation
- **Expired cert**: Renew with Let's Encrypt: `certbot renew`
- **Self-signed in chain**: Replace with a properly signed certificate
- **Hostname mismatch**: Check that the cert's CN/SAN matches the hostname you're connecting to

---

## dependency-down

**Tags:** `dependency-down`  
**What it means:** An upstream service or dependency is unreachable (external API,
internal microservice, Redis, message queue).

### First Kibana queries

```
tags: "dependency-down" AND @timestamp > now-30m

# Which dependency is failing?
tags: "dependency-down" | stats count() by service.name, log.original.keyword
```

### Remediation
1. Identify the dependency from `log.original` (e.g., `could not connect to redis:6379`)
2. Check if the dependency's container is running: `docker compose ps`
3. Restart the dependency: `docker compose restart redis`
4. If it's an external service (Stripe, SendGrid, etc.): check their status page
5. Implement a circuit breaker in your app to fail gracefully

---

## Kibana Alert Setup

The `kibana/alerting/error-rate-spike-rule.json` defines the alert rule spec.
Since Kibana alerting requires runtime connector IDs, follow these steps to activate it:

### Step 1: Create a Slack Connector
1. Kibana → **Stack Management** → **Rules and Connectors** → **Connectors**
2. Click **Create connector** → **Slack**
3. Paste your Slack webhook URL
4. Name it `slack-oncall` → Save

### Step 2: Create the Alert Rule
1. Click **Create rule** → type: **Elasticsearch query**
2. Index: `logs-*`, Time field: `@timestamp`
3. Query:
   ```json
   { "query": { "bool": { "filter": [
     { "terms": { "log.level": ["error", "critical", "fatal"] } }
   ] } } }
   ```
4. Threshold: `> 20` per 5-minute window
5. Add action: Slack connector → message:
   ```
   :fire: Error spike on {{ context.date }}: {{ context.value }} errors in 5m
   See Kibana: http://localhost:5601
   RUNBOOK.md#error-rate-spike
   ```
6. Enable the rule

The Python `error_rate_alerter.py` runs independently of Kibana alerting and
provides the same capability without a license requirement.
