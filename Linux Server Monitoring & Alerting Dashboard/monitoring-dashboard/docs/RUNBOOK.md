# SRE On-Call Runbook — Linux Server Monitoring Stack

> **Version:** 1.0.0 | **Last Updated:** 2026-07  
> **Audience:** On-call SRE engineers  
> **Escalation:** If in doubt, escalate. Don't guess with production.

---

## How to Use This Runbook

When an alert fires, find it below by `alertname`. Each section gives you:
1. **What it means** — concise plain-English explanation
2. **Likely causes** — ordered by frequency
3. **First commands** — exact shell commands to run *immediately*
4. **Remediation steps** — numbered, actionable
5. **Escalation criteria** — when to wake someone else up

> **Principle:** Diagnose first, remediate second. Never blindly restart services under load without understanding the cause.

---

## Table of Contents

- [HighCPUUsage / CriticalCPUUsage](#high-cpu-usage)
- [HighMemoryUsage / WarningMemoryUsage](#high-memory-usage)
- [MemoryOOM](#memory-oom)
- [LowDiskSpace / DiskSpaceWarning](#low-disk-space)
- [DiskIOSaturation](#disk-io-saturation)
- [DiskWillFillIn24h](#disk-will-fill-in-24h)
- [HostDown](#host-down)
- [HighNetworkErrors](#high-network-errors)
- [HighNetworkPacketLoss](#high-network-packet-loss)
- [ServiceEndpointDown](#service-endpoint-down)
- [ServiceSlowResponse](#service-slow-response)
- [HighSystemLoad](#high-system-load)
- [Silencing Alerts](#silencing-alerts)
- [Common Prometheus Queries](#common-prometheus-queries)

---

## High CPU Usage

**Alert names:** `HighCPUUsage` (>85% for 5m), `CriticalCPUUsage` (>95% for 2m)  
**Severity:** Warning / Critical

### What it means
CPU utilization has been sustained above the threshold for the `for` duration, ruling out transient spikes from batch jobs or cron.

### Likely causes (ordered by frequency)
1. Runaway process / memory leak causing GC thrashing
2. Sudden traffic surge (legitimate or malicious)
3. Crypto miner / compromised process
4. Misconfigured cron job firing too frequently
5. Kernel-level issue (driver loop, BPF program)

### First commands (run immediately)
```bash
# Top 10 CPU consumers, single snapshot
top -bn1 | head -25

# Real-time CPU view by process
htop   # or: top

# CPU-hungry processes sorted
ps aux --sort=-%cpu | head -20

# System call hotspots (requires root)
perf top -s pid,comm

# Check if it's a cron job
systemctl list-timers --all
grep -r 'your-pattern' /etc/cron* /var/spool/cron/ 2>/dev/null
```

### Remediation steps
1. **Identify the process:** `ps aux --sort=-%cpu | head -5`
2. **Is it expected?** Check if a known batch job / backup is running:
   ```bash
   ls -la /proc/<PID>/exe    # what binary
   cat /proc/<PID>/cmdline | tr '\0' ' '  # full command line
   ```
3. **If it's a legitimate spike** (deploy, backup): monitor and wait. Consider increasing instance size if recurring.
4. **If it's a runaway process:**
   ```bash
   kill -15 <PID>    # polite SIGTERM first
   # wait 10s, then:
   kill -9 <PID>     # SIGKILL if still running
   ```
5. **If it's suspicious (miner/malware):**
   - Take a memory dump before killing: `gcore <PID>`
   - Check network connections: `ss -tunap | grep <PID>`
   - **Escalate to security team immediately**
6. **Verify:** Watch `top` until CPU returns below 70%
7. **Post-incident:** Add process to monitoring, review access logs

### Escalation criteria
- CPU stays above 90% for 15+ minutes despite remediation
- Unknown/suspicious process identified
- Multiple hosts affected simultaneously

---

## High Memory Usage

**Alert names:** `WarningMemoryUsage` (>80% for 10m), `HighMemoryUsage` (>90% for 5m)  
**Severity:** Warning / Critical

### What it means
Available memory (RAM + swappable) is critically low. The system may start swapping heavily, dramatically degrading performance.

### Likely causes
1. Memory leak in application (most common)
2. Java heap too large / GC not running
3. Traffic spike causing more application instances
4. Cache not being evicted (Redis maxmemory not set)
5. Kernel memory leak (rare)

### First commands
```bash
# Summary
free -h

# Per-process memory consumption
ps aux --sort=-%mem | head -20

# Detailed memory breakdown
cat /proc/meminfo

# Which processes are using swap
for pid in /proc/[0-9]*; do
  proc=$(cat "${pid}/comm" 2>/dev/null)
  swap=$(awk '/VmSwap/{print $2}' "${pid}/status" 2>/dev/null)
  [[ -n "$swap" && "$swap" -gt 1000 ]] && echo "${swap}kB  ${proc}  ${pid##*/}"
done | sort -rn | head -10

# Check for OOM events
dmesg | grep -i oom | tail -20
journalctl -k | grep -i oom | tail -20
```

### Remediation steps
1. **Identify top consumers:** `ps aux --sort=-%mem | head -10`
2. **Check application-specific heap/cache settings**
3. **If swap is available and being used**, the system is already degraded — act quickly
4. **Clear page cache (safe, kernel will reclaim as needed):**
   ```bash
   sync && echo 1 > /proc/sys/vm/drop_caches   # free page cache only
   ```
5. **Restart the leaking service** (after notifying users if prod-facing):
   ```bash
   systemctl restart <service-name>
   ```
6. **Emergency: if system is unresponsive**, kill the biggest memory consumer:
   ```bash
   # Find and kill process using most memory
   kill -9 $(ps -eo pid,pmem --sort=-pmem | awk 'NR==2{print $1}')
   ```
7. **Temporary fix:** Add swap space if none exists:
   ```bash
   fallocate -l 4G /swapfile && chmod 600 /swapfile
   mkswap /swapfile && swapon /swapfile
   ```

### Escalation criteria
- OOM killer has fired (see [MemoryOOM](#memory-oom))
- Memory above 95% and not recovering
- Database process is the consumer (risk of data corruption)

---

## Memory OOM

**Alert name:** `MemoryOOM`  
**Severity:** Critical

### What it means
The Linux OOM (Out-of-Memory) killer has forcibly terminated one or more processes to prevent the kernel from running out of memory. **This is a serious event — a process has been killed.**

### First commands
```bash
# Find what was killed and when
dmesg | grep -A5 -i "oom killer"
journalctl -k --since "1 hour ago" | grep -i oom

# Check current memory state
free -h
vmstat -s
```

### Remediation steps
1. **Identify the killed process** from `dmesg` output
2. **Assess impact:** Is a critical service now down?
3. **Restart killed services** if necessary: `systemctl restart <service>`
4. **Root-cause:** Is this a recurring leak? Check memory trends in Grafana (last 24h)
5. **Immediate fix:** Reduce memory allocation for the offending app, add swap, or scale up
6. **Long-term:** Implement memory limits (cgroups / container limits), set OOM priority via `oom_score_adj`

### Escalation criteria
- Database process was killed (potential data corruption)
- OOM has fired more than twice in an hour

---

## Low Disk Space

**Alert names:** `DiskSpaceWarning` (<20%), `LowDiskSpace` (<10%)  
**Severity:** Warning / Critical

### What it means
A filesystem is running low on space. At 0%, the OS cannot write logs, temp files, or application data — services will crash.

### Likely causes
1. Log files not being rotated (most common)
2. Application generating large temp files / coredumps
3. Database growing without archive/prune jobs
4. Docker images/volumes accumulating
5. Legitimate data growth without capacity planning

### First commands
```bash
# Filesystem overview
df -h

# Find largest directories (top-down)
du -sh /* 2>/dev/null | sort -rh | head -20
du -sh /var/* 2>/dev/null | sort -rh | head -10
du -sh /var/log/* 2>/dev/null | sort -rh | head -10

# Largest individual files
find / -xdev -type f -size +100M 2>/dev/null | xargs ls -lh | sort -k5 -rh | head -20

# Open file descriptors pointing to deleted files (consuming space)
lsof +L1 | grep deleted | awk '{print $7, $9}' | sort -rh | head -10

# Docker space usage
docker system df 2>/dev/null
```

### Remediation steps
1. **Emergency: free space immediately**
   ```bash
   # Clear old journal logs
   journalctl --vacuum-time=7d

   # Truncate largest log file (safe — check it's not active data)
   > /var/log/some-large.log

   # Remove old rotated logs
   find /var/log -name "*.gz" -mtime +30 -delete
   find /var/log -name "*.1" -mtime +7 -delete

   # Docker cleanup
   docker system prune -f
   docker image prune -af
   ```
2. **For coredumps:**
   ```bash
   find /var/crash /tmp /var/core -name "core*" -mtime +1 -delete
   ```
3. **Recover space from deleted-but-open files:**
   ```bash
   lsof +L1 | grep deleted
   # Restart the process holding the file descriptor, or:
   # (advanced) truncate via /proc/PID/fd/FD
   ```
4. **Set up log rotation** if not configured — see `/etc/logrotate.d/`
5. **Long-term:** Add disk capacity, archive old data to S3/object storage, implement monitoring of growth rate

### Escalation criteria
- Disk is at <5% and services are failing
- Root filesystem affected (not just `/data`)
- Cannot free enough space with safe operations

---

## Disk IO Saturation

**Alert name:** `DiskIOSaturation`  
**Severity:** Warning

### What it means
A disk device is spending more than 80% of its time doing I/O (utilization), meaning requests are queuing up and latency is increasing.

### First commands
```bash
# Real-time I/O stats
iostat -x 1 5

# Which processes are doing the I/O
iotop -ao   # (install with: apt install iotop)

# Check I/O wait (shows as wa% in top)
top -bn3 | grep Cpu

# Per-process I/O from /proc
for pid in /proc/[0-9]*/io; do
  rchar=$(awk '/^rchar/{print $2}' "$pid" 2>/dev/null)
  proc=$(cat "$(dirname $pid)/comm" 2>/dev/null)
  echo "$rchar $proc"
done | sort -rn | head -10
```

### Remediation steps
1. Identify which process is generating the I/O with `iotop`
2. If it's a batch job: throttle it with `ionice -c 3 -p <PID>`
3. If it's a database: check for missing indexes, runaway queries
4. If it's log writes: check for excessive debug logging
5. Consider moving the workload to a faster disk or adding caching

---

## Disk Will Fill in 24h

**Alert name:** `DiskWillFillIn24h`  
**Severity:** Warning

### What it means
Prometheus's `predict_linear` function has calculated that, at the current write rate, the filesystem will run out of space within 24 hours.

### Remediation steps
1. Follow the **Low Disk Space** runbook above to identify what's growing
2. Act proactively before the critical threshold is breached
3. Check if a backup/export job kicked off and will finish soon
4. If legitimate growth: provision more storage or trigger an archive job

---

## Host Down

**Alert name:** `HostDown`  
**Severity:** Critical

### What it means
Prometheus cannot reach the scrape target. The exporter process may be down, the host may be unreachable, or there's a network issue.

### First commands
```bash
# From the monitoring host, try to reach the affected host
ping -c 4 <instance-ip>
curl -v http://<instance-ip>:9100/metrics
nc -zv <instance-ip> 9100

# Check if it's in the load balancer / service mesh
# (command depends on your infrastructure)
```

### Remediation steps
1. **Network partition?** Try pinging from a different host in the same subnet
2. **Is the host up?** Check cloud console (EC2, GCP, etc.) for instance state
3. **Is the exporter down?**
   ```bash
   ssh <host> "systemctl status node_exporter"
   ssh <host> "systemctl restart node_exporter"
   ```
4. **Firewall issue?**
   ```bash
   ssh <host> "iptables -L -n | grep 9100"
   ```
5. **Full host failure:** Follow your DR procedure, failover traffic if applicable

### Escalation criteria
- Host is completely unreachable via multiple methods
- Multiple hosts down simultaneously (potential network/infrastructure issue)
- Production service is affected

---

## High Network Errors

**Alert name:** `HighNetworkErrors`  
**Severity:** Warning

### What it means
A network interface is experiencing elevated error rates (CRC errors, frame errors, FIFO overflows). This usually indicates hardware problems or congestion.

### First commands
```bash
# Detailed interface stats including errors
ip -s link show eth0
ethtool -S eth0 2>/dev/null | grep -i error

# Watch error counters in real time
watch -n1 'ip -s link'

# Check for network-related kernel messages
dmesg | grep -i "eth0\|nic\|network\|link\|carrier" | tail -20

# Check cable / autoneg
ethtool eth0 | grep -E "Speed|Duplex|Link"
```

### Remediation steps
1. **CRC errors / physical layer:** Replace cable, check switch port, try different port
2. **Duplex mismatch:** Force full-duplex: `ethtool -s eth0 duplex full speed 1000`
3. **Buffer overflows (FIFO):** Increase ring buffer: `ethtool -G eth0 rx 4096 tx 4096`
4. **Driver issues:** Update NIC driver, check `dmesg` for driver errors
5. **If using virtual NIC:** Check hypervisor / VirtIO driver version

---

## High Network Packet Loss

**Alert name:** `HighNetworkPacketLoss`  
**Severity:** Warning

### First commands
```bash
# Confirm packet loss
ping -c 100 -i 0.1 <gateway-ip> | tail -5

# Check if drops are at NIC level
cat /proc/net/dev

# Check socket buffers
ss -s
```

### Remediation steps
1. Increase kernel network buffers:
   ```bash
   sysctl -w net.core.rmem_max=16777216
   sysctl -w net.core.wmem_max=16777216
   ```
2. Check for UDP socket drops: `netstat -su`
3. Investigate if a DoS/flood is causing the drops

---

## Service Endpoint Down

**Alert name:** `ServiceEndpointDown`  
**Severity:** Critical

### What it means
The custom Python health-check exporter has been unable to successfully reach a configured HTTP endpoint or TCP port for 2+ minutes.

### First commands
```bash
# Manually test the endpoint
curl -v <target_url>

# Check if port is open
nc -zv <host> <port>

# Check from inside the monitoring container
docker exec health_check_exporter curl -v <target_url>

# Review health check exporter logs
docker logs health_check_exporter --tail=50
```

### Remediation steps
1. **Is the target service actually down?** Confirm with `curl`
2. **DNS resolution issue?** Try with IP address instead of hostname
3. **SSL cert expired?** `echo | openssl s_client -connect host:443 2>/dev/null | openssl x509 -noout -dates`
4. **Restart the target service** if confirmed down
5. **Update the health check config** if the endpoint URL changed

---

## Service Slow Response

**Alert name:** `ServiceSlowResponse`  
**Severity:** Warning

### What it means
A monitored HTTP endpoint is responding, but latency exceeds the 3-second threshold.

### First commands
```bash
# Measure response time
time curl -o /dev/null -s -w "%{http_code} %{time_total}s\n" <target_url>

# Trace the full request
curl -w "\n\nDNS: %{time_namelookup}s\nConnect: %{time_connect}s\nTTFB: %{time_starttransfer}s\nTotal: %{time_total}s\n" <target_url>
```

### Remediation steps
1. Check if the service is CPU/memory constrained (see CPU/Memory runbooks above)
2. Check database query times
3. Check for network latency between the health checker and the service
4. Review application logs for slow query warnings

---

## High System Load

**Alert name:** `HighSystemLoad`  
**Severity:** Warning

### What it means
The 15-minute load average, normalized per CPU core, exceeds 1.5 — meaning CPUs are over-subscribed and processes are waiting for CPU time.

### First commands
```bash
uptime
vmstat 1 10   # look at r (running) and b (blocked) columns
ps aux --sort=-%cpu | head -20
```

### Remediation steps
1. If `r` column (runnable) is high in `vmstat`: follow [High CPU Usage](#high-cpu-usage) runbook
2. If `b` column (blocked on I/O) is high: follow [Disk IO Saturation](#disk-io-saturation) runbook
3. If neither: check for lock contention, zombie processes

---

## Silencing Alerts

To temporarily silence an alert (e.g., during planned maintenance):

**Via Alertmanager UI:**
1. Go to `http://localhost:9093`
2. Click "Silences" → "New Silence"
3. Set matchers (e.g., `alertname="HighCPUUsage"`, `instance="web01"`)
4. Set duration and add a comment with your name and ticket number

**Via CLI:**
```bash
# Create a 2-hour silence for a specific instance
curl -X POST http://localhost:9093/api/v2/silences \
  -H 'Content-Type: application/json' \
  -d '{
    "matchers": [{"name": "instance", "value": "web01", "isRegex": false}],
    "startsAt": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
    "endsAt": "'$(date -u -d '+2 hours' +%Y-%m-%dT%H:%M:%SZ)'",
    "comment": "Planned maintenance — Ticket #1234",
    "createdBy": "your-name"
  }'
```

---

## Common Prometheus Queries

Paste these directly into the Prometheus UI (`http://localhost:9090/graph`):

```promql
# Current CPU usage %
(1 - avg(rate(node_cpu_seconds_total{mode="idle"}[2m]))) * 100

# Memory usage %
(1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100

# Disk free % for all non-tmpfs filesystems
(node_filesystem_avail_bytes{fstype!~"tmpfs|overlay"} / node_filesystem_size_bytes{fstype!~"tmpfs|overlay"}) * 100

# Network receive rate (bytes/sec)
rate(node_network_receive_bytes_total[5m])

# Top 5 CPU processes (requires node_exporter process collector)
topk(5, rate(namedprocess_namegroup_cpu_seconds_total[5m]))

# All currently firing alerts
ALERTS{alertstate="firing"}

# Targets that are down
up == 0

# Predict when / disk will fill (seconds from now)
predict_linear(node_filesystem_avail_bytes{mountpoint="/"}[6h], 0)
```
