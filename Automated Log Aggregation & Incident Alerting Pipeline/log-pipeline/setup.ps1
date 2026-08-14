
# setup.ps1 - Windows PowerShell equivalent of setup.sh
# Bootstraps the ELK log pipeline (ILM policy, index template, Kibana data view, dashboard)

$ES     = "http://localhost:9200"
$KIBANA = "http://localhost:5601"
$Headers = @{ "Content-Type" = "application/json" }
$KibanaHeaders = @{ "Content-Type" = "application/json"; "kbn-xsrf" = "true" }

function Write-Step($msg)    { Write-Host "`n>>> $msg" -ForegroundColor Cyan }
function Write-OK($msg)      { Write-Host "    [OK] $msg" -ForegroundColor Green }
function Write-Warn($msg)    { Write-Host "    [WARN] $msg" -ForegroundColor Yellow }

# ── 1. Wait for Elasticsearch ─────────────────────────────────────────────────
Write-Step "Waiting for Elasticsearch at $ES..."
$attempts = 0
while ($true) {
    try {
        $health = Invoke-RestMethod -Uri "$ES/_cluster/health" -Method GET -ErrorAction Stop
        if ($health.status -in @("green","yellow")) { break }
    } catch {}
    $attempts++
    if ($attempts -gt 40) { Write-Error "Elasticsearch not ready after $attempts attempts."; exit 1 }
    Write-Host "  . attempt $attempts" -NoNewline
    Start-Sleep -Seconds 3
}
Write-OK "Elasticsearch is ready (status: $($health.status))"

# ── 2. Create ILM Policy ──────────────────────────────────────────────────────
Write-Step "Creating ILM policy: logs-policy"
$ilmBody = @"
{
  "policy": {
    "phases": {
      "hot":    { "min_age": "0ms",  "actions": { "rollover": { "max_primary_shard_size": "10gb", "max_age": "1d" }, "set_priority": { "priority": 100 } } },
      "warm":   { "min_age": "7d",   "actions": { "set_priority": { "priority": 50 }, "readonly": {} } },
      "delete": { "min_age": "30d",  "actions": { "delete": {} } }
    }
  }
}
"@
try {
    Invoke-RestMethod -Uri "$ES/_ilm/policy/logs-policy" -Method PUT -Headers $Headers -Body $ilmBody | Out-Null
    Write-OK "ILM policy created (hot=1d rollover, warm after 7d, delete after 30d)"
} catch { Write-Warn "ILM policy error: $_" }

# ── 3. Create Index Template ──────────────────────────────────────────────────
Write-Step "Creating index template: logs-template"
$templateBody = @"
{
  "index_patterns": ["logs-*"],
  "priority": 200,
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 0,
      "index.lifecycle.name": "logs-policy",
      "index.refresh_interval": "5s"
    },
    "mappings": {
      "dynamic": true,
      "properties": {
        "@timestamp": { "type": "date" },
        "message":    { "type": "text", "fields": { "keyword": { "type": "keyword", "ignore_above": 1024 } } },
        "tags":       { "type": "keyword" },
        "log": {
          "properties": {
            "level":    { "type": "keyword" },
            "format":   { "type": "keyword" },
            "original": { "type": "text", "fields": { "keyword": { "type": "keyword", "ignore_above": 2048 } } }
          }
        },
        "host":    { "properties": { "name": { "type": "keyword" } } },
        "service": { "properties": { "name": { "type": "keyword" } } },
        "http": {
          "properties": {
            "request":  { "properties": { "method": { "type": "keyword" } } },
            "response": { "properties": { "status_code": { "type": "integer" } } }
          }
        },
        "source": { "properties": { "ip": { "type": "ip" } } },
        "url":    { "properties": { "original": { "type": "keyword" } } },
        "alert":  { "properties": { "severity": { "type": "keyword" }, "fired": { "type": "boolean" } } },
        "user":   { "properties": { "id": { "type": "keyword" }, "name": { "type": "keyword" } } },
        "labels": { "properties": { "environment": { "type": "keyword" } } },
        "event":  { "properties": { "kind": { "type": "keyword" }, "type": { "type": "keyword" }, "dataset": { "type": "keyword" } } }
      }
    }
  }
}
"@
try {
    Invoke-RestMethod -Uri "$ES/_index_template/logs-template" -Method PUT -Headers $Headers -Body $templateBody | Out-Null
    Write-OK "Index template created with typed field mappings"
} catch { Write-Warn "Index template error: $_" }

# ── 4. Wait for Kibana ────────────────────────────────────────────────────────
Write-Step "Waiting for Kibana at $KIBANA..."
$kibanaReady = $false
$attempts = 0
while ($attempts -lt 30) {
    try {
        $status = Invoke-RestMethod -Uri "$KIBANA/api/status" -Method GET -ErrorAction Stop
        if ($status.status.overall.level -eq "available" -or $status.status.level -eq "available") {
            $kibanaReady = $true; break
        }
    } catch {}
    $attempts++
    Write-Host "  . attempt $attempts" -NoNewline
    Start-Sleep -Seconds 5
}

if (-not $kibanaReady) {
    Write-Warn "Kibana not ready yet — skipping data view + dashboard import"
    Write-Warn "Kibana may still be starting. Wait 1-2 minutes then re-run this script."
} else {
    Write-OK "Kibana is ready"

    # ── 5. Create Kibana Data View ────────────────────────────────────────────
    Write-Step "Creating Kibana data view: logs-*"
    $dataViewBody = @"
{
  "data_view": {
    "id": "logs-star",
    "title": "logs-*",
    "timeFieldName": "@timestamp",
    "name": "Log Pipeline"
  }
}
"@
    try {
        Invoke-RestMethod -Uri "$KIBANA/api/data_views/data_view" -Method POST -Headers $KibanaHeaders -Body $dataViewBody | Out-Null
        Write-OK "Kibana data view 'logs-*' created"
    } catch { Write-Warn "Data view may already exist (OK): $_" }

    # ── 6. Import Dashboard ───────────────────────────────────────────────────
    $dashFile = Join-Path $PSScriptRoot "kibana\dashboards\incident-overview.ndjson"
    if (Test-Path $dashFile) {
        Write-Step "Importing Kibana dashboard: incident-overview"
        try {
            $form = @{ file = Get-Item $dashFile }
            $resp = Invoke-RestMethod -Uri "$KIBANA/api/saved_objects/_import?overwrite=true" `
                -Method POST -Headers @{ "kbn-xsrf" = "true" } `
                -Form $form
            if ($resp.success) {
                Write-OK "Dashboard imported successfully ($($resp.successCount) objects)"
            } else {
                Write-Warn "Dashboard import partial: $($resp | ConvertTo-Json -Depth 3)"
            }
        } catch { Write-Warn "Dashboard import error: $_" }
    } else {
        Write-Warn "Dashboard file not found at: $dashFile"
    }
}

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  Log Pipeline Setup Complete!" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Service URLs:"
Write-Host "    Kibana:        http://localhost:5601" -ForegroundColor Cyan
Write-Host "    Elasticsearch: http://localhost:9200" -ForegroundColor Cyan
Write-Host "    Logstash API:  http://localhost:9600" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Next steps:" -ForegroundColor Yellow
Write-Host "  1. Start log simulation:"
Write-Host "     docker exec log-simulator bash /scripts/simulate_logs.sh"
Write-Host ""
Write-Host "  2. Trigger the alerter manually:"
Write-Host "     docker exec error-rate-alerter python /app/error_rate_alerter.py --once"
Write-Host ""
Write-Host "  3. Open Kibana -> Dashboards -> 'Incident Overview'" -ForegroundColor Yellow
Write-Host ""
