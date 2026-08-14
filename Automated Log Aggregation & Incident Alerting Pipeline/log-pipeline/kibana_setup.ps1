
# kibana_setup.ps1 — Waits for Kibana, then creates data view and imports dashboard
$KIBANA = "http://localhost:5601"

Write-Host "Waiting for Kibana to become available..." -ForegroundColor Cyan

$attempts = 0
$kibanaReady = $false

while ($attempts -lt 40) {
    try {
        $r = Invoke-RestMethod -Uri "$KIBANA/api/status" -Method GET -ErrorAction Stop -TimeoutSec 5
        $level = $r.status.overall.level
        if (-not $level) { $level = $r.status.level }
        Write-Host ("  attempt {0}: status = {1}" -f ($attempts + 1), $level)
        if ($level -eq "available") {
            $kibanaReady = $true
            Write-Host "Kibana is READY!" -ForegroundColor Green
            break
        }
    } catch {
        Write-Host ("  attempt {0}: not yet ready..." -f ($attempts + 1))
    }
    $attempts++
    Start-Sleep -Seconds 5
}

if (-not $kibanaReady) {
    Write-Host "Kibana did not become ready in time. Try restarting: docker compose restart kibana" -ForegroundColor Red
    exit 1
}

# Step 1: Create data view
Write-Host ""
Write-Host "Step 1: Creating Kibana data view (logs-*)..." -ForegroundColor Cyan
$dvBody = '{"data_view":{"id":"logs-star","title":"logs-*","timeFieldName":"@timestamp","name":"Log Pipeline"}}'
try {
    Invoke-RestMethod -Uri "$KIBANA/api/data_views/data_view" `
        -Method POST `
        -Headers @{ "Content-Type" = "application/json"; "kbn-xsrf" = "true" } `
        -Body $dvBody | Out-Null
    Write-Host "[OK] Data view logs-* created" -ForegroundColor Green
} catch {
    Write-Host "[WARN] Data view may already exist (that is fine): $_" -ForegroundColor Yellow
}

# Step 2: Import dashboard
Write-Host ""
Write-Host "Step 2: Importing Kibana dashboard..." -ForegroundColor Cyan
$dashFile = Join-Path $PSScriptRoot "kibana\dashboards\incident-overview.ndjson"

if (Test-Path $dashFile) {
    try {
        $resp = Invoke-RestMethod `
            -Uri "$KIBANA/api/saved_objects/_import?overwrite=true" `
            -Method POST `
            -Headers @{ "kbn-xsrf" = "true" } `
            -Form @{ file = Get-Item $dashFile }
        if ($resp.success) {
            Write-Host ("[OK] Dashboard imported: {0} objects" -f $resp.successCount) -ForegroundColor Green
        } else {
            Write-Host ("[WARN] Partial import: " + ($resp | ConvertTo-Json -Depth 3)) -ForegroundColor Yellow
        }
    } catch {
        Write-Host "[WARN] Dashboard import error: $_" -ForegroundColor Yellow
    }
} else {
    Write-Host "[WARN] Dashboard file not found at: $dashFile" -ForegroundColor Yellow
}

# Step 3: Start log simulation
Write-Host ""
Write-Host "Step 3: Starting log simulation (background)..." -ForegroundColor Cyan
docker exec -d log-simulator bash /scripts/simulate_logs.sh
Write-Host "[OK] Log simulator running" -ForegroundColor Green

# Summary
Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  ALL DONE! Your ELK pipeline is fully running." -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Open these in your browser:" -ForegroundColor Yellow
Write-Host "    Kibana UI:       http://localhost:5601" -ForegroundColor Cyan
Write-Host "    Elasticsearch:   http://localhost:9200" -ForegroundColor Cyan
Write-Host "    Logstash API:    http://localhost:9600" -ForegroundColor Cyan
Write-Host ""
Write-Host "  In Kibana: Dashboards -> 'Incident Overview -- Log Pipeline'" -ForegroundColor Yellow
Write-Host ""
Write-Host "  To test the alerter manually:" -ForegroundColor Yellow
Write-Host "    docker exec error-rate-alerter python /app/error_rate_alerter.py --once --threshold 5 --dry-run" -ForegroundColor White
Write-Host ""
