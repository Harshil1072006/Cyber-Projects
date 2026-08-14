
# fix_and_import.ps1 - Creates correct index-pattern and imports the dashboard

$KIBANA = "http://localhost:5601"

# Step 1: Delete the wrong data view (logs-star)
Write-Host "Removing old data view (logs-star)..." -ForegroundColor Cyan
try {
    Invoke-RestMethod -Uri "$KIBANA/api/data_views/data_view/logs-star" `
        -Method DELETE `
        -Headers @{ "kbn-xsrf" = "true" } | Out-Null
    Write-Host "[OK] Old data view deleted" -ForegroundColor Green
} catch {
    Write-Host "[INFO] No old data view found (OK)" -ForegroundColor Gray
}

# Step 2: Create index-pattern saved object with id matching the dashboard reference
Write-Host "Creating index-pattern with id 'logs-*'..." -ForegroundColor Cyan
$ipBody = '{"attributes":{"title":"logs-*","timeFieldName":"@timestamp"}}'
try {
    Invoke-RestMethod -Uri "$KIBANA/api/saved_objects/index-pattern/logs-*" `
        -Method POST `
        -Headers @{ "kbn-xsrf" = "true"; "Content-Type" = "application/json" } `
        -Body $ipBody | Out-Null
    Write-Host "[OK] Index pattern 'logs-*' created" -ForegroundColor Green
} catch {
    Write-Host "[INFO] Index pattern may already exist: $_" -ForegroundColor Yellow
}

# Step 3: Import the dashboard using raw multipart form-data
Write-Host "Importing dashboard..." -ForegroundColor Cyan
$dashFile = Join-Path $PSScriptRoot "kibana\dashboards\incident-overview.ndjson"

$boundary = [System.Guid]::NewGuid().ToString()
$fileBytes = [System.IO.File]::ReadAllBytes($dashFile)
$fileName  = "incident-overview.ndjson"

$headerStr = "--" + $boundary + "`r`n" +
             "Content-Disposition: form-data; name=`"file`"; filename=`"$fileName`"`r`n" +
             "Content-Type: application/x-ndjson`r`n`r`n"
$footerStr = "`r`n--" + $boundary + "--`r`n"

$headerBytes = [System.Text.Encoding]::UTF8.GetBytes($headerStr)
$footerBytes = [System.Text.Encoding]::UTF8.GetBytes($footerStr)

$fullBody = New-Object byte[] ($headerBytes.Length + $fileBytes.Length + $footerBytes.Length)
[System.Buffer]::BlockCopy($headerBytes, 0, $fullBody, 0,                                          $headerBytes.Length)
[System.Buffer]::BlockCopy($fileBytes,   0, $fullBody, $headerBytes.Length,                        $fileBytes.Length)
[System.Buffer]::BlockCopy($footerBytes, 0, $fullBody, $headerBytes.Length + $fileBytes.Length,    $footerBytes.Length)

try {
    $resp = Invoke-RestMethod `
        -Uri         "$KIBANA/api/saved_objects/_import?overwrite=true" `
        -Method      POST `
        -Headers     @{ "kbn-xsrf" = "true" } `
        -ContentType "multipart/form-data; boundary=$boundary" `
        -Body        $fullBody

    if ($resp.success) {
        Write-Host "[OK] Dashboard imported! ($($resp.successCount) objects)" -ForegroundColor Green
    } else {
        Write-Host "[WARN] Import result:" -ForegroundColor Yellow
        Write-Host ($resp | ConvertTo-Json -Depth 6) -ForegroundColor Yellow
    }
} catch {
    Write-Host "[ERROR] $_" -ForegroundColor Red
}

Write-Host ""
Write-Host "=================================================" -ForegroundColor Green
Write-Host "  Kibana is ready at: http://localhost:5601" -ForegroundColor Green
Write-Host "  Dashboards -> 'Incident Overview'" -ForegroundColor Green
Write-Host "=================================================" -ForegroundColor Green
