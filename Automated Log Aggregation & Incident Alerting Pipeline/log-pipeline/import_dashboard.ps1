
# import_dashboard.ps1 — Imports the Kibana dashboard using raw multipart/form-data
# Works on all PowerShell versions (no -Form parameter needed)

$KIBANA   = "http://localhost:5601"
$dashFile = Join-Path $PSScriptRoot "kibana\dashboards\incident-overview.ndjson"

if (-not (Test-Path $dashFile)) {
    Write-Host "[ERROR] Dashboard file not found: $dashFile" -ForegroundColor Red
    exit 1
}

Write-Host "Importing dashboard from: $dashFile" -ForegroundColor Cyan

# Build multipart/form-data body manually (compatible with all PS versions)
$boundary = [System.Guid]::NewGuid().ToString()
$fileBytes = [System.IO.File]::ReadAllBytes($dashFile)
$fileName  = "incident-overview.ndjson"

$header = [System.Text.Encoding]::UTF8.GetBytes(
    "--" + $boundary + "`r`n" +
    "Content-Disposition: form-data; name=`"file`"; filename=`"$fileName`"`r`n" +
    "Content-Type: application/x-ndjson`r`n`r`n"
)
$footer = [System.Text.Encoding]::UTF8.GetBytes("`r`n--" + $boundary + "--`r`n")

# Combine into one byte array
$fullBody = New-Object byte[] ($header.Length + $fileBytes.Length + $footer.Length)
[System.Buffer]::BlockCopy($header,    0, $fullBody, 0,                                    $header.Length)
[System.Buffer]::BlockCopy($fileBytes, 0, $fullBody, $header.Length,                       $fileBytes.Length)
[System.Buffer]::BlockCopy($footer,    0, $fullBody, $header.Length + $fileBytes.Length,   $footer.Length)

$contentType = "multipart/form-data; boundary=$boundary"

try {
    $resp = Invoke-RestMethod `
        -Uri    "$KIBANA/api/saved_objects/_import?overwrite=true" `
        -Method POST `
        -Headers @{ "kbn-xsrf" = "true" } `
        -ContentType $contentType `
        -Body $fullBody

    if ($resp.success) {
        Write-Host ("[OK] Dashboard imported successfully! $($resp.successCount) objects.") -ForegroundColor Green
    } else {
        Write-Host "[WARN] Partial import:" -ForegroundColor Yellow
        Write-Host ($resp | ConvertTo-Json -Depth 5) -ForegroundColor Yellow
    }
} catch {
    Write-Host "[ERROR] Import failed: $_" -ForegroundColor Red
}

Write-Host ""
Write-Host "=======================================================" -ForegroundColor Green
Write-Host "  Open Kibana: http://localhost:5601" -ForegroundColor Green
Write-Host "  Go to: Dashboards -> 'Incident Overview'" -ForegroundColor Green
Write-Host "=======================================================" -ForegroundColor Green
