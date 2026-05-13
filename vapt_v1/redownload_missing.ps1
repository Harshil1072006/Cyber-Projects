$toolsDir = "tools"
$ErrorActionPreference = "Continue"

# --- 1. TRIVY ---
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Downloading TRIVY..." -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
try {
    $trivyRelease = Invoke-RestMethod -Uri "https://api.github.com/repos/aquasecurity/trivy/releases/latest"
    $trivyAsset = $trivyRelease.assets | Where-Object { $_.name -like "*Windows-64bit.zip" }
    if (-not $trivyAsset) {
        $trivyAsset = $trivyRelease.assets | Where-Object { $_.name -like "*windows*64*zip" -or $_.name -like "*Windows*64*.zip" }
    }
    if ($trivyAsset) {
        $trivyUrl = $trivyAsset.browser_download_url
        Write-Host "Found: $trivyUrl"
        $trivyDest = Join-Path $toolsDir "trivy.zip"
        Invoke-WebRequest -Uri $trivyUrl -OutFile $trivyDest -UseBasicParsing
        $trivyExtract = Join-Path $toolsDir "trivy"
        if (!(Test-Path $trivyExtract)) { New-Item -ItemType Directory $trivyExtract | Out-Null }
        Expand-Archive -Path $trivyDest -DestinationPath $trivyExtract -Force
        Write-Host "TRIVY downloaded and extracted successfully!" -ForegroundColor Green
    } else {
        Write-Host "Could not find Trivy Windows asset. Available assets:" -ForegroundColor Yellow
        $trivyRelease.assets | ForEach-Object { Write-Host "  - $($_.name)" }
    }
} catch {
    Write-Host "ERROR downloading Trivy: $_" -ForegroundColor Red
}

# --- 2. RADARE2 ---
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Downloading RADARE2..." -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
try {
    $r2Release = Invoke-RestMethod -Uri "https://api.github.com/repos/radareorg/radare2/releases/latest"
    $r2Asset = $r2Release.assets | Where-Object { $_.name -like "*w64.zip" -or $_.name -like "*win64*" }
    if ($r2Asset -is [array]) { $r2Asset = $r2Asset[0] }
    if ($r2Asset) {
        $r2Url = $r2Asset.browser_download_url
        Write-Host "Found: $r2Url"
        $r2Dest = Join-Path $toolsDir "radare2.zip"
        Invoke-WebRequest -Uri $r2Url -OutFile $r2Dest -UseBasicParsing
        $r2Extract = Join-Path $toolsDir "radare2"
        if (!(Test-Path $r2Extract)) { New-Item -ItemType Directory $r2Extract | Out-Null }
        Expand-Archive -Path $r2Dest -DestinationPath $r2Extract -Force
        Write-Host "RADARE2 downloaded and extracted successfully!" -ForegroundColor Green
    } else {
        Write-Host "Could not find Radare2 Windows asset. Available assets:" -ForegroundColor Yellow
        $r2Release.assets | ForEach-Object { Write-Host "  - $($_.name)" }
    }
} catch {
    Write-Host "ERROR downloading Radare2: $_" -ForegroundColor Red
}

# --- 3. ZAP ---
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Downloading OWASP ZAP..." -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
try {
    $zapRelease = Invoke-RestMethod -Uri "https://api.github.com/repos/zaproxy/zaproxy/releases/latest"
    # Try crossplatform zip first (no installer needed)
    $zapAsset = $zapRelease.assets | Where-Object { $_.name -like "*crossplatform.zip" }
    if (-not $zapAsset) {
        $zapAsset = $zapRelease.assets | Where-Object { $_.name -like "*core.zip" -or $_.name -like "*windows*.zip" }
    }
    if ($zapAsset -is [array]) { $zapAsset = $zapAsset[0] }
    if ($zapAsset) {
        $zapUrl = $zapAsset.browser_download_url
        Write-Host "Found: $zapUrl"
        $zapDest = Join-Path $toolsDir "zap.zip"
        Invoke-WebRequest -Uri $zapUrl -OutFile $zapDest -UseBasicParsing
        $zapExtract = Join-Path $toolsDir "zap"
        if (!(Test-Path $zapExtract)) { New-Item -ItemType Directory $zapExtract | Out-Null }
        Expand-Archive -Path $zapDest -DestinationPath $zapExtract -Force
        Write-Host "ZAP downloaded and extracted successfully!" -ForegroundColor Green
    } else {
        Write-Host "Could not find ZAP asset. Available assets:" -ForegroundColor Yellow
        $zapRelease.assets | ForEach-Object { Write-Host "  - $($_.name)" }
    }
} catch {
    Write-Host "ERROR downloading ZAP: $_" -ForegroundColor Red
}

Write-Host "`n========================================" -ForegroundColor Green
Write-Host "  DOWNLOAD COMPLETE - Summary:" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host "Nuclei:  $(if(Test-Path tools/nuclei/nuclei.exe){'OK'}else{'MISSING'})"
Write-Host "Trivy:   $(if((Get-ChildItem tools/trivy -ErrorAction SilentlyContinue | Measure-Object).Count -gt 0){'OK'}else{'MISSING'})"
Write-Host "Radare2: $(if((Get-ChildItem tools/radare2 -ErrorAction SilentlyContinue | Measure-Object).Count -gt 0){'OK'}else{'MISSING'})"
Write-Host "Ghidra:  $(if(Test-Path tools/ghidra/ghidra_12.0.4_PUBLIC/ghidraRun.bat){'OK'}else{'MISSING'})"
Write-Host "ZAP:     $(if((Get-ChildItem tools/zap -ErrorAction SilentlyContinue | Measure-Object).Count -gt 0){'OK'}else{'MISSING'})"
