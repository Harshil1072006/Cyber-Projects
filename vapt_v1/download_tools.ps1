$toolsDir = "tools"
if (!(Test-Path $toolsDir)) { New-Item -ItemType Directory $toolsDir }

function Download-Tool {
    param([string]$name, [string]$url, [string]$filename)
    $dest = Join-Path $toolsDir $filename
    Write-Host "Downloading $name from $url..."
    Invoke-WebRequest -Uri $url -OutFile $dest
    Write-Host "Downloaded $name to $dest."
    
    if ($filename.EndsWith(".zip")) {
        $extractDir = Join-Path $toolsDir $name
        if (!(Test-Path $extractDir)) { New-Item -ItemType Directory $extractDir }
        Write-Host "Extracting $filename to $extractDir..."
        Expand-Archive -Path $dest -DestinationPath $extractDir -Force
        Write-Host "Extracted $name."
    }
}

# 1. Nuclei (Latest Windows amd64 zip)
$nucleiRelease = Invoke-RestMethod -Uri "https://api.github.com/repos/projectdiscovery/nuclei/releases/latest"
$nucleiUrl = ($nucleiRelease.assets | Where-Object { $_.name -like "*_windows_amd64.zip" }).browser_download_url
Download-Tool -name "nuclei" -url $nucleiUrl -filename "nuclei.zip"

# 2. Trivy (Latest Windows-64bit zip)
$trivyRelease = Invoke-RestMethod -Uri "https://api.github.com/repos/aquasecurity/trivy/releases/latest"
$trivyUrl = ($trivyRelease.assets | Where-Object { $_.name -like "*_64bit.zip" -and $_.name -like "*Windows*" }).browser_download_url
Download-Tool -name "trivy" -url $trivyUrl -filename "trivy.zip"

# 3. Radare2 (Latest win64 zip)
$r2Release = Invoke-RestMethod -Uri "https://api.github.com/repos/radareorg/radare2/releases/latest"
$r2Url = ($r2Release.assets | Where-Object { $_.name -like "*_win64.zip" }).browser_download_url
Download-Tool -name "radare2" -url $r2Url -filename "radare2.zip"

# 4. Ghidra (Latest PUBLIC zip)
$ghidraRelease = Invoke-RestMethod -Uri "https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest"
$ghidraUrl = ($ghidraRelease.assets | Where-Object { $_.name -like "*_PUBLIC_*.zip" }).browser_download_url
Download-Tool -name "ghidra" -url $ghidraUrl -filename "ghidra.zip"

# 5. OWASP ZAP (Latest Windows x64 exe)
$zapRelease = Invoke-RestMethod -Uri "https://api.github.com/repos/zaproxy/zaproxy/releases/latest"
$zapUrl = ($zapRelease.assets | Where-Object { $_.name -like "*_windows_x64.exe" }).browser_download_url
Download-Tool -name "zap" -url $zapUrl -filename "zap_installer.exe"

Write-Host "Tools setup complete!"
