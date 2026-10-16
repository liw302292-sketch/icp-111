# Elevation helper: restart the ICP query service with a clean single instance.
$ErrorActionPreference = "Continue"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

Write-Output "[1/4] Stopping any leftover python service process..."
Get-Process python -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

Write-Output "[2/4] Resolving python interpreter..."
$Py = Join-Path $Root ".venv\Scripts\python.exe"
if (-not (Test-Path $Py)) { $Py = "python" }
Write-Output "      using: $Py"

Write-Output "[3/4] Starting service (hidden window, logs go to logs\ymicp.log)..."
Start-Process -FilePath $Py `
    -ArgumentList "src\python\icpApi.py" `
    -WorkingDirectory $Root `
    -WindowStyle Hidden

Write-Output "[4/4] Waiting for port 16181 to listen..."
$ok = $false
for ($i = 0; $i -lt 40; $i++) {
    Start-Sleep -Seconds 3
    $line = netstat -ano | Select-String ':16181\s' | Select-String 'LISTENING'
    if ($line) {
        Write-Output "      LISTENING after $([int](3*($i+1)))s"
        $ok = $true
        break
    }
}
if (-not $ok) { Write-Output "      WARNING: port not listening yet" }

Write-Output "DONE"
