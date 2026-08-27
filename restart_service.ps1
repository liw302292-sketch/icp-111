$conn = Get-NetTCPConnection -LocalPort 16181 -State Listen -ErrorAction SilentlyContinue
if ($conn) {
    Stop-Process -Id $conn.OwningProcess -Force
    Write-Output "已停止旧服务 PID $($conn.OwningProcess)"
    Start-Sleep -Seconds 2
}
$log = "logs\service_v2_" + (Get-Date -Format 'HHmmss') + ".log"
Start-Process -FilePath "python" -ArgumentList "src\python\icpApi.py" `
    -WorkingDirectory (Get-Location) -WindowStyle Hidden `
    -RedirectStandardOutput $log -RedirectStandardError "$log.err"
Write-Output "已启动新服务，日志: $log"
