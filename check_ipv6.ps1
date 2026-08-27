# 检查本机已有的 Manual IPv6 地址数量
$existing = (Get-NetIPAddress -AddressFamily IPv6 |
    Where-Object { $_.PrefixOrigin -eq 'Manual' -and $_.IPAddress -notmatch '^fe80:' }).Count
if ($existing -gt 0) {
    Write-Host "  Found $existing IPv6 addresses, will reuse directly"
} else {
    Write-Host "  No existing IPv6 found, will create on startup"
}
