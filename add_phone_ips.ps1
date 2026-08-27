# 自动为手机USB网络(Remote NDIS)补足 300 个 IPv6 地址（幂等，可重复执行）
$adapter = Get-NetAdapter -ErrorAction SilentlyContinue |
    Where-Object { $_.InterfaceDescription -like "*Remote NDIS*" -and $_.Status -eq "Up" } |
    Select-Object -First 1
if (-not $adapter) {
    Write-Output "未检测到手机USB网络，跳过（插上手机并开启USB网络共享后再试）"
    exit 0
}
$idx = $adapter.ifIndex
$addrs = Get-NetIPAddress -InterfaceIndex $idx -AddressFamily IPv6 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -notlike 'fe80*' }
$prefix = $null
foreach ($a in $addrs) {
    $p = (($a.IPAddress -split ':')[0..3]) -join ':'
    if ($p -match '^[0-9a-fA-F]{1,4}(:[0-9a-fA-F]{1,4}){3}$') { $prefix = $p; break }
}
if (-not $prefix) {
    Write-Output "手机网络没有全局IPv6前缀（运营商可能未下发IPv6），跳过"
    exit 0
}
$existing = 0
foreach ($a in $addrs) {
    if ($a.IPAddress.StartsWith($prefix)) { $existing++ }
}
$need = 300 - $existing
if ($need -le 0) {
    Write-Output "手机前缀 $prefix 已有 $existing 个地址，无需添加"
    exit 0
}
$count = 0
for ($i = 1; $i -le $need; $i++) {
    $suffix = "{0:x}" -f $i
    $addr = "$prefix:0:0:0:$suffix"
    netsh interface ipv6 add address $idx $addr | Out-Null
    if ($LASTEXITCODE -eq 0) { $count++ }
}
Write-Output "手机前缀 $prefix 新增 $count 个地址（现共 $($existing + $count) 个）"
