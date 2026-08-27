$iface = "以太网 2"
$addr = "2408:8439:1220:1da4:0:0:0:1"
netsh interface ipv6 add address $iface $addr
Write-Output "exitcode=$LASTEXITCODE"
netsh interface ipv6 show addresses interface=14 | Select-String "2408:8439"
