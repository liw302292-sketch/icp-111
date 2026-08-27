$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot
$python = Join-Path $root '.venv\Scripts\python.exe'
$script = Join-Path $root 'tests\verify_ipv6_trim.py'
$out = Join-Path $root 'tests\verify_ipv6_trim.out.txt'
$err = Join-Path $root 'tests\verify_ipv6_trim.err.txt'
Remove-Item $out, $err -ErrorAction SilentlyContinue
Push-Location $root
try {
    & $python -X utf8 $script *> $out
    $code = $LASTEXITCODE
    if (Test-Path $err) {
        Remove-Item $err -ErrorAction SilentlyContinue
    }
    "exit=$code" | Out-File -FilePath $out -Append -Encoding utf8
}
catch {
    $_ | Out-File -FilePath $err -Encoding utf8
    exit 1
}
finally {
    Pop-Location
}
exit 0
