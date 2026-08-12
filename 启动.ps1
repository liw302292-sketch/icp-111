# ============================================
#  ICP备案查询系统 - 一键启动脚本 (PowerShell)
#  支持: Python / Rust 双版本
# ============================================

param(
    [switch]$Setup,           # 仅初始化环境
    [switch]$Rust,            # 使用 Rust 版本启动
    [switch]$MCP,             # 仅启动 MCP 服务
    [switch]$NoWebUI,         # 不自动打开浏览器
    [int]$Port = 16181        # 自定义端口
)

$ErrorActionPreference = "Stop"
$RootDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $RootDir

# --- 颜色函数 ---
function Write-Color($Text, $Color = "White") {
    Write-Host $Text -ForegroundColor $Color
}

# --- 打印横幅 ---
function Show-Banner {
    Write-Host ""
    Write-Color "╔══════════════════════════════════════════════════════════╗" "Cyan"
    Write-Color "║         ICP备案查询系统  v0.7.1                          ║" "Cyan"
    Write-Color "║         开源项目 - 仅用于学习交流                        ║" "Cyan"
    Write-Color "╚══════════════════════════════════════════════════════════╝" "Cyan"
    Write-Host ""
}

# --- 检查 Python ---
function Test-Python {
    try {
        $pyVersion = python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>&1
        $major, $minor = $pyVersion -split '\.'
        Write-Color "  Python 版本: $pyVersion" "Green"
        if ([int]$major -lt 3 -or ([int]$major -eq 3 -and [int]$minor -lt 11)) {
            Write-Color "  [WARNING] 建议使用 Python 3.11+，当前版本可能有问题" "Yellow"
        }
        return $true
    } catch {
        Write-Color "  [ERROR] 未找到 Python，请安装 Python 3.11+" "Red"
        Write-Color "           https://www.python.org/downloads/" "Red"
        return $false
    }
}

# --- 检查 Rust ---
function Test-Rust {
    try {
        $cargoVersion = cargo --version 2>&1
        Write-Color "  Rust: $cargoVersion" "Green"
        return $true
    } catch {
        Write-Color "  [WARNING] 未找到 Rust 工具链" "Yellow"
        return $false
    }
}

# --- 初始化 Python 虚拟环境 ---
function Initialize-PythonEnv {
    Write-Color "[1/3] 检查 Python 环境..." "Yellow"
    if (-not (Test-Python)) { exit 1 }

    Write-Color "[2/3] 检查虚拟环境..." "Yellow"
    if (-not (Test-Path ".venv\Scripts\python.exe")) {
        Write-Color "  创建虚拟环境 .venv ..." "Gray"
        python -m venv .venv
        if ($LASTEXITCODE -ne 0) {
            Write-Color "  [ERROR] 虚拟环境创建失败" "Red"
            exit 1
        }
        $script:NeedInstall = $true
    } else {
        Write-Color "  虚拟环境已存在" "Green"
    }

    Write-Color "[3/3] 检查依赖包..." "Yellow"
    & ".venv\Scripts\activate.ps1"
    if ($script:NeedInstall) {
        Write-Color "  安装依赖包..." "Gray"
        pip install -r src\python\requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
        if ($LASTEXITCODE -ne 0) {
            Write-Color "  [WARNING] 清华源失败，使用默认源..." "Yellow"
            pip install -r src\python\requirements.txt
        }
    }
    
    # 检查关键模型文件
    if (-not (Test-Path "model_data\ibig.onnx")) {
        Write-Color "  [WARNING] model_data\ibig.onnx 缺失，验证码识别不可用" "Yellow"
    }
    if (-not (Test-Path "model_data\isma.onnx")) {
        Write-Color "  [WARNING] model_data\isma.onnx 缺失，验证码识别不可用" "Yellow"
    }
    
    Write-Host ""
}

# --- 修改端口 ---
function Set-CustomPort {
    if ($Port -ne 16181) {
        Write-Color "  自定义端口: $Port" "Yellow"
        # 临时修改 config.yml 端口
        $configPath = Join-Path $RootDir "config.yml"
        if (Test-Path $configPath) {
            $content = Get-Content $configPath -Raw -Encoding UTF8
            $content = $content -replace 'port: \d+', "port: $Port"
            Set-Content $configPath -Value $content -Encoding UTF8
            Write-Color "  已修改 config.yml 端口为 $Port" "Gray"
        }
    }
}

# --- 启动 Web UI ---
function Start-WebUI {
    $url = "http://127.0.0.1:$Port"
    Write-Color "  正在打开浏览器: $url" "Gray"
    Start-Process $url
}

# --- 主流程 ---
Show-Banner

if ($Setup) {
    Write-Color ">>> 环境初始化模式 <<<" "Yellow"
    Initialize-PythonEnv
    Write-Color "环境初始化完成！请运行 启动.bat 启动服务" "Green"
    pause
    exit 0
}

if ($Rust) {
    # --- Rust 版本 ---
    Write-Color ">>> 使用 Rust 版本启动 <<<" "Yellow"
    if (-not (Test-Rust)) {
        Write-Color "请先安装 Rust: https://rustup.rs/" "Red"
        pause
        exit 1
    }
    Set-Location "src\rust"
    Write-Color ""
    Write-Color "════════════════════════════════════════════════════════════" "Cyan"
    Write-Color "  编译并启动 Rust 版本 ICP 查询服务..." "Cyan"
    Write-Color "  按 Ctrl+C 停止服务" "Cyan"
    Write-Color "════════════════════════════════════════════════════════════" "Cyan"
    Write-Color ""
    cargo run --release
} elseif ($MCP) {
    # --- MCP 模式 ---
    Write-Color ">>> MCP 服务模式 <<<" "Yellow"
    Initialize-PythonEnv
    Write-Color ""
    Write-Color "════════════════════════════════════════════════════════════" "Cyan"
    Write-Color "  启动 MCP Streamable HTTP 服务..." "Cyan"
    Write-Color "  按 Ctrl+C 停止服务" "Cyan"
    Write-Color "════════════════════════════════════════════════════════════" "Cyan"
    Write-Color ""
    python src\python\mcp_server.py --http
} else {
    # --- Python 版本 (默认) ---
    Write-Color ">>> 使用 Python 版本启动 <<<" "Yellow"
    Initialize-PythonEnv
    Set-CustomPort
    
    Write-Color ""
    Write-Color "════════════════════════════════════════════════════════════" "Cyan"
    Write-Color "  启动 ICP 查询服务..." "Cyan"
    Write-Color "  访问地址: http://127.0.0.1:$Port" "Green"
    Write-Color "  MCP 服务: http://127.0.0.1:16182/mcp (需在config中开启)" "Gray"
    Write-Color "  按 Ctrl+C 停止服务" "Cyan"
    Write-Color "════════════════════════════════════════════════════════════" "Cyan"
    Write-Color ""

    if (-not $NoWebUI) {
        # 延迟打开浏览器，等服务器就绪
        Start-Sleep -Seconds 2
        Start-WebUI
    }

    python src\python\icpApi.py
}

Write-Color ""
Write-Color "[INFO] ICP 查询服务已停止" "Yellow"
pause
