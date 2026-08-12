@echo off
chcp 65001 >nul
title ICP备案查询系统 - 环境初始化
cd /d "%~dp0"

echo.
echo ╔══════════════════════════════════════════════════════════╗
echo ║        ICP备案查询系统 - 环境初始化                    ║
echo ╚══════════════════════════════════════════════════════════╝
echo.

echo [1/3] 检查 Python 环境...
where python >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] 未找到 Python，请安装 Python 3.11+
    echo         下载: https://www.python.org/downloads/
    pause
    exit /b 1
)

for /f "tokens=2" %%V in ('python -c "import sys; print(sys.version_info[0])"') do set PY_MAJOR=%%V
for /f "tokens=2" %%V in ('python -c "import sys; print(sys.version_info[1])"') do set PY_MINOR=%%V

echo    Python %PY_MAJOR%.%PY_MINOR% 已检测到

if %PY_MAJOR% lss 3 (
    echo [ERROR] 需要 Python 3.11+
    pause
    exit /b 1
)
if %PY_MAJOR% equ 3 if %PY_MINOR% lss 11 (
    echo [WARNING] 建议 Python 3.11+，当前为 %PY_MAJOR%.%PY_MINOR%，可能无法正常运行
)

echo [2/3] 创建虚拟环境...
if not exist ".venv\" (
    echo    正在创建 .venv ...
    python -m venv .venv
    if %errorlevel% neq 0 (
        echo [ERROR] 虚拟环境创建失败
        pause
        exit /b 1
    )
    echo    虚拟环境创建完成
) else (
    echo    虚拟环境 .venv 已存在
)

echo [3/3] 安装依赖包...
call .venv\Scripts\activate.bat
pip install -r src\python\requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
if %errorlevel% neq 0 (
    echo [WARNING] 清华源安装失败，尝试默认源...
    pip install -r src\python\requirements.txt
)

echo.
echo ╔══════════════════════════════════════════════════════════╗
echo ║              环境初始化完成！                          ║
echo ╚══════════════════════════════════════════════════════════╝
echo.
echo   双击 "启动.bat" 即可启动服务
echo.
pause
