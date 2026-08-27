@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion
cd /d "%~dp0"

:: ============================================
::  管理员提权检查
:: ============================================
net session >nul 2>&1
if !errorlevel! neq 0 (
    echo 正在请求管理员权限...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

:: ============================================
::  至此已获取管理员权限
:: ============================================
title ICP备案查询系统 - 管理员模式
cls

echo.
echo ==========================================================
echo       ICP Query - Admin Mode
echo       Check IPv6 + Start Service
echo ==========================================================
echo.

:: ============================================
::  第一步：检测现有IPv6地址（不再删除重建）
:: ============================================
echo [1/2] Check existing IPv6 addresses...

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0check_ipv6.ps1"

echo.

:: ============================================
::  第二步：启动ICP查询服务
:: ============================================
echo [2/2] Start ICP query service...

:: ============================================
::  手机USB网络自动补IPv6（插手机后自动添加300个地址）
:: ============================================
echo [2.1] Ensure phone IPv6 addresses...
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0add_phone_ips.ps1"
echo.

:: 检查Python
where python >nul 2>&1
if !errorlevel! neq 0 (
    echo [ERROR] 未找到 Python
    pause
    exit /b 1
)

:: Check / create virtual environment
if not exist ".venv\Scripts\python.exe" (
    echo   Creating virtual environment...
    python -m venv .venv
    if !errorlevel! neq 0 (
        echo [ERROR] Virtual environment creation failed
        pause
        exit /b 1
    )
    echo   Installing dependencies...
    call .venv\Scripts\activate.bat
    pip install -r src\python\requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple 2>&1
    if !errorlevel! neq 0 (
        pip install -r src\python\requirements.txt
    )
) else (
    call .venv\Scripts\activate.bat
)

echo.
echo ════════════════════════════════════════════════════════════
echo   Starting service...
echo   URL: http://127.0.0.1:16181
echo   Press Ctrl+C to stop
echo ════════════════════════════════════════════════════════════
echo.

python src\python\icpApi.py

echo.
echo [INFO] Service stopped
pause
