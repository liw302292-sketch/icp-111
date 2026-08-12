@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion
title ICP备案查询系统
cd /d "%~dp0"

:: ============================================
::  ICP Query System - Quick Start
::  Python source mode
:: ============================================

echo.
echo ╔══════════════════════════════════════════════════════════╗
echo ║         ICP Query System  v0.7.1                       ║
echo ║         Open Source - Learning Use Only                 ║
echo ╚══════════════════════════════════════════════════════════╝
echo.

:: --- 检查 Python ---
where python >nul 2>&1
if !errorlevel! neq 0 (
    echo [ERROR] Python not found, please install Python 3.11+
    echo         Download: https://www.python.org/downloads/
    pause
    exit /b 1
)

:: --- 检查/创建虚拟环境 ---
set "NEED_INSTALL=0"
if not exist ".venv\Scripts\python.exe" (
    echo [INFO] Virtual environment not found, creating...
    python -m venv .venv
    if !errorlevel! neq 0 (
        echo [ERROR] Failed to create virtual environment
        pause
        exit /b 1
    )
    echo [INFO] Virtual environment created
    set "NEED_INSTALL=1"
)

:: --- 激活虚拟环境 ---
call .venv\Scripts\activate.bat

:: --- 检查/安装依赖 ---
if "!NEED_INSTALL!"=="1" (
    echo [INFO] Installing dependencies...
    pip install -r src\python\requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
    if !errorlevel! neq 0 (
        echo [WARNING] Tsinghua mirror failed, trying default...
        pip install -r src\python\requirements.txt
    )
)

:: --- 检查关键文件 ---
if not exist "config.yml" (
    echo [WARNING] config.yml not found, using defaults
)
if not exist "model_data\ibig.onnx" (
    echo [WARNING] model_data\ibig.onnx not found, captcha may fail
)
if not exist "model_data\isma.onnx" (
    echo [WARNING] model_data\isma.onnx not found, captcha may fail
)

:: --- 启动服务 ---
echo.
echo ════════════════════════════════════════════════════════════
echo   Starting ICP query service...
echo   URL: http://127.0.0.1:16181
echo   Press Ctrl+C to stop
echo ════════════════════════════════════════════════════════════
echo.

python src\python\icpApi.py

:: --- 服务停止 ---
echo.
echo [INFO] ICP query service stopped
pause
endlocal
