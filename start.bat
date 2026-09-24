@echo off
REM ============================================
REM AI Red Team - One-Click Startup (Batch)
REM ============================================
@echo off
setlocal enabledelayedexpansion

set "PROJECT_ROOT=%~dp0"
cd /d "%PROJECT_ROOT%"

echo ============================================
echo   AI RED TEAM - One-Click Startup
echo ============================================
echo.

REM Check if Docker Desktop is running
docker info >nul 2>nul
if errorlevel 1 (
    echo Starting Docker Desktop...
    start "" "C:\Program Files\Docker\Docker\Docker Desktop.exe"
    echo Waiting for Docker Desktop to start...
    :wait_docker
    timeout /t 5 >nul
    docker info >nul 2>nul
    if errorlevel 1 (
        echo Waiting for Docker...
        goto wait_docker
    )
    echo Docker Desktop ready!
) else (
    echo Docker Desktop already running
)

echo.
echo Building and starting vulnerable labs...
docker compose build vulnerable-llm vulnerable-rag vulnerable-agent 2>nul
docker compose up -d vulnerable-llm vulnerable-rag vulnerable-agent

echo Waiting for labs to be healthy...
timeout /t 30 >nul

REM Start API server in new window
start "AI Red Team API" cmd /k "cd /d "%~dp0" && python -m uvicorn app.api.main:app --host 127.0.0.1 --port 8080"

timeout /t 5 >nul

REM Start Dashboard
start "AI Red Team Dashboard" cmd /k "cd /d "%PROJECT_ROOT%" && python -m streamlit run dashboard/main.py --server.port 8501"

timeout /t 5

REM Open browser
start http://localhost:8501

echo.
echo ============================================
echo   AI RED TEAM PLATFORM RUNNING
echo ============================================
echo   Dashboard:  http://localhost:8501
echo   API:        http://127.0.0.1:8080
echo   Vuln LLM:   http://localhost:8000
echo   Vuln RAG:   http://localhost:8001
echo   Vuln Agent: http://localhost:8002
echo.
echo Press Ctrl+C in the API/Dashboard windows to stop
echo ============================================
pause