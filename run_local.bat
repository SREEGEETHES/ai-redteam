@echo off
REM ============================================
REM AI Red Team - Local Startup (No Docker Required)
REM ============================================
@echo off
setlocal enabledelayedexpansion

set PROJECT_ROOT=C:\Users\JASPRIT SREE\Desktop\Ai-redteam\ai-redteam
cd /d "%PROJECT_ROOT%"

echo ============================================
echo   AI RED TEAM - Local Startup (No Docker)
REM ============================================
echo.

REM Check if virtual environment exists
if not exist "venv" (
    echo Creating virtual environment...
    python -m venv venv
    call venv\Scripts\activate.bat
    pip install -e ".[dev]"
) else (
    call venv\Scripts\activate.bat
)

echo.
echo Starting all services...
echo.

REM Start vulnerable labs in background
start "Vulnerable LLM" cmd /k "cd /d C:\Users\JASPRIT SREE\Desktop\Ai-redteam\ai-redteam\examples\vulnerable-llm && python -m uvicorn main:app --host 127.0.0.1 --port 8000"

start "Vulnerable RAG" cmd /k "cd /d C:\Users\JASPRIT SREE\Desktop\Ai-redteam\ai-redteam\examples\vulnerable-rag && python -m uvicorn main:app --host 127.0.0.1 --port 8001"

start "Vulnerable Agent" cmd /k "cd /d C:\Users\JASPRIT SREE\Desktop\Ai-redteam\ai-redteam\examples\vulnerable-agent && python -m uvicorn main:app --host 127.0.0.1 --port 8002"

start "Secure LLM" cmd /k "cd /d C:\Users\JASPRIT SREE\Desktop\Ai-redteam\ai-redteam\examples\secure-llm && python -m uvicorn main:app --host 127.0.0.1 --port 8001"

start "Secure RAG" cmd /k "cd /d C:\Users\JASPRIT SREE\Desktop\Ai-redteam\ai-redteam\examples\secure-rag && python -m uvicorn main:app --host 127.0.0.1 --port 8003"

start "Secure Agent" cmd /k "cd /d C:\Users\JASPRIT SREE\Desktop\Ai-redteam\ai-redteam\examples\secure-agent && python -m uvicorn main:app --host 127.0.0.1 --port 8004"

echo Waiting for labs to start...
timeout /t 5 >nul

REM Start API server
start "AI Red Team API" cmd /k "cd /d C:\Users\JASPRIT SREE\Desktop\Ai-redteam\ai-redteam && python -m uvicorn app.api.main:app --host 127.0.0.1 --port 8080"

timeout /t 3 >nul

REM Start Dashboard
start "AI Red Team Dashboard" cmd /k "cd /d C:\Users\JASPRIT SREE\Desktop\Ai-redteam\ai-redteam && python -m streamlit run dashboard/main.py --server.port 8501"

timeout /t 4 >nul

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
echo   Secure LLM:  http://localhost:8001
echo   Secure RAG:  http://localhost:8003
echo   Secure Agent: http://localhost:8004
echo.
echo Press Ctrl+C in any window to stop that service
echo ============================================
pause