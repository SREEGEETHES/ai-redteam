<#>
.SYNOPSIS
    One-click startup for AI Red Team Platform
.DESCRIPTION
    Starts all services: Docker labs, API server, Streamlit dashboard
    Opens browser automatically
#>

param(
    [switch]$NoBrowser = $false,
    [switch]$SkipDocker = $false
)

$ErrorActionPreference = "Stop"
$ProjectRoot = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Item .).FullName }

Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║       AI RED TEAM - One-Click Startup                         ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Check if Docker Desktop is running
function Test-DockerRunning {
    try {
        $result = docker info 2>$null
        return $LASTEXITCODE -eq 0
    } catch {
        return $false
    }
}

# Start Docker Desktop if not running
function Ensure-DockerRunning {
    if (-not (Test-DockerRunning)) {
        Write-Host "Starting Docker Desktop..." -ForegroundColor Yellow
        Start-Process "C:\Program Files\Docker\Docker\Docker Desktop.exe" -WindowStyle Hidden
        Write-Host "Waiting for Docker Desktop to start..." -ForegroundColor Yellow
        $timeout = 120
        $start = Get-Date
        while (-not (Test-DockerRunning)) {
            if ((Get-Date) - $start).TotalSeconds -gt $timeout {
                throw "Docker Desktop failed to start within $timeout seconds"
            }
            Write-Host "." -NoNewline -ForegroundColor Yellow
            Start-Sleep -Seconds 2
        }
        Write-Host "`nDocker Desktop ready!" -ForegroundColor Green
    } else {
        Write-Host "Docker Desktop already running" -ForegroundColor Green
    }
}

# Build and start vulnerable labs
function Start-VulnerableLabs {
    Write-Host "`nBuilding & starting vulnerable labs..." -ForegroundColor Yellow
    docker compose build vulnerable-llm vulnerable-rag vulnerable-agent 2>&1 | Out-Null
    docker compose up -d vulnerable-llm vulnerable-rag 2>&1 | Out-Null
    
    Write-Host "Waiting for labs to be healthy..." -ForegroundColor Yellow
    $urls = @("http://localhost:8000/health", "http://localhost:8001/health")
    foreach ($url in $urls) {
        $timeout = 60
        $start = Get-Date
        while ($true) {
            try {
                $resp = Invoke-WebRequest -Uri $url -TimeoutSec 2 -ErrorAction Stop
                if ($resp.StatusCode -eq 200) { break }
            } catch {}
            if ((Get-Date) - $start).TotalSeconds -gt 60 { throw "Timeout waiting for $url" }
            Start-Sleep -Seconds 2
        }
    }
    Write-Host "Vulnerable labs ready!" -ForegroundColor Green
}

# Start API server
function Start-API {
    Write-Host "`nStarting API server (port 8080)..." -ForegroundColor Yellow
    $apiProc = Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PSScriptRoot'; python -m uvicorn app.api.main:app --host 127.0.0.1 --port 8080" -PassThru
    Start-Sleep -Seconds 3
    # Verify API is up
    try {
        $resp = Invoke-WebRequest -Uri "http://127.0.0.1:8080/health" -TimeoutSec 5
        if ($resp.StatusCode -eq 200) {
            Write-Host "API server ready at http://127.0.0.1:8080" -ForegroundColor Green
        }
    } catch {
        Write-Host "API server starting..." -ForegroundColor Yellow
    }
    return $apiProc
}

# Start Dashboard
function Start-Dashboard {
    Write-Host "`nStarting Streamlit Dashboard..." -ForegroundColor Yellow
    $dashProc = Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PSScriptRoot'; python -m streamlit run dashboard/main.py --server.port 8501" -PassThru
    Start-Sleep -Seconds 4
    Write-Host "Dashboard ready at http://localhost:8501" -ForegroundColor Green
    return $dashProc
}

# Open browser
function Open-Browser {
    if (-not $NoBrowser) {
        Start-Sleep -Seconds 2
        Start-Process "http://localhost:8501"
        Write-Host "Opened dashboard in browser" -ForegroundColor Green
    }
}

# Main execution
try {
    Set-Location $ProjectRoot

    if (-not $SkipDocker) {
        Ensure-DockerRunning
        Start-VulnerableLabs
    }

    $apiProc = Start-API
    $dashProc = Start-Dashboard
    Open-Browser

    Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║  AI RED TEAM PLATFORM RUNNING                                 ║" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host "  Dashboard:  http://localhost:8501" -ForegroundColor Green
    Write-Host "  API:        http://127.0.0.1:8080" -ForegroundColor Green
    Write-Host "  Vuln LLM:   http://localhost:8000" -ForegroundColor Green
    Write-Host "  Vuln RAG:   http://localhost:8001" -ForegroundColor Green
    Write-Host "  Vuln Agent: http://localhost:8002" -ForegroundColor Green
    Write-Host ""
    Write-Host "Press Ctrl+C to stop all services" -ForegroundColor Yellow
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan

    # Keep script running
    try {
        while ($true) { Start-Sleep -Seconds 10 }
    } finally {
        Write-Host "`nShutting down..." -ForegroundColor Yellow
        $apiProc | Stop-Process -Force -ErrorAction SilentlyContinue
        $dashProc | Stop-Process -Force -ErrorAction SilentlyContinue
        docker compose down 2>$null | Out-Null
        Write-Host "All services stopped" -ForegroundColor Green
    }

} catch {
    Write-Host "`nERROR: $_" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}