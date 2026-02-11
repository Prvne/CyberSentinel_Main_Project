@echo off
REM CyberSentinelAI - ML Defending Agent Startup Script for Windows

echo 🤖 CyberSentinelAI - ML Defending Agent Startup
echo ==========================================

REM Check if Docker is running
docker --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Docker is not running. Please start Docker Desktop first.
    pause
    exit /b 1
)

echo 🐳 Checking Docker Compose configuration...

REM Check if ml-defender compose file exists
if not exist "docker-compose.ml-defender.yml" (
    echo ❌ docker-compose.ml-defender.yml not found
    pause
    exit /b 1
)

echo 🚀 Starting ML Defending Agent services...

REM Start the ML defending agent stack
docker-compose -f docker-compose.ml-defender.yml up -d

echo.
echo ⏳ Waiting for services to be ready...
timeout /t 30 >nul 2>&1

REM Health check loop
:healthcheck
curl -s http://localhost:8001/health >nul 2>&1
if %errorlevel% equ 0 (
    echo ✅ ML Defending Agent is ready!
    echo.
    echo 🎯 Services Status:
    docker-compose -f docker-compose.ml-defender.yml ps
    echo.
    echo 📊 Access the ML Defending Dashboard:
    echo   Main API: http://localhost:8000 (existing services)
    echo   ML API: http://localhost:8001 (new ML defending agent)
    echo   Dashboard: http://localhost:3000 (updated to use ML services)
    echo.
    echo 🔍 To view logs:
    echo   docker-compose -f docker-compose.ml-defender.yml logs -f ml-defender
    echo.
    echo 🛑 To stop services:
    echo   docker-compose -f docker-compose.ml-defender.yml down
    goto :end
)

timeout /t 5 >nul 2>&1
goto healthcheck

:end
echo ❌ Failed to start ML Defending Agent
echo 🔍 Check logs with: docker-compose -f docker-compose.ml-defender.yml logs -f ml-defender
pause
exit /b 1
