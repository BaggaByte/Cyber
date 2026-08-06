@echo off
echo ============================================
echo  NEXUS AI ENTERPRISE — Frontend Startup
echo ============================================
cd /d "%~dp0\frontend"
echo [INFO] Starting Vite dev server on http://localhost:5173
npm run dev
pause
