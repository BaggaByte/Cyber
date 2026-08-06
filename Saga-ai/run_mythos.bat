@echo off
echo Starting Mini-Mythos DAST Orchestrator...
cd /d "%~dp0Mini-Mythos"
call venv\Scripts\activate.bat 2>nul || echo [WARNING] venv not found, using system Python
cd src
set PYTHONPATH=%cd%
echo [INFO] Backend: http://127.0.0.1:8082
uvicorn main:app --host 127.0.0.1 --port 8082 --reload --log-level info
