@echo off
echo Starting Aegis-AI SAST Engine...
cd /d "%~dp0Aegis-AI\src"
set PYTHONPATH=%cd%
uvicorn main:app --host 127.0.0.1 --port 8001 --reload
