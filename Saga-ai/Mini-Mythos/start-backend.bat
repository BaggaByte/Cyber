cd /d "%~dp0"
call venv\Scripts\activate.bat 2>nul || echo [WARNING] venv not found, using system Python
cd src
echo [INFO] Starting FastAPI server on http://127.0.0.1:8082
uvicorn main:app --host 127.0.0.1 --port 8082 --reload --log-level info
