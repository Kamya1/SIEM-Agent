# Start API on port 8001 (8000 may be stuck from old zombie processes on Windows).
Set-Location $PSScriptRoot
.\.venv\Scripts\Activate.ps1
uvicorn main:app --reload --host 127.0.0.1 --port 8001
