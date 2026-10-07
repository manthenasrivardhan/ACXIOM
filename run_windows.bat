@echo off
cd /d "%~dp0backend"
if not exist ".venv\Scripts\python.exe" py -m venv .venv
call ".venv\Scripts\activate.bat"
python -m pip install -r requirements.txt
python -m uvicorn app:app --reload
