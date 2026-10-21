@echo off
rem Starts LeftoverSweeper without a console window.
where pythonw >nul 2>nul && (start "" pythonw "%~dp0app.py" & exit /b)
where pyw >nul 2>nul && (start "" pyw "%~dp0app.py" & exit /b)
echo Python was not found. Install it from https://www.python.org/downloads/
pause
