@echo off
rem Abre LimpiaResiduos sin ventana de consola.
where pythonw >nul 2>nul && (start "" pythonw "%~dp0app.py" & exit /b)
where pyw >nul 2>nul && (start "" pyw "%~dp0app.py" & exit /b)
echo No se encontro Python. Instalalo desde https://www.python.org/downloads/
pause
