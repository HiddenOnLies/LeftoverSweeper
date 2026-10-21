@echo off
rem Compila LimpiaResiduos en un unico ejecutable: dist\LimpiaResiduos.exe
cd /d "%~dp0"
python -m pip install --upgrade pyinstaller || goto :error
python -m PyInstaller --noconfirm --clean --onefile --windowed ^
    --name LimpiaResiduos ^
    --icon LimpiaResiduos\icono.ico ^
    --add-data "LimpiaResiduos\icono.ico;." ^
    --paths LimpiaResiduos ^
    LimpiaResiduos\app.py || goto :error
echo.
echo Listo: dist\LimpiaResiduos.exe
exit /b 0

:error
echo.
echo La compilacion ha fallado.
exit /b 1
