@echo off
rem Builds LeftoverSweeper into a single executable: dist\LeftoverSweeper.exe
cd /d "%~dp0"
python -m pip install --upgrade pyinstaller || goto :error
python -m PyInstaller --noconfirm --clean --onefile --windowed ^
    --name LeftoverSweeper ^
    --icon LeftoverSweeper\icon.ico ^
    --add-data "LeftoverSweeper\icon.ico;." ^
    --paths LeftoverSweeper ^
    LeftoverSweeper\app.py || goto :error
echo.
echo Done: dist\LeftoverSweeper.exe
exit /b 0

:error
echo.
echo The build failed.
exit /b 1
