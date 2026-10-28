@echo off
echo Installing PyInstaller and Pillow...
python -m pip install pyinstaller Pillow

echo.
echo Generating app icon...
python -c "import theme; theme.generate_icon_file('vault_icon.ico')"

set ICON_ARG=
if exist vault_icon.ico set ICON_ARG=--icon=vault_icon.ico

echo.
echo Building Vault.exe (this takes a minute or two)...
python -m PyInstaller --onefile --windowed --name Vault %ICON_ARG% app.py

echo.
echo Done. Your app is at: dist\Vault.exe
echo You can copy that one file anywhere - e.g. your Desktop - and double-click it to run. No Python needed.
pause
