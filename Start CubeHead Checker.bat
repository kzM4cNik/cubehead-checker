@echo off
cd /d "%~dp0"
if exist "CubeHead Checker.exe" (
  start "" "%~dp0CubeHead Checker.exe"
  exit /b 0
)
if exist "dist\CubeHead Checker.exe" (
  start "" "%~dp0dist\CubeHead Checker.exe"
  exit /b 0
)
py -3 cubehead_checker.py
if errorlevel 1 python cubehead_checker.py
