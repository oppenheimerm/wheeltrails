@echo off
REM Simple wrapper to run the PowerShell injector from Windows (call from repository root or WT.Client folder)
IF "%~1"=="" (
 echo Usage: %~nx0 "YOUR_GOOGLE_MAPS_KEY" [--Persist] [--ForceGitChanges]
 exit /b1
)
set KEY=%~1n
REM pass through optional flags
set ARGS=
if not "%~2"=="" set ARGS=%ARGS% %~2
if not "%~3"=="" set ARGS=%ARGS% %~3

pwsh -NoProfile -ExecutionPolicy Bypass -File "%~dp0dev-inject.ps1" -Key "%KEY%" %ARGS%
exit /b %ERRORLEVEL%