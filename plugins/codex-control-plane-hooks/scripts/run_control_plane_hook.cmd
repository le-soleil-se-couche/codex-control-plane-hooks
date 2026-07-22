@echo off
setlocal EnableExtensions DisableDelayedExpansion
set "ERRORLEVEL="

powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0run_control_plane_hook.ps1"
set "_cph_rc=%ERRORLEVEL%"
endlocal & exit /b %_cph_rc%
