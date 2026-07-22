@echo off
where python.exe >nul 2>&1 && goto run_python
where py.exe >nul 2>&1 && goto run_py
>&2 echo codex-control-plane-hooks requires Python 3 via python.exe or py.exe
exit /b 127

:run_python
python.exe "%~dp0control_plane_hook.py"
exit /b %errorlevel%

:run_py
py.exe -3 "%~dp0control_plane_hook.py"
exit /b %errorlevel%
