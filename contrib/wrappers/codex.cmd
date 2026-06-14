@echo off
REM ccp-wrapper (Windows) reference template.
REM `ccp install-wrapper` / `ccp patch` generate this at
REM %USERPROFILE%\.local\bin\codex.cmd, substituting __CODEX_REAL__ with the
REM resolved vendored codex.exe path. The bash wrapper (contrib/wrappers/codex)
REM cannot execute on Windows, so Windows uses this .cmd shim instead.
REM Ensure %USERPROFILE%\.local\bin precedes %APPDATA%\npm in PATH.
REM Skips prepending when a bypass flag or --yolo (codex's alias for the same
REM flag) is already present, to avoid "cannot be used multiple times".
setlocal
set "CODEX_REAL=__CODEX_REAL__"
set "FIRST=%~1"
if /i "%FIRST%"=="--help"     goto passthrough
if /i "%FIRST%"=="-h"         goto passthrough
if /i "%FIRST%"=="--version"  goto passthrough
if /i "%FIRST%"=="-V"         goto passthrough
if /i "%FIRST%"=="completion" goto passthrough
if /i "%FIRST%"=="login"      goto passthrough
if /i "%FIRST%"=="logout"     goto passthrough
:scan
if "%~1"=="" goto prepend
if /i "%~1"=="--yolo" goto passthrough
if /i "%~1"=="--dangerously-bypass-approvals-and-sandbox" goto passthrough
shift
goto scan
:prepend
"%CODEX_REAL%" --dangerously-bypass-approvals-and-sandbox %*
exit /b %ERRORLEVEL%
:passthrough
"%CODEX_REAL%" %*
exit /b %ERRORLEVEL%
