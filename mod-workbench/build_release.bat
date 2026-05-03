@echo off
setlocal
cd /d "%~dp0"

echo ============================================================
echo  Crimson Desert Mod Workbench - Release Build
echo ============================================================
echo.
echo Working dir: %CD%
echo Started:     %DATE% %TIME%
echo.
echo You'll see each crate compile (380+ deps for the first build).
echo This can take 5-15 minutes from scratch. Subsequent builds
echo only recompile what changed (~30-90 seconds).
echo.
echo ------------------------------------------------------------
echo.

REM Build with progress + timing report.
REM   --release        optimized binary (~25-40 MB)
REM   --timings        writes target/cargo-timings/ HTML for analysis
REM Cargo by default already prints "Compiling <crate> v<version>" lines
REM as it works through the dep graph, plus a final size/path summary.
cargo build --release --timings

set EXIT_CODE=%ERRORLEVEL%

echo.
echo ------------------------------------------------------------
echo Finished: %DATE% %TIME%

if %EXIT_CODE% NEQ 0 (
    echo Build FAILED with exit code %EXIT_CODE%
    echo.
    pause
    exit /b %EXIT_CODE%
)

echo Build OK
echo.

REM Show binary info
set EXE=target\release\mod-workbench.exe
if exist "%EXE%" (
    for %%I in ("%EXE%") do (
        echo Binary: %%~fI
        set /a SIZE_MB=%%~zI / 1048576
    )
    echo Size:   %SIZE_MB% MB
)

echo.
echo Open timing report? (target\cargo-timings\cargo-timing.html)
echo Press Y to open, any other key to skip.
choice /c YN /n /t 10 /d N >nul
if errorlevel 2 goto skip_timings
start "" "target\cargo-timings\cargo-timing.html"

:skip_timings
echo.
echo Run binary now? (Y/N, auto-skip in 10s)
choice /c YN /n /t 10 /d N >nul
if errorlevel 2 goto end
start "" "%EXE%"

:end
echo.
pause
