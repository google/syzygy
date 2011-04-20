@echo off
setlocal

:parseargs
set REPO=
set SYZYGY=
set WORKDIR=
set SMTP_SERVER=
set FROM=
set TO=
set CONFIG=
set ITERATIONS=

for %%A in (%*) do (
  for /F "tokens=1* delims=:" %%b in ("%%~A") do (
    if /I "%%b" == "/repo" set REPO=%%~c
    if /I "%%b" == "/syzygy" set SYZYGY=%%~c
    if /I "%%b" == "/workdir" set WORKDIR=%%~c
    if /I "%%b" == "/server" set SMTP_SERVER=%%~c
    if /I "%%b" == "/from" set FROM=%%~c
    if /I "%%b" == "/to" set TO=%%~c
    if /I "%%b" == "/config" set CONFIG=%%~c
    if /I "%%b" == "/iterations" set ITERATIONS=%%~c
    )
  )

:checkargs
if "%REPO%" == "" echo Missing parameter: /repo & goto usage
if "%SYZYGY%" == "" echo Missing parameter: /syzygy & goto usage
if "%WORKDIR%" == "" echo Missing parameter: /workdir & goto usage
if "%SMTP_SERVER%" == "" echo Missing parameter: /server & goto usage
if "%FROM%" == "" echo Missing parameter: /from & goto usage
if "%TO%" == "" echo Missing parameter: /to & goto usage
if "%CONFIG%" == "" set CONFIG=Debug
if "%ITERATIONS%" == "" set ITERATIONS=20
goto setup

:usage
echo:
echo:Usage: %0 [options]
echo:
echo:  /repo:URL        URL to the root of the Chrome Repositoty
echo:  /syzygy:PATH     Path to the root of the Syzygy source tree
echo:  /workdir:PATH    Working directory in which to download Chrome builds
echo:  /server:HOST     SMTP server to use when generating reports
echo:  /from:EMAIL      E-Mail address from which to send reports
echo:  /to:EMAIL        E-Mail address to which reports should be sent
echo:  /config:CONFIG   The configuration of Syzygy test (default: Debug)
echo:  /iterations:NUM  The number of iterations of the test to run
echo:
goto done

:setup
call "C:\Program Files (x86)\Microsoft Visual Studio 9.0\Common7\Tools\vsvars32.bat"
set THISDIR=%~dp0
set SOLUTION=%SYZYGY%\src\syzygy\relink\relink.sln
set DOWNLOAD_PY=%THISDIR%chrome_repo.py
set REORDER_PY=%THISDIR%reorder.py
set SEND_MAIL_PY=%THISDIR%send_mail.py
set ACTIONS_XML=%THISDIR%actions.xml
set REORDER_EXE=%SYZYGY%\src\syzygy\relink\%CONFIG%\relink.exe
set CHROME_PTR=%WORKDIR%\chrome-dir.txt
set SYNC_LOG=%WORKDIR%\sync-log.txt
set BUILD_LOG=%WORKDIR%\build-log.txt
set DOWNLOAD_LOG=%WORKDIR%\downoad-log.txt
set REORDER_LOG=%WORKDIR%\reorder-log.txt
set TEST_REPORT=%WORKDIR%\report-{iter}-{seed}.xml
set SUMMARY=%WORKDIR%\reorder-summary.txt
set ERROR_MESSAGE=%WORKDIR%\error-message.txt

del ^
  "%SYNC_LOG%" ^
  "%BUILD_LOG%" ^
  "%DOWNLOAD_LOG%" ^
  "%REORDER_LOG%" ^
  "%WORKDIR%\report-*.xml" ^
  "%SUMMARY%" ^
  "%ERROR_MESSAGE%"
  
:step1
cd "%SYZYGY%\src"
echo Synchronizing "%SYZYGY%" ...
call gclient sync ^
  > "%SYNC_LOG%" 2>&1
if %ERRORLEVEL% equ 0 goto step2
copy "%SYNC_LOG%" "%ERROR_MESSAGE%"
goto error

:step2
echo Building "%SOLUTION%" ...
call msbuild /t:Rebuild /p:Configuration=%CONFIG% "%SOLUTION%" ^
  > "%BUILD_LOG%" 2>&1 
if %ERRORLEVEL% equ 0 goto step3
copy "%BUILD_LOG%" "%ERROR_MESSAGE%"
goto error

:step3
echo Downloading latest chrome release ...
call python "%DOWNLOAD_PY%" ^
  --repo-url="%REPO%" ^
  --repo-work-dir="%WORKDIR%" ^
  --log-file="%DOWNLOAD_LOG%" ^
  --log-verbose ^
  GET ^
  > "%CHROME_PTR%"
if %ERRORLEVEL% equ 0 goto step4
copy %DOWNLOAD_LOG% %ERROR_MESSAGE%
goto error

:step4
echo Running reorder test ...
set /p CHROME_DIR= < "%CHROME_PTR%"
set CHROME_DLL=%CHROME_DIR%\chrome.dll
set CHROME_PDB=%CHROME_DIR%\chrome_dll.pdb
set UI_TESTS_EXE=%CHROME_DIR%\automated_ui_tests.exe
call python "%REORDER_PY%" ^
  --reorder-tool="%REORDER_EXE%" ^
  --reorder-input-bin="%CHROME_DLL%" ^
  --reorder-input-pdb="%CHROME_PDB%" ^
  --reorder-test-program="%UI_TESTS_EXE%" ^
  --reorder-num-iterations=%ITERATIONS% ^
  --log-file="%REORDER_LOG%" ^
  --log-verbose ^
  -- --input=%ACTIONS_XML% ^
    --output=%TEST_REPORT% ^
    --debug ^
  > "%SUMMARY%"
if %ERRORLEVEL% equ 0 goto step5
copy %SUMMARY%+%REORDER_LOG% %ERROR_MESSAGE%
goto error

:step5
echo Sending out summary mail ...
call python "%SEND_MAIL_PY%" ^
  --server="%SMTP_SERVER%" ^
  --from="%FROM%" ^
  --to="%TO%" ^
  --subject="@%SUMMARY%" ^
  --message="@%REORDER_LOG%" ^
  --attach="%REORDER_LOG%" ^
  --attach="%SYNC_LOG%" ^
  --attach="%BUILD_LOG%" ^
  --attach="%DOWNLOAD_LOG%" ^
  --attach="%WORKDIR%\report*.xml" ^
  > "%ERROR_MESSAGE%"
if %ERRORLEVEL% equ 0 goto done

:error
echo Reporting error
call python %SEND_MAIL_PY% ^
  --server="%SMTP_SERVER%" ^
  --from="%FROM%" ^
  --to="%TO%" ^
  --subject="Syzgy Test Bot Failed!" ^
  --message="@%ERROR_MESSAGE%" ^
  --attach="%REORDER_LOG%" ^
  --attach="%SYNC_LOG%" ^
  --attach="%BUILD_LOG%" ^
  --attach="%DOWNLOAD_LOG%" ^
  --attach="%WORKDIR%\report*.xml" ^
  --ignore-missing

:done
echo Done.
