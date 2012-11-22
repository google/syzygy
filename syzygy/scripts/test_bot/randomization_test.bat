@echo off
rem Copyright 2012 Google Inc. All Rights Reserved.
rem
rem Licensed under the Apache License, Version 2.0 (the "License");
rem you may not use this file except in compliance with the License.
rem You may obtain a copy of the License at
rem
rem      http://www.apache.org/licenses/LICENSE-2.0
rem
rem Unless required by applicable law or agreed to in writing, software
rem distributed under the License is distributed on an "AS IS" BASIS,
rem WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
rem See the License for the specific language governing permissions and
rem limitations under the License.

setlocal

:parseargs
set REPO=
set PROXY=
set WORKDIR=
set GCLIENT=
set SMTP_SERVER=
set FROM=
set TO=
set MODE_LABEL=
set CONFIG=Debug
set ITERATIONS=1
set PADDING=32
set NO_REVERT=
set REORDER_BASIC_BLOCKS=
set URL_LIST=%~dp0url-list.txt

for %%A in (%*) do (
  for /F "tokens=1* delims=:" %%b in ("%%~A") do (
    if /I "%%b" == "/mode" set MODE=%%~c
    if /I "%%b" == "/repo" set REPO=%%~c
    if /I "%%b" == "/proxy" set PROXY=--repo-proxy=%%~c
    if /I "%%b" == "/build-id" set BUILD_ID_PATTERN=%%~c
    if /I "%%b" == "/gclient-dir" set GCLIENT=%%~c
    if /I "%%b" == "/work-dir" set WORKDIR=%%~c
    if /I "%%b" == "/url-list" set URL_LIST=%%~c
    if /I "%%b" == "/server" set SMTP_SERVER=%%~c
    if /I "%%b" == "/from" set FROM=%%~c
    if /I "%%b" == "/to" set TO=%%~c
    if /I "%%b" == "/config" set CONFIG=%%~c
    if /I "%%b" == "/iterations" set ITERATIONS=%%~c
    if /I "%%b" == "/padding" set PADDING=%%~c
    if /I "%%b" == "/no-revert" set NO_REVERT=--reorder-no-revert-binaries
    if /I "%%b" == "/reorder-basic-blocks" (
      set REORDER_BASIC_BLOCKS=--reorder-basic-blocks
    )
  )
)

:checkargs
if "%MODE%" == "ui" set MODE_LABEL=step4_ui_tests
if "%MODE%" == "reliability" set MODE_LABEL=step4_reliability_tests
if "%MODE_LABEL%" == "" echo Missing or invalid /mode & goto usage
if "%REPO%" == "" echo Missing parameter: /repo & goto usage
if "%GCLIENT%" == "" echo Missing parameter: /gclient-dir & goto usage
if "%WORKDIR%" == "" echo Missing parameter: /work-dir & goto usage
if "%SMTP_SERVER%" == "" echo Missing parameter: /server & goto usage
if "%FROM%" == "" echo Missing parameter: /from & goto usage
if "%TO%" == "" echo Missing parameter: /to & goto usage
if "%BUILD_ID_PATTERN%" == "" set BUILD_ID_PATTERN=\d+\.\d+\.\d+\.\d+

SET SYZYGY=%GCLIENT%\src\syzygy
set BUILD_DIR=%GCLIENT%\src\build
goto setup

:usage
echo:
echo:Usage: %0 [options]
echo:
echo:  /mode:MODE         The type of test to run: ui or reliability
echo:  /repo:URL          URL to the root of the Chrome Repository
echo:  /build-id:PATTERN  The regular expression to use when filtering build ids
echo:  /gclient-dir:PATH  Path to the root of the source tree (where .gclient lives)
echo:  /work-dir:PATH     Working directory in which to download Chrome builds
echo:  /server:HOST       SMTP server to use when generating reports
echo:  /from:EMAIL        E-Mail address from which to send reports
echo:  /to:EMAIL          E-Mail address to which reports should be sent
echo:  /config:CONFIG     The configuration of Syzygy test (default: Debug)
echo:  /iterations:NUM    The number of iterations of the test to run
echo:  /padding:NUM       The amount of block padding to add when reordering
echo:  /no-revert         Do not revert chrome DLL/PDB after running the tests
echo:  /reorder-basic-blocks
echo:                     Randomize at the basic block level (as opposed to the
echo:                     function and data block level).
echo:
goto done

:setup
call "C:\Program Files (x86)\Microsoft Visual Studio 10.0\Common7\Tools\vsvars32.bat"

echo Initializing local variables ...
set THISDIR=%~dp0
set SOLUTION=%SYZYGY%\relink\relink.sln
set DOWNLOAD_PY=%THISDIR%chrome_repo.py
set REORDER_PY=%THISDIR%reorder.py
set SEND_MAIL_PY=%THISDIR%send_mail.py
set ACTIONS_XML=%THISDIR%actions.xml
set REORDER_EXE=%BUILD_DIR%\%CONFIG%\relink.exe
set BUILD_PTR=%WORKDIR%\chrome-build-dir.txt
set SYNC_LOG=%WORKDIR%\sync-log.txt
set BUILD_LOG=%WORKDIR%\build-log.txt
set DOWNLOAD_LOG=%WORKDIR%\downoad-log.txt
set REORDER_LOG=%WORKDIR%\reorder-log.txt
set TEST_REPORT=%WORKDIR%\report-{iter}-{seed}.xml
set SUMMARY=%WORKDIR%\reorder-summary.txt
set ERROR_MESSAGE=%WORKDIR%\error-message.txt

:step1
echo Cleaning up data from previous runs ...
del /F /Q ^
  "%BUILD_LOG%" ^
  "%DOWNLOAD_LOG%" ^
  "%REORDER_LOG%" ^
  "%WORKDIR%\report-*.xml" ^
  "%SUMMARY%" ^
  "%ERROR_MESSAGE%"

:step2
echo Building "%SOLUTION%" ...
call devenv.com "%SOLUTION%" /Rebuild "Release|Win32" > "%BUILD_LOG%" 2>&1
if %ERRORLEVEL% equ 0 goto step3
handle.exe >> "%BUILD_LOG%"
echo Trying again to build "%SOLUTION%" ...
call devenv.com "%SOLUTION%" /Build "Release|Win32" >> "%BUILD_LOG%" 2>&1
if %ERRORLEVEL% equ 0 goto step3
handle.exe >> "%BUILD_LOG%"
copy "%BUILD_LOG%" "%ERROR_MESSAGE%"
goto error

:step3
echo Downloading latest chrome release ...
call python "%DOWNLOAD_PY%" ^
  --repo-url="%REPO%" %PROXY% ^
  --repo-work-dir="%WORKDIR%" ^
  --repo-build-id-pattern="%BUILD_ID_PATTERN%" ^
  --log-file="%DOWNLOAD_LOG%" ^
  --log-verbose ^
  GET ^
  > "%BUILD_PTR%"
if %ERRORLEVEL% equ 0 goto step4
copy %DOWNLOAD_LOG% %ERROR_MESSAGE%
goto error

:step4
set /p BUILD_DIR= < "%BUILD_PTR%"
set CHROME_DIR=%BUILD_DIR%\chrome-win32
set SYMBOL_DIR=%BUILD_DIR%\chrome-win32-syms
set CHROME_DLL=%CHROME_DIR%\chrome.dll
set CHROME_PDB=%SYMBOL_DIR%\chrome?dll.pdb
goto %MODE_LABEL%

:step4_ui_tests
echo Running randomized ui test ...
set UI_TESTS_EXE=%CHROME_DIR%\automated_ui_tests.exe
call python "%REORDER_PY%" ^
  --summary-title="Reordered UI Tests" ^
  --reorder-tool="%REORDER_EXE%" ^
  --reorder-input-bin="%CHROME_DLL%" ^
  --reorder-input-pdb="%CHROME_PDB%" ^
  --reorder-test-program="%UI_TESTS_EXE%" ^
  --reorder-num-iterations=%ITERATIONS% ^
  %NO_REVERT% %REORDER_BASIC_BLOCKS% ^
  --reorder-padding="%PADDING%" ^
  --log-file="%REORDER_LOG%" ^
  --log-verbose ^
  -- --input=%ACTIONS_XML% ^
    --output=%TEST_REPORT% ^
    --debug ^
  > "%SUMMARY%"
if %ERRORLEVEL% equ 0 goto step5
copy %SUMMARY%+%REORDER_LOG% %ERROR_MESSAGE%
goto error

:step4_reliability_tests
echo Running randomized reliability test ...
set RELIABILITY_TESTS_EXE=%CHROME_DIR%\reliability_tests.exe
call python "%REORDER_PY%" ^
  --summary-title="Reordered Reliability Tests" ^
  --reorder-tool="%REORDER_EXE%" ^
  --reorder-input-bin="%CHROME_DLL%" ^
  --reorder-input-pdb="%CHROME_PDB%" ^
  --reorder-test-program="%RELIABILITY_TESTS_EXE%" ^
  --reorder-num-iterations=%ITERATIONS% ^
  %NO_REVERT% %REORDER_BASIC_BLOCKS% ^
  --reorder-padding="%PADDING%" ^
  --log-file="%REORDER_LOG%" ^
  --log-verbose ^
  -- --list="%URL_LIST%" ^
     --logfile="%RELIABILITY_LOG%" ^
     --savedebuglog ^
     --js-flags="" ^
     --ui-test-timeout=240000 ^
     --ui-test-action-timeout=240000 ^
     --ui-test-action-max-timeout=240000 ^
     --ui-test-terminate-timeout=240000 ^
     --enable-logging ^
     --log-level=0 ^
     --enable-dcheck ^
     --extra-chrome-flags="--no-js-randomness --disable-background-networking" ^
     --full-memory-crash-report ^
  > "%SUMMARY%"
if %ERRORLEVEL% equ 0 goto step5
copy %SUMMARY%+%REORDER_LOG% %ERROR_MESSAGE%
goto error

:step5
rmdir /S /Q "%BUILD_DIR%"
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
  --ignore-missing ^
  > "%ERROR_MESSAGE%"
if %ERRORLEVEL% equ 0 goto done

:error
echo Reporting error
call python %SEND_MAIL_PY% ^
  --server="%SMTP_SERVER%" ^
  --from="%FROM%" ^
  --to="%TO%" ^
  --subject="Syzygy %MODE% test bot failed!" ^
  --message="@%ERROR_MESSAGE%" ^
  --attach="%REORDER_LOG%" ^
  --attach="%SYNC_LOG%" ^
  --attach="%BUILD_LOG%" ^
  --attach="%DOWNLOAD_LOG%" ^
  --attach="%WORKDIR%\report*.xml" ^
  --ignore-missing

:done
rem Done
