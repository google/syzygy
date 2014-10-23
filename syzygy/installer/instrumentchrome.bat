@echo off
:: Copyright 2012 Google Inc. All Rights Reserved.
::
:: Licensed under the Apache License, Version 2.0 (the "License");
:: you may not use this file except in compliance with the License.
:: You may obtain a copy of the License at
::
::     http://www.apache.org/licenses/LICENSE-2.0
::
:: Unless required by applicable law or agreed to in writing, software
:: distributed under the License is distributed on an "AS IS" BASIS,
:: WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
:: See the License for the specific language governing permissions and
:: limitations under the License.

:: Grab the input directory.
set CHROME_DIR=%1
set ORIGINALS_DIR=%CHROME_DIR%\original

if "%CHROME_DIR%"=="" (
  echo You must provide the directory of the Chrome to instrument.
  goto END
)

:: Copy the instrumentation DLL into the directory.
copy /y "%~dp0profile_client.dll" "%CHROME_DIR%"

:: Make a copy of chrome.dll and chrome.dll.pdb in the directory "original".
if not exist "%ORIGINALS_DIR%". (
  echo Making a copy of chrome.dll and chrome.dll.pdb in "%ORIGINALS_DIR%".
  mkdir "%ORIGINALS_DIR%"
  copy "%CHROME_DIR%\chrome.dll" "%ORIGINALS_DIR%"
  copy "%CHROME_DIR%\chrome?dll.pdb" "%ORIGINALS_DIR%"
) else (
  echo "%ORIGINALS_DIR%" already exists.
)
:: Instrument Chrome.dll.
instrument.exe --overwrite ^
    --call-trace-client=PROFILER ^
    --input-image="%ORIGINALS_DIR%\chrome.dll" ^
    --output-image="%CHROME_DIR%\chrome.dll"

:END