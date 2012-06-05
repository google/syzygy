@echo off
:: Copyright 2012 Google Inc.
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

:: Make a full copy of the Chrome directory provided.
xcopy "%1" instrumented /ei
:: Copy the instrumentation DLL into the directory.
copy "%~dp0profile_client.dll" instrumented

:: Instrument Chrome.dll.
instrument.exe --overwrite^
    --call-trace-client=PROFILER^
    --input-dll="%1\chrome.dll"^
    --output-dll=instrumented\chrome.dll

:: Uncomment this to also instrument Chrome.exe.
:: Note that instrumented Chrome.exe cannot run with sandboxing enabled,
:: so you'll have to run it with --no-sandbox.
::
:: instrument.exe --overwrite^
::     --call-trace-client=PROFILER^
::     --input-dll="%1\chrome.exe"^
::     --output-dll=instrumented\chrome.exe
