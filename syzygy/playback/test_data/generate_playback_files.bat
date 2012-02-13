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
::
:: Temporary file, instruments test_dll, generates trace files, and
:: copies everything to the playback test_data folder.
set PLAYBACKDIR="%~dp0"
set DEBUGDIR="%~dp0..\..\..\build\Debug\"
set INSTRUMENT="instrument.exe"
set TEST_DLL="test_data\test_dll.dll"
set INSTRUMENTED_DLL="test_data\instrumented_dll.dll"
set CALL_TRACE_SERVICE=call_trace_service.exe

:: Save current directory, and move to Debug dir since the DLLs have
:: to be executed from there.
pushd .
cd %DEBUGDIR%

:: Instrument the test_dll.
%INSTRUMENT% --input-dll=%TEST_DLL% --output-dll=%INSTRUMENTED_DLL% ^
    --call-trace-client=RPC

:: Start the call trace service and call the instrumented_dll a few times.
start %CALL_TRACE_SERVICE --verbose start
rundll32 %INSTRUMENTED_DLL%,DllMain
rundll32 %INSTRUMENTED_DLL%,DllMain
rundll32 %INSTRUMENTED_DLL%,function1
rundll32 %INSTRUMENTED_DLL%,function3

:: Wait for 1 second - apparently there is not a much better way to do this.
ping 1.2.3.4 -n 1 -w 1000 > nul
%CALL_TRACE_SERVICE% stop

:: Copy DLLs to playback dir
copy %TEST_DLL% %PLAYBACKDIR%
copy %INSTRUMENTED_DLL% %PLAYBACKDIR%

:: Move *.bin files to playback dir
set a=1
for %%i in (*.bin) do call :movefile %%i

:: Restore original directory
popd
goto :eof

:movefile
move %1 "%PLAYBACKDIR%trace-%a%.bin"
set /A a+=1
goto :eof

