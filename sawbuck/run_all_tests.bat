@echo off
rem = """
:: Copyright 2009 Google Inc.
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

:: depot_tools scripts use %SCRIPT% - make sure we don't pollute the env.
setlocal

set PYTHON="%~p0..\third_party\python_26\python.exe"
set SCRIPT="%~p0..\sawbuck\tools\run_all_tests.py"
set SOLUTION="%~p0Sawbuck.sln"
set PROJECT="run_unittests"

%PYTHON% %SCRIPT% --solution="%SOLUTION%" --project="%PROJECT%" %*

endlocal
