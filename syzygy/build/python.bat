@echo off
:: Copyright 2016 Google Inc.
::
:: Licensed under the Apache License, Version 2.0 (the 'License');
:: you may not use this file except in compliance with the License.
:: You may obtain a copy of the License at
::
::      http://www.apache.org/licenses/LICENSE-2.0
::
:: Unless required by applicable law or agreed to in writing, software
:: distributed under the License is distributed on an 'AS IS' BASIS,
:: WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
:: See the License for the specific language governing permissions and
:: limitations under the License.

:: Save original Python environment variables.
set OLD_PYTHONHOME=%PYTHONHOME%
set OLD_PYTHONPATH=%PYTHONPATH%

:: Build paths to Syzygy's baked in Python version. Clear any paths that are set
:: externally, which likely reference depot_tools Python.
set SYZYGY_PYTHON="%~dp0..\..\third_party\python_26\python.exe"
set PYTHONHOME=
set PYTHONPATH=

:: Launch this in a separate process so that a Ctrl-C is caught there instead of
:: here. This ensures that the following code to restore the environment will be
:: executed.
cmd /c %SYZYGY_PYTHON% %*

:: Restore the environment.
set SYZYGY_PYTHON=
set PYTHONHOME=%OLD_PYTHONHOME%
set PYTHONPATH=%OLD_PYTHONPATH%
set OLD_PYTHONHOME=
set OLD_PYTHONPATH=
