@echo off
:: Copyright 2009 Google Inc. All Rights Reserved.
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
set SYZYGY_PYTHON="%~dp0..\third_party\python_26\python.exe"
set SYZYGY_SCRIPT="%~dp0tests\run_all_tests.py"
set SYZYGY_INTERNAL_TESTS="%~dp0internal\run_all_tests.bat"

%SYZYGY_PYTHON% %SYZYGY_SCRIPT% %*

IF EXIST %SYZYGY_INTERNAL_TESTS% (
%SYZYGY_INTERNAL_TESTS% %*
)

set SYZYGY_PYTHON=
set SYZYGY_SCRIPT=
set SYZYGY_INTERNAL_TESTS=
