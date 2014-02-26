@echo off
rem = """
:: Copyright 2014 Google Inc.
::
:: Licensed under the Apache License, Version 2.0 (the "License");
:: you may not use this file except in compliance with the License.
:: You may obtain a copy of the License at
::
::      http://www.apache.org/licenses/LICENSE-2.0
::
:: Unless required by applicable law or agreed to in writing, software
:: distributed under the License is distributed on an "AS IS" BASIS,
:: WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
:: See the License for the specific language governing permissions and
:: limitations under the License.

python -x "%~f0" %*
exit /b %ERRORLEVEL%
goto endofPython """

import sys
import os

# Prepend the eggs we need to our python path.
_EGGS = [
    'Benchmark_Chrome-0.1_r2027-py2.6.egg',
    'ETW-0.6.5.0-py2.6.egg',
    'ETW_Db-0.1_r2024-py2.6.egg',
    'setuptools-0.6c11-py2.6.egg',
  ]
dir = os.path.dirname(__file__)
sys.path[0:0] = [os.path.join(dir, egg) for egg in _EGGS]

# And run the main program.
import profile
sys.exit(profile.main())

rem = """
:endofPython """
