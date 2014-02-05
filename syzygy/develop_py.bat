@echo off
rem = """
:: Copyright 2012 Google Inc.
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

python -x "%~f0" %*
exit /b %ERRORLEVEL%
goto endofPython """

import os
import subprocess
import sys


# Add the setup.py files for any new modules here. Note that setup files
# must be ordered, so if module X depends on module Y, Y's setup file
# must precede X's.
_SETUP_FILES=[
  '../third_party/sawbuck/py/etw/setup.py',
  'py/etw_db/setup.py',
  'scripts/benchmark/setup.py',
  'scripts/graph/setup.py',
]
_SYZYGY_DIR = os.path.dirname(__file__)
_PYTHON = os.path.join(_SYZYGY_DIR, 'Debug/py/scripts/python.exe')


if not os.path.exists(_PYTHON):
  print 'The Python Debug virtual environment does not exist.'
  print 'Open the Syzygy solution and build the "virtualenv" target.'
  sys.exit(1)

for file in _SETUP_FILES:
  file = os.path.abspath(os.path.join(_SYZYGY_DIR, file))
  ret = subprocess.call([_PYTHON, file, 'develop'], cwd=os.path.dirname(file))
  if ret != 0:
    print 'Setup for file "%s" failed, return value %d' % (file, ret)
    sys.exit(ret)

sys.exit(0)

rem = """
:endofPython """
