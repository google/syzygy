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

:: TODO(manzagop): reimplement in python.

set SYZYGY_ROOT="%~dp0..\.."

:: Delete the old test_types.dll and the associated PDB file to ensure
:: old types don't linger.
del %SYZYGY_ROOT%\out\Release\test_types.dll
del %SYZYGY_ROOT%\out\Release\test_types.dll.pdb
del %SYZYGY_ROOT%\out\Release_x64\test_types.dll
del %SYZYGY_ROOT%\out\Release_x64\test_types.dll.pdb

del %SYZYGY_ROOT%\out\Release\test_typenames.dll
del %SYZYGY_ROOT%\out\Release\test_typenames.dll.pdb

del %SYZYGY_ROOT%\out\Release\test_vtables.dll
del %SYZYGY_ROOT%\out\Release\test_vtables.dll.pdb
del %SYZYGY_ROOT%\out\Release\test_vtables_omap.dll
del %SYZYGY_ROOT%\out\Release\test_vtables_omap.dll.pdb

:: Build a brand-spanking new version.
ninja -C %SYZYGY_ROOT%\out\Release test_types.dll
ninja -C %SYZYGY_ROOT%\out\Release_x64 test_types.dll

ninja -C %SYZYGY_ROOT%\out\Release test_typenames.dll

ninja -C %SYZYGY_ROOT%\out\Release test_vtables.dll

ninja -C %SYZYGY_ROOT%\out\Release relink
%SYZYGY_ROOT%\out\Release\relink.exe ^
  --input-image=%SYZYGY_ROOT%\out\Release\test_vtables.dll ^
  --output-image=%SYZYGY_ROOT%\out\Release\test_vtables_omap.dll ^
  --overwrite

:: And copy it, with it's associated PDB to the test_data directory.
copy /Y %SYZYGY_ROOT%\out\Release_x64\test_types.dll^
 "%~dp0test_data\test_types_x64.dll"
copy /Y %SYZYGY_ROOT%\out\Release_x64\test_types.dll.pdb^
 "%~dp0test_data\test_types_x64.dll.pdb"
copy /Y %SYZYGY_ROOT%\out\Release\test_types.dll "%~dp0test_data"
copy /Y %SYZYGY_ROOT%\out\Release\test_types.dll.pdb "%~dp0test_data"

copy /Y %SYZYGY_ROOT%\out\Release\test_typenames.dll "%~dp0test_data"
copy /Y %SYZYGY_ROOT%\out\Release\test_typenames.dll.pdb "%~dp0test_data"

copy /Y %SYZYGY_ROOT%\out\Release\test_vtables.dll "%~dp0test_data"
copy /Y %SYZYGY_ROOT%\out\Release\test_vtables.dll.pdb "%~dp0test_data"

copy /Y %SYZYGY_ROOT%\out\Release\test_vtables_omap.dll "%~dp0test_data"
copy /Y %SYZYGY_ROOT%\out\Release\test_vtables_omap.dll.pdb ^
  "%~dp0test_data"

set SYZYGY_ROOT=
