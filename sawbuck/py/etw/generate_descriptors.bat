:: Copyright 2010 Google Inc.
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
@echo off

:: Image load events
python generate_descriptor.py -g {2cb15d1d-5fc1-11d2-abe1-00a0c911f518} -o etw\descriptors

:: Page fault events
python generate_descriptor.py -g {3d6fa8d3-fe05-11d0-9dda-00c04fd7ba7c} -o etw\descriptors

:: Process events
python generate_descriptor.py -g {3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c} -o etw\descriptors

:: Thread events
python generate_descriptor.py -g {3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c} -o etw\descriptors

:: Registry events
python generate_descriptor.py -g {ae53722e-c863-11d2-8659-00c04fa321a1} -o etw\descriptors

:: File Io events
python generate_descriptor.py -g {90cbdc39-4a3e-11d1-84f4-0000f80464e3} -o etw\descriptors

