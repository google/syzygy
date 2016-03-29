// Copyright 2015 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

// This file exports CrashForException, which is an optional API that
// instrumented processes may export (from their executable module) in order to
// handle SyzyASAN reports. The exit code from this method is used to verify
// SyzyASAN functionality in instrument_integration_test.cc .
//
// These are the exports that a Breakpad enabled binary provides. Both of these
// exports must be present for the RTL to decide to use this channel.

#include <windows.h>

extern "C" void __declspec(dllexport) SetCrashKeyValueImpl(
    const wchar_t* key, const wchar_t* value) {
  return;
}

extern "C" int __declspec(dllexport) CrashForException(
    EXCEPTION_POINTERS* info) {
  ::TerminateProcess(::GetCurrentProcess(), 99);
  return EXCEPTION_CONTINUE_SEARCH;
}
