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

// This file exports ReportCrashWithProtobuf, which is an optional API that
// instrumented processes may export (from their executable module) in order to
// handle SyzyASAN reports. The exit code from this method is used to verify
// SyzyASAN functionality in instrument_integration_test.cc .
//
// This export, along with SetCrashKeyValueImpl, is expected of a Kasko crash
// reporter enabled binary. If either ReportCrashWithProtobuf or
// ReportCrashWithProtobufAndMemoryRanges is available, the RTL will use these
// preferentially rather than the Breakpad exports provided by
// crash_for_exception_export.cc .

#include <windows.h>

#include "base/environment.h"
#include "syzygy/crashdata/crashdata.h"
#include "syzygy/crashdata/json.h"

void Exit(UINT code) {
  ::TerminateProcess(::GetCurrentProcess(), code);
}

extern "C" void __declspec(dllexport)
    ReportCrashWithProtobuf(EXCEPTION_POINTERS* info,
                            const char* protobuf,
                            size_t protobuf_length) {
  // Bail if there was no protobuf.
  if (protobuf == nullptr || protobuf_length == 0)
    Exit(97);

  // Parse the protobuf and bail if that fails.
  crashdata::Value value;
  if (!value.ParseFromArray(protobuf, protobuf_length))
    ::Exit(97);

  // A useful debugging hack.
  std::unique_ptr<base::Environment> env(base::Environment::Create());
  if (env->HasVar("SYZYGY_ASAN_DUMP_PROTOBUF_ON_CRASH")) {
    std::string json;
    crashdata::ToJson(true, &value, &json);
    ::printf("%s", json.c_str());
  }

  Exit(98);
}
