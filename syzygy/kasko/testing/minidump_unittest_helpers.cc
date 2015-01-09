// Copyright 2014 Google Inc. All Rights Reserved.
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

#include "syzygy/kasko/testing/minidump_unittest_helpers.h"

#include "base/bind.h"
#include "base/callback.h"
#include "base/callback_helpers.h"
#include "base/logging.h"
#include "base/files/file_path.h"
#include "base/win/scoped_comptr.h"
#include "syzygy/common/com_utils.h"

namespace kasko {
namespace testing {
namespace {

void EndSession(IDebugClient* debug_client) {
  HRESULT result = debug_client->EndSession(DEBUG_END_ACTIVE_TERMINATE);
  DCHECK(SUCCEEDED(result)) << "EndSession failed: " << ::common::LogHr(result);
}

}  // namespace

HRESULT VisitMinidump(const base::FilePath& path,
                      const MinidumpVisitor& visitor) {
  // Create a debugging client.
  base::win::ScopedComPtr<IDebugClient4> debug_client_4;
  base::win::ScopedComPtr<IDebugClient> debug_client;
  HRESULT result =
      ::DebugCreate(__uuidof(IDebugClient4), debug_client_4.ReceiveVoid());
  if (!SUCCEEDED(result)) {
    LOG(ERROR) << "DebugCreate failed: " << ::common::LogHr(result);
    return result;
  }

  result = debug_client_4.QueryInterface(__uuidof(IDebugClient),
                                         debug_client.ReceiveVoid());
  if (!SUCCEEDED(result)) {
    LOG(ERROR) << "QI(IDebugClient) failed: " << ::common::LogHr(result);
    return result;
  }

  // Ask the debugger to open our dump file.
  result = debug_client_4->OpenDumpFileWide(path.value().c_str(), NULL);
  if (!SUCCEEDED(result)) {
    LOG(ERROR) << "OpenDumpFileWide failed: " << ::common::LogHr(result);
    return result;
  }

  // Now that we have started a debugging session must ensure we will terminate
  // it when the test completes. Otherwise the dump file will remain open and we
  // won't be able to clean up our temporary directory.
  base::ScopedClosureRunner end_debugger_session(
      base::Bind(&EndSession, base::Unretained(debug_client.get())));

  // The following will block until the dump file has finished loading.
  base::win::ScopedComPtr<IDebugControl> debug_control;
  result = debug_client_4.QueryInterface(__uuidof(IDebugControl),
                                         debug_control.ReceiveVoid());
  if (!SUCCEEDED(result)) {
    LOG(ERROR) << "QI(IDebugControl) failed: " << ::common::LogHr(result);
    return result;
  }

  result = debug_control->WaitForEvent(0, INFINITE);
  if (!SUCCEEDED(result)) {
    LOG(ERROR) << "WaitForEvent failed: " << ::common::LogHr(result);
    return result;
  }

  base::win::ScopedComPtr<IDebugSymbols> debug_symbols;
  result = debug_client_4.QueryInterface(__uuidof(IDebugSymbols),
                                         debug_symbols.ReceiveVoid());
  if (!SUCCEEDED(result)) {
    LOG(ERROR) << "QI(IDebugSymbols) failed: " << ::common::LogHr(result);
    return result;
  }

  IDebugClient4* dc4 = debug_client_4.get();
  visitor.Run(dc4, debug_control.get(), debug_symbols.get());
  return S_OK;
}

}  // namespace testing
}  // namespace kasko
