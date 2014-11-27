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

#include "syzygy/kasko/minidump.h"

#include <Windows.h>  // NOLINT
#include <Dbgeng.h>

#include "base/bind.h"
#include "base/callback.h"
#include "base/callback_helpers.h"
#include "base/files/file_path.h"
#include "base/files/scoped_temp_dir.h"
#include "base/win/scoped_comptr.h"
#include "gtest/gtest.h"

namespace kasko {

namespace {

void EndSession(IDebugClient* debug_client) {
  EXPECT_HRESULT_SUCCEEDED(
      debug_client->EndSession(DEBUG_END_ACTIVE_TERMINATE));
}

}  // namespace

TEST(MinidumpTest, GenerateAndLoad) {
  // Generate a minidump for the current process.
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  base::FilePath dump_file_path = temp_dir.path().Append(L"test.dump");
  ASSERT_TRUE(kasko::GenerateMinidump(dump_file_path, ::GetCurrentProcessId(),
                                      0, NULL));

  // Create a debugging client.
  base::win::ScopedComPtr<IDebugClient4> debug_client_4;
  base::win::ScopedComPtr<IDebugClient> debug_client;
  ASSERT_HRESULT_SUCCEEDED(
      DebugCreate(__uuidof(IDebugClient4), debug_client_4.ReceiveVoid()));
  ASSERT_HRESULT_SUCCEEDED(debug_client_4.QueryInterface(
      __uuidof(IDebugClient), debug_client.ReceiveVoid()));

  // Ask the debugger to open our dump file.
  ASSERT_HRESULT_SUCCEEDED(
      debug_client_4->OpenDumpFileWide(dump_file_path.value().c_str(), NULL));

  // Now that we have started a debugging session must ensure we will terminate
  // it when the test completes. Otherwise the dump file will remain open and we
  // won't be able to clean up our temporary directory.
  base::ScopedClosureRunner end_debugger_session(
      base::Bind(&EndSession, base::Unretained(debug_client.get())));

  // The following will block until the dump file has finished loading.
  base::win::ScopedComPtr<IDebugControl> debug_control;
  ASSERT_HRESULT_SUCCEEDED(debug_client_4.QueryInterface(
      __uuidof(IDebugControl), debug_control.ReceiveVoid()));
  ASSERT_HRESULT_SUCCEEDED(debug_control->WaitForEvent(0, INFINITE));

  // Simple sanity test that the dump contained the expected data.
  base::win::ScopedComPtr<IDebugSymbols> debug_symbols;
  ASSERT_HRESULT_SUCCEEDED(debug_client_4.QueryInterface(
      __uuidof(IDebugSymbols), debug_symbols.ReceiveVoid()));

  ASSERT_HRESULT_SUCCEEDED(
      debug_symbols->GetModuleByModuleName("kasko_unittests", 0, NULL, NULL));
}

}  // namespace kasko
