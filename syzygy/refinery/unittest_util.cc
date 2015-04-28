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

#include "syzygy/refinery/unittest_util.h"

#include <Windows.h>  // NOLINT
#include <dbghelp.h>

#include "base/files/file.h"
#include "base/files/file_path.h"
#include "base/files/scoped_temp_dir.h"
#include "base/process/process.h"
#include "base/process/process_handle.h"

namespace testing {

void MinidumpTest::SetUp() {
  ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());

  dump_file_ = temp_dir_.path().Append(L"minidump.dmp");
}

bool MinidumpTest::CreateDump() {
  base::File dump_file;
  dump_file.Initialize(
      dump_file_, base::File::FLAG_CREATE | base::File::FLAG_WRITE);
  if (!dump_file.IsValid())
    return false;

  return ::MiniDumpWriteDump(base::GetCurrentProcessHandle(),
                             base::GetCurrentProcId(),
                             dump_file.GetPlatformFile(),
                             MiniDumpNormal,
                             nullptr,
                             nullptr,
                             nullptr) == TRUE;
}

}  // namespace testing
