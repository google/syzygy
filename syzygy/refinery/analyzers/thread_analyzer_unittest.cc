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

#include "syzygy/refinery/analyzers/thread_analyzer.h"

#include <stdint.h>

#include "base/file_util.h"
#include "base/files/file.h"
#include "base/files/file_path.h"
#include "base/files/scoped_temp_dir.h"
#include "base/process/process.h"
#include "base/process/process_handle.h"
#include "gtest/gtest.h"
#include "syzygy/refinery/minidump/minidump.h"
#include "syzygy/refinery/process_state/process_state.h"

namespace refinery {

namespace {

class AnalysisTest : public testing::Test {
 public:
  void SetUp() override {
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());

    dump_file_ = temp_dir_.path().Append(L"minidump.dmp");
    ASSERT_TRUE(CreateDump());
  }

  bool CreateDump() {
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

  const base::FilePath& dump_file() const { return dump_file_; }

 private:
  base::FilePath dump_file_;
  base::ScopedTempDir temp_dir_;
};

}  // namespace

TEST_F(AnalysisTest, Basic) {
  Minidump minidump;
  ASSERT_TRUE(minidump.Open(dump_file()));
  ProcessState process_state;

  ThreadAnalyzer analyzer;
  ASSERT_EQ(Analyzer::ANALYSIS_COMPLETE,
            analyzer.Analyze(minidump, &process_state));

  scoped_refptr<ProcessState::Layer<Stack>> stack_layer;
  ASSERT_TRUE(process_state.FindLayer(&stack_layer));

  // TODO(siggi): Flesh out layer so that it can be enumerated in some way for
  //     more elaborate testing.
}

}  // namespace refinery
