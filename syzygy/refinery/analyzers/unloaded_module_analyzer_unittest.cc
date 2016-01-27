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

#include "syzygy/refinery/analyzers/unloaded_module_analyzer.h"

#include <stdint.h>

#include <vector>

#include "base/files/scoped_temp_dir.h"
#include "gtest/gtest.h"
#include "syzygy/minidump/minidump.h"
#include "syzygy/minidump/unittest_util.h"
#include "syzygy/refinery/analyzers/analyzer_util.h"
#include "syzygy/refinery/process_state/process_state.h"
#include "syzygy/refinery/process_state/process_state_util.h"
#include "syzygy/refinery/process_state/refinery.pb.h"

namespace refinery {

TEST(UnloadedModuleAnalyzerTest, AnalyzeMinidump) {
  minidump::FileMinidump minidump;
  ASSERT_TRUE(minidump.Open(testing::TestMinidumps::GetNotepad32Dump()));

  ProcessState process_state;
  SimpleProcessAnalysis analysis(&process_state);

  UnloadedModuleAnalyzer analyzer;
  ASSERT_EQ(Analyzer::ANALYSIS_COMPLETE, analyzer.Analyze(minidump, analysis));

  // TODO(manzagop): implement testing once UnloadedModuleAnalyzer is
  // implemented.
}

TEST(UnloadedModuleAnalyzerTest, AnalyzeSyntheticMinidump) {
  // TODO(manzagop): implement testing once UnloadedModuleAnalyzer is
  // implemented.
}

}  // namespace refinery
