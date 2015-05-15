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

#include "syzygy/refinery/analyzers/exception_analyzer.h"

#include <stdint.h>

#include <vector>

#include "base/files/scoped_temp_dir.h"
#include "gtest/gtest.h"
#include "syzygy/refinery/unittest_util.h"
#include "syzygy/refinery/minidump/minidump.h"
#include "syzygy/refinery/process_state/process_state.h"
#include "syzygy/refinery/process_state/process_state_util.h"
#include "syzygy/refinery/process_state/refinery.pb.h"

namespace refinery {

TEST(ExceptionAnalyzerTest, AnalyzeMinidump) {
  Minidump minidump;
  ASSERT_TRUE(minidump.Open(testing::TestMinidumps::GetNotepad32Dump()));

  ProcessState process_state;

  ExceptionAnalyzer analyzer;
  ASSERT_EQ(Analyzer::ANALYSIS_COMPLETE,
            analyzer.Analyze(minidump, &process_state));

  // TODO(manzagop): implement testing once ExceptionAnalyzer is implemented.
}

TEST(ExceptionAnalyzerTest, AnalyzeSyntheticMinidump) {
  // TODO(manzagop): implement testing once ExceptionAnalyzer is implemented.
}

}  // namespace refinery
