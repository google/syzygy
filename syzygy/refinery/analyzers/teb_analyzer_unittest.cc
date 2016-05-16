// Copyright 2016 Google Inc. All Rights Reserved.
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

#include "syzygy/refinery/analyzers/teb_analyzer.h"

#include <winnt.h>
#include <winternl.h>  // For _TEB.

#include <vector>

#include "gtest/gtest.h"
#include "syzygy/common/unittest_util.h"
#include "syzygy/refinery/unittest_util.h"
#include "syzygy/refinery/analyzers/analysis_runner.h"
#include "syzygy/refinery/analyzers/analyzer_util.h"
#include "syzygy/refinery/analyzers/memory_analyzer.h"
#include "syzygy/refinery/analyzers/module_analyzer.h"
#include "syzygy/refinery/process_state/process_state.h"
#include "syzygy/refinery/process_state/process_state_util.h"
#include "syzygy/refinery/symbols/symbol_provider.h"

namespace refinery {

namespace {

bool AnalyzeMinidump(const base::FilePath& minidump_path,
                     ProcessState* process_state) {
  minidump::FileMinidump minidump;
  if (!minidump.Open(minidump_path))
    return false;

  AnalysisRunner runner;
  runner.AddAnalyzer(
      std::move(std::unique_ptr<Analyzer>(new refinery::MemoryAnalyzer())));
  runner.AddAnalyzer(
      std::move(std::unique_ptr<Analyzer>(new refinery::ModuleAnalyzer())));
  runner.AddAnalyzer(
      std::move(std::unique_ptr<Analyzer>(new refinery::TebAnalyzer())));

  SimpleProcessAnalysis analysis(process_state);
  analysis.set_symbol_provider(new SymbolProvider());

  return runner.Analyze(minidump, analysis) == Analyzer::ANALYSIS_COMPLETE;
}

class TebAnalyzerTest : public testing::Test {
 public:
  void SetUp() override {
    ASSERT_NO_FATAL_FAILURE(testing::Test::SetUp());
    ASSERT_TRUE(scoped_symbol_path_.Setup());
  }

 private:
  testing::ScopedSymbolPath scoped_symbol_path_;
};

}  // namespace

TEST_F(TebAnalyzerTest, AnalyzeTeb) {
  testing::ScopedMinidump minidump;

  ASSERT_TRUE(
      minidump.GenerateMinidump(testing::ScopedMinidump::kMinidumpWithData));

  ProcessState process_state;
  ASSERT_TRUE(AnalyzeMinidump(minidump.minidump_path(), &process_state));

  TypedBlockLayerPtr typed_block_layer;
  ASSERT_TRUE(process_state.FindLayer(&typed_block_layer));

  Address teb_addr = reinterpret_cast<Address>(NtCurrentTeb());
  std::vector<TypedBlockRecordPtr> blocks;
  typed_block_layer->GetRecordsAt(teb_addr, &blocks);
  ASSERT_EQ(1u, blocks.size());

  TypedBlockRecordPtr teb_block = blocks[0];
  EXPECT_EQ("_TEB", teb_block->data().data_name());
  // The winternl.h TEB declaration exposes a subset of the structure.
  EXPECT_LE(sizeof(_TEB), teb_block->range().size());
}

}  // namespace refinery
