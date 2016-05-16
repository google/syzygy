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

#include "syzygy/refinery/analyzers/heap_analyzer.h"

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
      std::move(std::unique_ptr<Analyzer>(new refinery::HeapAnalyzer())));

  SimpleProcessAnalysis analysis(process_state);
  analysis.set_symbol_provider(new SymbolProvider());

  return runner.Analyze(minidump, analysis) == Analyzer::ANALYSIS_COMPLETE;
}

class HeapAnalyzerTest : public testing::Test {
 public:
  void SetUp() override {
    ASSERT_TRUE(scoped_symbol_path_.Setup());
  }

 private:
  testing::ScopedSymbolPath scoped_symbol_path_;
};

}  // namespace

TEST_F(HeapAnalyzerTest, AnalyzeHeap) {
  if (testing::IsAppVerifierActive()) {
    LOG(WARNING) << "HeapAnalyzerTest.AnalyzeHeap is incompatible with AV.";
    return;
  }

  testing::ScopedMinidump minidump;
  testing::ScopedHeap heap;

  ASSERT_TRUE(heap.Create());

  const size_t kBlockSize = 19;
  void* lfh_block = nullptr;
  void* free_lfh_block = nullptr;
  for (size_t tries = 0; tries < 1000 && !lfh_block; ++tries) {
    void* block = heap.Allocate(kBlockSize);
    if (heap.IsLFHBlock(block)) {
      // Grab one block to free later first.
      if (free_lfh_block == nullptr)
        free_lfh_block = block;
      else
        lfh_block = block;
    }
  }
  ASSERT_TRUE(free_lfh_block);
  ASSERT_TRUE(lfh_block);
  heap.Free(free_lfh_block);

  ASSERT_TRUE(
      minidump.GenerateMinidump(testing::ScopedMinidump::kMinidumpWithData));
  ProcessState process_state;
  ASSERT_TRUE(AnalyzeMinidump(minidump.minidump_path(), &process_state));

  // Find the lfh_block allocation.
  HeapAllocationLayerPtr alloc_layer;
  ASSERT_TRUE(process_state.FindLayer(&alloc_layer));
  std::vector<HeapAllocationRecordPtr> alloc_records;
  alloc_layer->GetRecordsAt(testing::ToAddress(lfh_block), &alloc_records);
  ASSERT_EQ(1U, alloc_records.size());
  ASSERT_EQ(kBlockSize, alloc_records[0]->range().size());
  ASSERT_FALSE(alloc_records[0]->data().is_free());

  // Find the free_lfh_block allocation.
  alloc_layer->GetRecordsAt(testing::ToAddress(free_lfh_block), &alloc_records);
  ASSERT_EQ(1U, alloc_records.size());
  ASSERT_LE(kBlockSize, alloc_records[0]->range().size());
  ASSERT_TRUE(alloc_records[0]->data().is_free());

  // Find the heap entry preceding the allocation.
  HeapMetadataLayerPtr heap_meta_layer;
  ASSERT_TRUE(process_state.FindLayer(&heap_meta_layer));
  std::vector<HeapMetadataRecordPtr> heap_meta_records;
  heap_meta_layer->GetRecordsIntersecting(
      AddressRange(testing::ToAddress(lfh_block) - 1, 1), &heap_meta_records);
  ASSERT_EQ(1U, heap_meta_records.size());
  ASSERT_FALSE(heap_meta_records[0]->data().corrupt());

  // Find the heap entry preceding the freed allocation.
  heap_meta_layer->GetRecordsIntersecting(
      AddressRange(testing::ToAddress(free_lfh_block) - 1, 1),
      &heap_meta_records);
  ASSERT_EQ(1U, heap_meta_records.size());
  ASSERT_FALSE(heap_meta_records[0]->data().corrupt());
}

// TODO(siggi): Test corruption etc.

}  // namespace refinery
