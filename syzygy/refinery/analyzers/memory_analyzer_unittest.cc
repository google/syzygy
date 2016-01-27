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

#include "syzygy/refinery/analyzers/memory_analyzer.h"

#include <stdint.h>

#include <vector>

#include "base/files/scoped_temp_dir.h"
#include "gtest/gtest.h"
#include "syzygy/minidump/minidump.h"
#include "syzygy/minidump/unittest_util.h"
#include "syzygy/refinery/unittest_util.h"
#include "syzygy/refinery/analyzers/analyzer_util.h"
#include "syzygy/refinery/process_state/process_state.h"
#include "syzygy/refinery/process_state/process_state_util.h"
#include "syzygy/refinery/process_state/refinery.pb.h"

namespace refinery {

TEST(MemoryAnalyzerTest, AnalyzeMinidump) {
  minidump::FileMinidump minidump;
  ASSERT_TRUE(minidump.Open(testing::TestMinidumps::GetNotepad32Dump()));

  ProcessState process_state;
  SimpleProcessAnalysis analysis(&process_state);
  MemoryAnalyzer analyzer;
  ASSERT_EQ(Analyzer::ANALYSIS_COMPLETE, analyzer.Analyze(minidump, analysis));

  scoped_refptr<ProcessState::Layer<Bytes>> bytes_layer;
  ASSERT_TRUE(process_state.FindLayer(&bytes_layer));
  ASSERT_LE(1, bytes_layer->size());
}

class MemoryAnalyzerSyntheticTest : public testing::SyntheticMinidumpTest {
 protected:
  using MemorySpecification =
      testing::MinidumpSpecification::MemorySpecification;
  using MinidumpSpecification = testing::MinidumpSpecification;

  static const char kDataFirst[];
  static const char kDataSecond[];
};

const char MemoryAnalyzerSyntheticTest::kDataFirst[] = "ABCD";
const char MemoryAnalyzerSyntheticTest::kDataSecond[] = "EFGHI";

TEST_F(MemoryAnalyzerSyntheticTest, BasicTest) {
  MinidumpSpecification spec;
  ASSERT_TRUE(spec.AddMemoryRegion(MemorySpecification(80ULL, kDataFirst)));
  ASSERT_TRUE(spec.AddMemoryRegion(MemorySpecification(88ULL, kDataSecond)));
  ASSERT_NO_FATAL_FAILURE(Serialize(spec));

  // Analyze.
  minidump::FileMinidump minidump;
  ASSERT_TRUE(minidump.Open(dump_file()));

  ProcessState process_state;
  SimpleProcessAnalysis analysis(&process_state);
  MemoryAnalyzer analyzer;
  ASSERT_EQ(Analyzer::ANALYSIS_COMPLETE, analyzer.Analyze(minidump, analysis));

  // Validate analysis.
  BytesLayerPtr bytes_layer;
  ASSERT_TRUE(process_state.FindLayer(&bytes_layer));
  EXPECT_EQ(2, bytes_layer->size());

  std::vector<BytesRecordPtr> matching_records;

  // Retrieve first memory region.
  {
    bytes_layer->GetRecordsAt(80ULL, &matching_records);
    ASSERT_EQ(1, matching_records.size());
    EXPECT_EQ(AddressRange(80ULL, sizeof(kDataFirst) - 1),
              matching_records[0]->range());
    const Bytes& bytes = matching_records[0]->data();
    EXPECT_EQ(kDataFirst, bytes.data());
  }

  // Retrieve second memory region.
  {
    bytes_layer->GetRecordsAt(88ULL, &matching_records);
    ASSERT_EQ(1, matching_records.size());
    EXPECT_EQ(AddressRange(88ULL, sizeof(kDataSecond) - 1),
              matching_records[0]->range());
    const Bytes& bytes = matching_records[0]->data();
    EXPECT_EQ(kDataSecond, bytes.data());
  }
}

TEST_F(MemoryAnalyzerSyntheticTest, OverlappingRangesAreConsolidated) {
  MinidumpSpecification spec(MinidumpSpecification::ALLOW_MEMORY_OVERLAP);

  // Overlap at start.
  ASSERT_TRUE(spec.AddMemoryRegion(MemorySpecification(84ULL, kDataFirst)));
  ASSERT_TRUE(spec.AddMemoryRegion(MemorySpecification(86ULL, kDataSecond)));

  // Overlap at end.
  ASSERT_TRUE(spec.AddMemoryRegion(MemorySpecification(106ULL, kDataFirst)));
  ASSERT_TRUE(spec.AddMemoryRegion(MemorySpecification(103ULL, kDataSecond)));

  // Overlap at both ends.
  ASSERT_TRUE(
      spec.AddMemoryRegion(MemorySpecification(206ULL, "ABCDEFGHIJKLM")));
  ASSERT_TRUE(spec.AddMemoryRegion(MemorySpecification(209ULL, kDataFirst)));

  ASSERT_NO_FATAL_FAILURE(Serialize(spec));

  // Analyze.
  minidump::FileMinidump minidump;
  ASSERT_TRUE(minidump.Open(dump_file()));

  ProcessState process_state;
  SimpleProcessAnalysis analysis(&process_state);
  MemoryAnalyzer analyzer;
  ASSERT_EQ(Analyzer::ANALYSIS_COMPLETE, analyzer.Analyze(minidump, analysis));

  // Validate analysis.
  BytesLayerPtr bytes_layer;
  ASSERT_TRUE(process_state.FindLayer(&bytes_layer));
  EXPECT_EQ(3, bytes_layer->size());

  std::vector<BytesRecordPtr> matching_records;

  // Retrieve first memory region.
  {
    bytes_layer->GetRecordsAt(84ULL, &matching_records);
    ASSERT_EQ(1, matching_records.size());
    static const char kExpectedData[] = "ABEFGHI";
    EXPECT_EQ(AddressRange(84ULL, sizeof(kExpectedData) - 1),
              matching_records[0]->range());
    const Bytes& bytes = matching_records[0]->data();
    EXPECT_EQ(kExpectedData, bytes.data());
  }

  // Retrieve second memory region.
  {
    bytes_layer->GetRecordsAt(103, &matching_records);
    ASSERT_EQ(1, matching_records.size());
    static const char kExpectedData[] = "EFGHICD";
    EXPECT_EQ(AddressRange(103ULL, sizeof(kExpectedData) - 1),
              matching_records[0]->range());
    const Bytes& bytes = matching_records[0]->data();
    EXPECT_EQ(kExpectedData, bytes.data());
  }

  // Retrieve third memory region.
  {
    bytes_layer->GetRecordsAt(206, &matching_records);
    ASSERT_EQ(1, matching_records.size());
    static const char kExpectedData[] = "ABCABCDHIJKLM";
    EXPECT_EQ(AddressRange(206ULL, sizeof(kExpectedData) - 1),
              matching_records[0]->range());
    const Bytes& bytes = matching_records[0]->data();
    EXPECT_EQ(kExpectedData, bytes.data());
  }
}

}  // namespace refinery
