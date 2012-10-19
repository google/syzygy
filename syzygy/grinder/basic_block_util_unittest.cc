// Copyright 2012 Google Inc. All Rights Reserved.
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

#include "syzygy/grinder/basic_block_util.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/grinder/grinder.h"
#include "syzygy/pe/pe_file.h"
#include "syzygy/pe/unittest_util.h"

namespace grinder {
namespace basic_block_util {

namespace {

using testing::GetExeTestDataRelativePath;
using trace::parser::AbsoluteAddress64;
using trace::parser::Parser;

static const wchar_t kCoverageTraceFile[] = L"coverage_traces/trace-1.bin";
static const wchar_t kBbInstrumentedPdbName[] =
    L"basic_block_entry_instrumented_test_dll.pdb";

class TestGrinder : public GrinderInterface {
 public:
  TestGrinder() : parser_(NULL), on_bb_freq_was_called_(false) {
    // Nothing else to initialize.
  }

  // @name GrinderInterface implementation.
  // @{
  virtual bool ParseCommandLine(const CommandLine*) OVERRIDE { return true; }
  virtual void SetParser(Parser* parser) OVERRIDE {
    ASSERT_TRUE(parser != NULL);
    parser_ = parser;
  }
  virtual bool Grind() OVERRIDE { return true; };
  virtual bool OutputData(FILE*) OVERRIDE { return true; }
  // @}

  // @name ParseEventHandler overrides.
  // @{
  virtual void OnBasicBlockFrequency(
      base::Time time,
      DWORD process_id,
      DWORD thread_id,
      const TraceBasicBlockFrequencyData* data) OVERRIDE {
    on_bb_freq_was_called_ = true;
    ASSERT_TRUE(data != NULL);

    // Lookup the module information.
    const ModuleInformation* module_info = parser_->GetModuleInformation(
        process_id, AbsoluteAddress64(data->module_base_addr));
    ASSERT_TRUE(module_info != NULL);

    // Load the PDB information.
    PdbInfo* pdb_info = NULL;
    ASSERT_TRUE(LoadPdbInfo(&pdb_info_cache_, module_info, &pdb_info));
    ASSERT_TRUE(pdb_info != NULL);

    // Validate that the cache works.
    PdbInfo* dup_pdb_info = NULL;
    ASSERT_TRUE(LoadPdbInfo(&pdb_info_cache_, module_info, &dup_pdb_info));
    ASSERT_EQ(pdb_info, dup_pdb_info);
  }

  Parser* parser_;
  PdbInfoMap pdb_info_cache_;
  bool on_bb_freq_was_called_;
};

void PopulateModuleInformation(ModuleInformation* module_info) {
  ASSERT_TRUE(module_info != NULL);
  module_info->base_address = 0xDEADBEEF;
  module_info->image_checksum = 0xCAFEBABE;
  module_info->image_file_name = L"image_file_name";
  module_info->module_size = 0x12345678;
  module_info->time_date_stamp = 0x87654321;
}

}  // namespace

TEST(GrinderBasicBlockUtilTest, BasicBlockIdMap) {
  // Setup the basic-block range vector.
  RelativeAddressRangeVector bb_ranges;
  bb_ranges.reserve(5);
  bb_ranges.push_back(RelativeAddressRange(RelativeAddress(100), 100));
  bb_ranges.push_back(RelativeAddressRange(RelativeAddress(400), 100));
  bb_ranges.push_back(RelativeAddressRange(RelativeAddress(300), 100));
  bb_ranges.push_back(RelativeAddressRange(RelativeAddress(500), 100));
  bb_ranges.push_back(RelativeAddressRange(RelativeAddress(200), 100));

  // Setup the expected basic-block ID map.
  BasicBlockIdMap::ContainerType expected_map;
  expected_map.reserve(5);
  expected_map.push_back(BasicBlockIdMap::ValueType(RelativeAddress(100), 0));
  expected_map.push_back(BasicBlockIdMap::ValueType(RelativeAddress(200), 4));
  expected_map.push_back(BasicBlockIdMap::ValueType(RelativeAddress(300), 2));
  expected_map.push_back(BasicBlockIdMap::ValueType(RelativeAddress(400), 1));
  expected_map.push_back(BasicBlockIdMap::ValueType(RelativeAddress(500), 3));

  // Test Init(), Begin(), and End().
  BasicBlockIdMap bb_id_map;
  ASSERT_TRUE(bb_id_map.Init(bb_ranges));
  ASSERT_EQ(expected_map.size(), bb_id_map.Size());
  ASSERT_TRUE(
      std::equal(bb_id_map.Begin(), bb_id_map.End(), expected_map.begin()));

  // Test LowerBound().
  EXPECT_TRUE(
      bb_id_map.LowerBound(RelativeAddress(50)) == bb_id_map.Begin());
  EXPECT_TRUE(
      bb_id_map.LowerBound(RelativeAddress(200)) == ++bb_id_map.Begin());
  EXPECT_TRUE(
      bb_id_map.LowerBound(RelativeAddress(500)) == --bb_id_map.End());
  EXPECT_TRUE(
      bb_id_map.LowerBound(RelativeAddress(600)) == bb_id_map.End());

  // Test UpperBound().
  EXPECT_TRUE(
      bb_id_map.UpperBound(RelativeAddress(50)) == bb_id_map.Begin());
  EXPECT_TRUE(
      bb_id_map.UpperBound(RelativeAddress(200)) == ++(++bb_id_map.Begin()));
  EXPECT_TRUE(
      bb_id_map.UpperBound(RelativeAddress(500)) == bb_id_map.End());

  // Test Find().
  BasicBlockIdMap::BasicBlockId id = 0;
  EXPECT_TRUE(bb_id_map.Find(RelativeAddress(300), &id));
  EXPECT_EQ(2U, id);
  EXPECT_TRUE(bb_id_map.Find(RelativeAddress(500), &id));
  EXPECT_EQ(3U, id);
  EXPECT_FALSE(bb_id_map.Find(RelativeAddress(50), &id));
  EXPECT_FALSE(bb_id_map.Find(RelativeAddress(301), &id));
  EXPECT_FALSE(bb_id_map.Find(RelativeAddress(600), &id));

  // Test corner cases of Init() - Empty relative address range vector.
  bb_ranges.clear();
  EXPECT_TRUE(bb_id_map.Init(bb_ranges));
  EXPECT_EQ(0U, bb_id_map.Size());

  // Test error cases of Init() - Duplicate entry in bb_ranges.
  bb_ranges.push_back(RelativeAddressRange(RelativeAddress(100), 100));
  bb_ranges.push_back(RelativeAddressRange(RelativeAddress(100), 100));
  EXPECT_FALSE(bb_id_map.Init(bb_ranges));
}

TEST(GrinderBasicBlockUtilTest, InitModuleInfo) {
  // Create a prototype module info structure.
  ModuleInformation orig_module_info;
  EXPECT_NO_FATAL_FAILURE(PopulateModuleInformation(&orig_module_info));

  // Initialize a signature matching the prototype.
  pe::PEFile::Signature signature(orig_module_info);

  // Extract the module information from the signature. It should match the
  // prototype.
  ModuleInformation new_module_info;
  InitModuleInfo(signature, &new_module_info);
  EXPECT_EQ(orig_module_info, new_module_info);
}

TEST(GrinderBasicBlockUtilTest, FindEntryCountVector) {
  // Create a prototype module info structure.
  ModuleInformation module_info;
  EXPECT_NO_FATAL_FAILURE(PopulateModuleInformation(&module_info));

  // Initialize a signature matching the module_info.
  pe::PEFile::Signature signature(module_info);

  // Create an empty entry count map.
  EntryCountMap entry_count_map;
  EXPECT_TRUE(entry_count_map.empty());

  // Search the empty map for the module..
  const EntryCountVector* entry_count_vector = NULL;
  EXPECT_FALSE(
      FindEntryCountVector(signature, entry_count_map, &entry_count_vector));
  EXPECT_EQ(NULL, entry_count_vector);

  // Insert a matching module and search again.
  const EntryCountVector* entry_count_vector_1 = &entry_count_map[module_info];
  EXPECT_TRUE(
      FindEntryCountVector(signature, entry_count_map, &entry_count_vector));
  EXPECT_EQ(entry_count_vector_1, entry_count_vector);

  // Insert a second matching module and search again. This shoudl fail.
  module_info.image_file_name = L"Some other file name";
  const EntryCountVector* entry_count_vector_2 = &entry_count_map[module_info];
  ASSERT_NE(entry_count_vector_1, entry_count_vector_2);
  EXPECT_FALSE(
      FindEntryCountVector(signature, entry_count_map, &entry_count_vector));
  EXPECT_EQ(NULL, entry_count_vector);
}

TEST(GrinderBasicBlockUtilTest, LoadBasicBlockRanges) {
  RelativeAddressRangeVector bb_ranges;

  FilePath wrong_file_type(GetExeTestDataRelativePath(kCoverageTraceFile));
  EXPECT_FALSE(LoadBasicBlockRanges(wrong_file_type, &bb_ranges));

  FilePath wrong_pdb(
      GetExeTestDataRelativePath(testing::PELibUnitTest::kDllPdbName));
  EXPECT_FALSE(LoadBasicBlockRanges(wrong_pdb, &bb_ranges));

  FilePath right_pdb(GetExeTestDataRelativePath(kBbInstrumentedPdbName));
  EXPECT_TRUE(LoadBasicBlockRanges(right_pdb, &bb_ranges));
}

TEST(GrinderBasicBlockUtilTest, LoadPdbInfo) {
  // TODO(rogerm): Rewrite me! This test doesn't directly test LoadPdbInfo.
  Parser parser;
  TestGrinder grinder;
  ASSERT_TRUE(parser.Init(&grinder));
  ASSERT_NO_FATAL_FAILURE(grinder.SetParser(&parser));
  ASSERT_TRUE(grinder.ParseCommandLine(NULL));
  ASSERT_TRUE(
      parser.OpenTraceFile(GetExeTestDataRelativePath(kCoverageTraceFile)));
  ASSERT_TRUE(parser.Consume());
  ASSERT_TRUE(grinder.on_bb_freq_was_called_);
  ASSERT_TRUE(grinder.Grind());
  ASSERT_TRUE(grinder.OutputData(NULL));
}

TEST(GrinderBasicBlockUtilTest, IsValidFrequencySize) {
  EXPECT_TRUE(IsValidFrequencySize(1));
  EXPECT_TRUE(IsValidFrequencySize(2));
  EXPECT_TRUE(IsValidFrequencySize(4));

  EXPECT_FALSE(IsValidFrequencySize(0));
  EXPECT_FALSE(IsValidFrequencySize(3));
  EXPECT_FALSE(IsValidFrequencySize(8));
  EXPECT_FALSE(IsValidFrequencySize(65536));
}

TEST(GrinderBasicBlockUtilTest, GetFrequency) {
  // Counter data we'll test against.
  static const uint8 kData[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                                 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB };

  // A buffer over which we'll overlay a TraceBasicBlockFrequencyData struct.
  uint8 buffer[sizeof(TraceBasicBlockFrequencyData) + sizeof(kData) - 1] = {};
  ::memset(buffer, 0, sizeof(buffer));

  // A TraceDataBlockFrequencyData structure with the frequency_data populated
  // with a copy of kData.
  TraceBasicBlockFrequencyData* data =
      reinterpret_cast<TraceBasicBlockFrequencyData*>(buffer);
  ::memcpy(data->frequency_data, kData, sizeof(kData));

  // Validate 1-byte frequency data.
  data->frequency_size = 1;
  data->num_basic_blocks = sizeof(kData) / data->frequency_size;
  EXPECT_EQ(0x44, GetFrequency(data, 0x4));
  EXPECT_EQ(0xAA, GetFrequency(data, 0xA));

  // Validate 2-byte frequency data.
  data->frequency_size = 2;
  data->num_basic_blocks = sizeof(kData) / data->frequency_size;
  EXPECT_EQ(0x5544, GetFrequency(data, 0x2));
  EXPECT_EQ(0x9988, GetFrequency(data, 0x4));

  // Validate 4-byte frequency data.
  data->frequency_size = 4;
  data->num_basic_blocks = sizeof(kData) / data->frequency_size;
  EXPECT_EQ(0x33221100, GetFrequency(data, 0x0));
  EXPECT_EQ(0xBBAA9988, GetFrequency(data, 0x2));
}

}  // namespace basic_block_util
}  // namespace grinder
