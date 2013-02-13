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
  virtual void OnIndexedFrequency(
      base::Time time,
      DWORD process_id,
      DWORD thread_id,
      const TraceIndexedFrequencyData* data) OVERRIDE {
    on_bb_freq_was_called_ = true;
    ASSERT_TRUE(data != NULL);

    // Lookup the module information.
    const ModuleInformation* module_info = parser_->GetModuleInformation(
        process_id, AbsoluteAddress64(data->module_base_addr));
    ASSERT_TRUE(module_info != NULL);

    // Load the PDB information.
    PdbInfo* pdb_info = NULL;
    ASSERT_TRUE(LoadPdbInfo(&pdb_info_cache_, *module_info, &pdb_info));
    ASSERT_TRUE(pdb_info != NULL);

    // Validate that the cache works.
    PdbInfo* dup_pdb_info = NULL;
    ASSERT_TRUE(LoadPdbInfo(&pdb_info_cache_, *module_info, &dup_pdb_info));
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

TEST(GrinderBasicBlockUtilTest, ModuleIdentityComparator) {
  ModuleInformation a;
  PopulateModuleInformation(&a);

  ModuleInformation b = a;
  ModuleIdentityComparator comp;
  // The two should compare equal.
  EXPECT_FALSE(comp(a, b));
  EXPECT_FALSE(comp(b, a));

  // Jiggle b's base address and checksum.
  b.base_address -= 10;
  b.image_checksum += 100;
  // The two should still compare equal.
  EXPECT_FALSE(comp(a, b));
  EXPECT_FALSE(comp(b, a));

  b = a;
  b.module_size -= 1;
  EXPECT_FALSE(comp(a, b));
  EXPECT_TRUE(comp(b, a));

  b = a;
  b.time_date_stamp += 1;
  EXPECT_TRUE(comp(a, b));
  EXPECT_FALSE(comp(b, a));

  b = a;
  b.image_file_name = L"foo";
  EXPECT_FALSE(comp(a, b));
  EXPECT_TRUE(comp(b, a));
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
  ModuleEntryCountMap module_entry_count_map;
  EXPECT_TRUE(module_entry_count_map.empty());

  // Search the empty map for the module..
  const EntryCountMap* entry_count_map = NULL;
  EXPECT_FALSE(
      FindEntryCountMap(signature, module_entry_count_map, &entry_count_map));
  EXPECT_EQ(NULL, entry_count_map);

  // Insert a matching module and search again.
  const EntryCountMap* entry_count_map_1 = &module_entry_count_map[module_info];
  EXPECT_TRUE(
      FindEntryCountMap(signature, module_entry_count_map, &entry_count_map));
  EXPECT_EQ(entry_count_map_1, entry_count_map);

  // Insert a second matching module and search again. This should fail.
  module_info.image_file_name = L"Some other file name";
  const EntryCountMap* entry_count_map_2 = &module_entry_count_map[module_info];
  ASSERT_NE(entry_count_map_1, entry_count_map_2);
  EXPECT_FALSE(
      FindEntryCountMap(signature, module_entry_count_map, &entry_count_map));
  EXPECT_EQ(NULL, entry_count_map);
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

  // A buffer over which we'll overlay a TraceIndexedFrequencyData struct.
  uint8 buffer[sizeof(TraceIndexedFrequencyData) + sizeof(kData) - 1] = {};
  ::memset(buffer, 0, sizeof(buffer));

  // A TraceDataBlockFrequencyData structure with the frequency_data populated
  // with a copy of kData.
  TraceIndexedFrequencyData* data =
      reinterpret_cast<TraceIndexedFrequencyData*>(buffer);
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
