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

#include "syzygy/grinder/basic_block_entry_count_grinder.h"

#include "base/file_util.h"
#include "base/scoped_temp_dir.h"
#include "base/values.h"
#include "base/json/json_reader.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/common/syzygy_version.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/metadata.h"
#include "syzygy/pe/unittest_util.h"

namespace grinder {

namespace {

using base::DictionaryValue;
using base::ListValue;
using base::Value;
using basic_block_util::EntryCountMap;
using basic_block_util::EntryCountType;
using basic_block_util::EntryCountVector;
using basic_block_util::IsValidFrequencySize;
using basic_block_util::ModuleInformation;
using common::kSyzygyVersion;
using file_util::CreateAndOpenTemporaryFileInDir;

const wchar_t kBasicBlockEntryTraceFile[] =
    L"basic_block_entry_traces/trace-1.bin";
const wchar_t kCoverageTraceFile[] = L"coverage_traces/trace-1.bin";
const wchar_t kImageFileName[] = L"foo.dll";
const uint32 kBaseAddress = 0xDEADBEEF;
const uint32 kModuleSize = 0x1000;
const uint32 kImageChecksum = 0xCAFEBABE;
const uint32 kTimeDateStamp = 0xBABECAFE;

class TestBasicBlockEntryCountGrinder : public BasicBlockEntryCountGrinder {
 public:
  using BasicBlockEntryCountGrinder::UpdateBasicBlockEntryCount;
  using BasicBlockEntryCountGrinder::parser_;
};

class BasicBlockEntryCountGrinderTest : public testing::PELibUnitTest {
 public:
  typedef testing::PELibUnitTest Super;

  BasicBlockEntryCountGrinderTest()
      : cmd_line_(FilePath(L"basic_block_entry_count_grinder.exe")) {
  }

  virtual void SetUp() OVERRIDE {
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
  }

  void InitParser(trace::parser::ParseEventHandlerImpl* handler,
                  const wchar_t* file_path) {
    ASSERT_TRUE(handler != NULL);
    ASSERT_TRUE(parser_.Init(handler));
    FilePath trace_file(testing::GetExeTestDataRelativePath(file_path));
    ASSERT_TRUE(parser_.OpenTraceFile(trace_file));
  }


  void RunGrinderTest(const wchar_t* trace_file,
                      EntryCountMap* entry_counts) {
    ASSERT_TRUE(trace_file != NULL);
    ASSERT_TRUE(entry_counts != NULL);
    FilePath json_path;
    ASSERT_NO_FATAL_FAILURE(GrindTraceFileToJson(trace_file, &json_path));
    ASSERT_NO_FATAL_FAILURE(LoadJson(json_path, entry_counts));
  }

  void GrindTraceFileToJson(const wchar_t* trace_file,
                            FilePath* json_path) {
    ASSERT_TRUE(trace_file != NULL);
    ASSERT_TRUE(json_path != NULL);

    json_path->clear();

    // Consume the the trace file.
    TestBasicBlockEntryCountGrinder grinder;
    cmd_line_.AppendSwitch("pretty-print");
    grinder.ParseCommandLine(&cmd_line_);
    ASSERT_NO_FATAL_FAILURE(InitParser(&grinder, trace_file));
    grinder.SetParser(&parser_);
    ASSERT_TRUE(parser_.Consume());

    // Grind and output the data to a JSON file.
    FilePath temp_path;
    file_util::ScopedFILE json_file(
        CreateAndOpenTemporaryFileInDir(temp_dir_.path(), &temp_path));
    ASSERT_TRUE(json_file.get() != NULL);
    ASSERT_TRUE(grinder.Grind());
    ASSERT_TRUE(grinder.OutputData(json_file.get()));
    *json_path = temp_path;
  }

  void LoadJson(const FilePath& json_path, EntryCountMap* entry_counts) {
    ASSERT_TRUE(!json_path.empty());
    ASSERT_TRUE(entry_counts != NULL);

    BasicBlockEntryCountSerializer serializer;
    ASSERT_TRUE(serializer.LoadFromJson(json_path, entry_counts));
  }

  void InitModuleInfo(ModuleInformation* module_info) {
    ASSERT_TRUE(module_info != NULL);
    module_info->image_file_name = kImageFileName;
    module_info->base_address = kBaseAddress;
    module_info->module_size = kModuleSize;
    module_info->image_checksum = kImageChecksum;
    module_info->time_date_stamp = kTimeDateStamp;
  }

  void GetFrequencyData(const ModuleInformation& module_info,
                        size_t frequency_size,
                        scoped_ptr<TraceBasicBlockFrequencyData>* data) {
    ASSERT_TRUE(IsValidFrequencySize(frequency_size));
    ASSERT_TRUE(data != NULL);

    static const size_t kNumBasicBlocks = 5;
    static const size_t kMaxDataSize = kNumBasicBlocks * sizeof(uint32);
    static const size_t kBufferSize =
        sizeof(TraceBasicBlockFrequencyData) + kMaxDataSize - 1;

    uint8* buffer = new uint8[kBufferSize];
    ASSERT_TRUE(buffer != NULL);
    ::memset(buffer, 0, kBufferSize);

    data->reset(reinterpret_cast<TraceBasicBlockFrequencyData*>(buffer));
    (*data)->module_base_addr =
        reinterpret_cast<ModuleAddr>(module_info.base_address);
    (*data)->module_base_size = module_info.module_size;
    (*data)->module_checksum = module_info.image_checksum;
    (*data)->module_time_date_stamp = module_info.time_date_stamp;
    (*data)->frequency_size = frequency_size;
    (*data)->num_basic_blocks = kNumBasicBlocks;

    for (size_t i = 0; i < kNumBasicBlocks; ++i) {
      uint8 value = i + 1;
      switch (frequency_size) {
        case 1:
          (*data)->frequency_data[i] = value;
          break;
        case 2:
          reinterpret_cast<uint16*>(&(*data)->frequency_data)[i] = value;
          break;
        case 4:
          reinterpret_cast<uint32*>(&(*data)->frequency_data)[i] = value;
          break;
      }
    }
  }

 protected:
  ScopedTempDir temp_dir_;
  CommandLine cmd_line_;
  trace::parser::Parser parser_;
};

}  // namespace

TEST_F(BasicBlockEntryCountGrinderTest, ParseCommandLineSucceeds) {
  TestBasicBlockEntryCountGrinder grinder1;
  EXPECT_TRUE(grinder1.ParseCommandLine(&cmd_line_));

  TestBasicBlockEntryCountGrinder grinder2;
  cmd_line_.AppendSwitch("pretty-print");
  EXPECT_TRUE(grinder2.ParseCommandLine(&cmd_line_));
}

TEST_F(BasicBlockEntryCountGrinderTest, SetParserSucceeds) {
  TestBasicBlockEntryCountGrinder grinder;

  grinder.ParseCommandLine(&cmd_line_);

  ASSERT_NO_FATAL_FAILURE(InitParser(&grinder, kBasicBlockEntryTraceFile));

  grinder.SetParser(&parser_);
  EXPECT_EQ(&parser_, grinder.parser_);
}

TEST_F(BasicBlockEntryCountGrinderTest, GrindFailsOnNoEvents) {
  TestBasicBlockEntryCountGrinder grinder;

  grinder.ParseCommandLine(&cmd_line_);

  ASSERT_NO_FATAL_FAILURE(InitParser(&grinder, kBasicBlockEntryTraceFile));
  grinder.SetParser(&parser_);

  EXPECT_FALSE(grinder.Grind());
}

TEST_F(BasicBlockEntryCountGrinderTest, UpdateBasicBlockEntryCount) {
  ModuleInformation module_info;
  ASSERT_NO_FATAL_FAILURE(InitModuleInfo(&module_info));

  EntryCountMap expected_entry_count_map;
  EntryCountVector& expected_entry_count_vector =
      expected_entry_count_map[module_info];

  TestBasicBlockEntryCountGrinder grinder;
  scoped_ptr<TraceBasicBlockFrequencyData> data1;
  scoped_ptr<TraceBasicBlockFrequencyData> data2;
  scoped_ptr<TraceBasicBlockFrequencyData> data4;
  static const uint32 kExpectedValues1[] = { 1, 2, 3, 4, 5 };
  static const uint32 kExpectedValues2[] = { 2, 4, 6, 8, 10 };
  static const uint32 kExpectedValues4[] = { 3, 6, 9, 12, 15 };

  // Validate 1-byte frequency data.
  ASSERT_NO_FATAL_FAILURE(GetFrequencyData(module_info, 1, &data1));
  ASSERT_EQ(1U, data1->frequency_size);
  grinder.UpdateBasicBlockEntryCount(&module_info, data1.get());
  EXPECT_EQ(1U, grinder.entry_count_map().size());
  EXPECT_THAT(grinder.entry_count_map().begin()->second,
              testing::ElementsAreArray(kExpectedValues1));

  // Validate 2-byte frequency data.
  ASSERT_NO_FATAL_FAILURE(GetFrequencyData(module_info, 2, &data2));
  ASSERT_EQ(2U, data2->frequency_size);
  grinder.UpdateBasicBlockEntryCount(&module_info, data2.get());
  EXPECT_EQ(1U, grinder.entry_count_map().size());
  EXPECT_THAT(grinder.entry_count_map().begin()->second,
              testing::ElementsAreArray(kExpectedValues2));

  // Validate 4-byte frequency data.
  ASSERT_NO_FATAL_FAILURE(GetFrequencyData(module_info, 4, &data4));
  ASSERT_EQ(4U, data4->frequency_size);
  grinder.UpdateBasicBlockEntryCount(&module_info, data4.get());
  EXPECT_EQ(1U, grinder.entry_count_map().size());
  EXPECT_THAT(grinder.entry_count_map().begin()->second,
              testing::ElementsAreArray(kExpectedValues4));
}

TEST_F(BasicBlockEntryCountGrinderTest, GrindBasicBlockEntryDataSucceeds) {
  EntryCountMap entry_counts;
  ASSERT_NO_FATAL_FAILURE(
      RunGrinderTest(kBasicBlockEntryTraceFile, &entry_counts));
  // TODO(rogerm): Inspect value for bb-entry specific expected data.
}

TEST_F(BasicBlockEntryCountGrinderTest, GrindCoverageDataSucceeds) {
  EntryCountMap entry_counts;
  ASSERT_NO_FATAL_FAILURE(RunGrinderTest(kCoverageTraceFile, &entry_counts));
  // TODO(rogerm): Inspect value for coverage specific expected data.
}

}  // namespace grinder
