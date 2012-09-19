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
using basic_block_util::IsValidFrequencySize;
using basic_block_util::ModuleInformation;
using common::kSyzygyVersion;
using file_util::CreateAndOpenTemporaryFile;

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
  using BasicBlockEntryCountGrinder::pretty_print_;
};

class BasicBlockEntryCountGrinderTest : public testing::PELibUnitTest {
 public:
  typedef testing::PELibUnitTest Super;

  BasicBlockEntryCountGrinderTest()
      : cmd_line_(FilePath(L"basic_block_entry_count_grinder.exe")) {
  }

  void InitParser(trace::parser::ParseEventHandlerImpl* handler,
                  const wchar_t* file_path) {
    ASSERT_TRUE(handler != NULL);
    ASSERT_TRUE(parser_.Init(handler));
    FilePath trace_file(testing::GetExeTestDataRelativePath(file_path));
    ASSERT_TRUE(parser_.OpenTraceFile(trace_file));
  }


  void RunGrinderTest(const wchar_t* trace_file,
                      scoped_ptr<Value>* json_value) {
    ASSERT_TRUE(trace_file != NULL);
    ASSERT_TRUE(json_value != NULL);
    EXPECT_TRUE(json_value->get() == NULL);
    ASSERT_NO_FATAL_FAILURE(GrindTraceFileToJson(trace_file, json_value));
    ASSERT_NO_FATAL_FAILURE(ValidateJson(json_value->get()));
  }

  void GrindTraceFileToJson(const wchar_t* trace_file,
                            scoped_ptr<Value>* json_value) {
    ASSERT_TRUE(trace_file != NULL);
    ASSERT_TRUE(json_value != NULL);

    // Consume the the trace file.
    TestBasicBlockEntryCountGrinder grinder;
    cmd_line_.AppendSwitch("pretty-print");
    grinder.ParseCommandLine(&cmd_line_);
    ASSERT_NO_FATAL_FAILURE(InitParser(&grinder, trace_file));
    grinder.SetParser(&parser_);
    ASSERT_TRUE(parser_.Consume());

    // Grind and output the data to a JSON file.
    FilePath json_path;
    file_util::ScopedFILE json_file(CreateAndOpenTemporaryFile(&json_path));
    ASSERT_TRUE(json_file.get() != NULL);
    ASSERT_TRUE(grinder.Grind());
    ASSERT_TRUE(grinder.OutputData(json_file.get()));
    json_file.reset();

    // Read the JSON file to a string.
    std::string json;
    ASSERT_TRUE(file_util::ReadFileToString(json_path, &json));
    ASSERT_FALSE(json.empty());

    // Parse the string to a JSON value.
    json_value->reset(base::JSONReader::Read(json, false));
    ASSERT_TRUE(json_value->get() != NULL);
  }

  void ValidateJson(Value* json_value) {
    ASSERT_TRUE(json_value != NULL);

    // Verify that the json valus is a list of length 1.
    ListValue* module_list = NULL;
    ASSERT_TRUE(json_value->GetAsList(&module_list));
    ASSERT_TRUE(module_list != NULL);
    ASSERT_EQ(1U, module_list->GetSize());

    // The first (and only) item in the module list is a dictionary.
    DictionaryValue* module_dict = NULL;
    ASSERT_TRUE(module_list->GetDictionary(0, &module_dict));
    ASSERT_TRUE(module_dict != NULL);

    // Verify that the names and types of the dictionary entries are correct.
    DictionaryValue* metadata_dict = NULL;
    int num_basic_blocks = 0;
    ListValue* entry_counts = NULL;
    pe::Metadata metadata;
    EXPECT_TRUE(module_dict->GetDictionary("metadata", &metadata_dict));
    ASSERT_TRUE(metadata_dict != NULL);
    EXPECT_TRUE(metadata.LoadFromJSON(*metadata_dict));
    EXPECT_TRUE(module_dict->GetInteger("num_basic_blocks", &num_basic_blocks));
    EXPECT_LT(0, num_basic_blocks);
    EXPECT_TRUE(module_dict->GetList("entry_counts", &entry_counts));
    ASSERT_TRUE(entry_counts != NULL);
    EXPECT_EQ(static_cast<size_t>(num_basic_blocks), entry_counts->GetSize());
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
  CommandLine cmd_line_;
  trace::parser::Parser parser_;
};

}  // namespace

TEST_F(BasicBlockEntryCountGrinderTest, ParseCommandLineSucceeds) {
  TestBasicBlockEntryCountGrinder grinder1;
  EXPECT_TRUE(grinder1.ParseCommandLine(&cmd_line_));
  EXPECT_FALSE(grinder1.pretty_print_);

  TestBasicBlockEntryCountGrinder grinder2;
  cmd_line_.AppendSwitch("pretty-print");
  EXPECT_TRUE(grinder2.ParseCommandLine(&cmd_line_));
  EXPECT_TRUE(grinder2.pretty_print_);
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

  BasicBlockEntryCountGrinder::EntryCountMap expected_entry_count_map;
  BasicBlockEntryCountGrinder::EntryCountVector& expected_entry_count_vector =
      expected_entry_count_map[&module_info];

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
  EXPECT_EQ(&module_info, grinder.entry_count_map().begin()->first);
  EXPECT_THAT(grinder.entry_count_map().begin()->second,
              testing::ElementsAreArray(kExpectedValues1));

  // Validate 2-byte frequency data.
  ASSERT_NO_FATAL_FAILURE(GetFrequencyData(module_info, 2, &data2));
  ASSERT_EQ(2U, data2->frequency_size);
  grinder.UpdateBasicBlockEntryCount(&module_info, data2.get());
  EXPECT_EQ(1U, grinder.entry_count_map().size());
  EXPECT_EQ(&module_info, grinder.entry_count_map().begin()->first);
  EXPECT_THAT(grinder.entry_count_map().begin()->second,
              testing::ElementsAreArray(kExpectedValues2));

  // Validate 4-byte frequency data.
  ASSERT_NO_FATAL_FAILURE(GetFrequencyData(module_info, 4, &data4));
  ASSERT_EQ(4U, data4->frequency_size);
  grinder.UpdateBasicBlockEntryCount(&module_info, data4.get());
  EXPECT_EQ(1U, grinder.entry_count_map().size());
  EXPECT_EQ(&module_info, grinder.entry_count_map().begin()->first);
  EXPECT_THAT(grinder.entry_count_map().begin()->second,
              testing::ElementsAreArray(kExpectedValues4));
}

TEST_F(BasicBlockEntryCountGrinderTest, GrindBasicBlockEntryDataSucceeds) {
  scoped_ptr<Value> value;
  ASSERT_NO_FATAL_FAILURE(RunGrinderTest(kBasicBlockEntryTraceFile, &value));
  // TODO(rogerm): Inspect value for bb-entry specific expected data.
}

TEST_F(BasicBlockEntryCountGrinderTest, GrindCoverageDataSucceeds) {
  scoped_ptr<Value> value;
  ASSERT_NO_FATAL_FAILURE(RunGrinderTest(kCoverageTraceFile, &value));
  // TODO(rogerm): Inspect value for coverage specific expected data.
}

}  // namespace grinder
