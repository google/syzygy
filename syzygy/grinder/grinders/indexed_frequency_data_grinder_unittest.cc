// Copyright 2013 Google Inc. All Rights Reserved.
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

#include "syzygy/grinder/grinders/indexed_frequency_data_grinder.h"

#include "base/file_util.h"
#include "base/values.h"
#include "base/files/scoped_temp_dir.h"
#include "base/json/json_reader.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/common/indexed_frequency_data.h"
#include "syzygy/common/syzygy_version.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/metadata.h"
#include "syzygy/pe/unittest_util.h"

namespace grinder {
namespace grinders {

namespace {

using base::DictionaryValue;
using base::ListValue;
using base::Value;
using basic_block_util::IndexedFrequencyMap;
using basic_block_util::EntryCountType;
using basic_block_util::ModuleIndexedFrequencyMap;
using basic_block_util::IsValidFrequencySize;
using basic_block_util::ModuleInformation;
using common::kSyzygyVersion;
using file_util::CreateAndOpenTemporaryFileInDir;

const wchar_t kImageFileName[] = L"foo.dll";
const uint32 kBaseAddress = 0xDEADBEEF;
const uint32 kModuleSize = 0x1000;
const uint32 kImageChecksum = 0xCAFEBABE;
const uint32 kTimeDateStamp = 0xBABECAFE;

// We allocate the frequency data using new uint8[], so we need to make sure it
// gets cleaned up with the appropriate deleter.
struct TraceIndexedFrequencyDataDeleter {
  inline void operator()(TraceIndexedFrequencyData* ptr) const {
    delete [] reinterpret_cast<uint8*>(ptr);
  }
};
typedef scoped_ptr<TraceIndexedFrequencyData,
                   TraceIndexedFrequencyDataDeleter> ScopedFrequencyData;

class TestIndexedFrequencyDataGrinder : public IndexedFrequencyDataGrinder {
 public:
  using IndexedFrequencyDataGrinder::UpdateBasicBlockFrequencyData;
  using IndexedFrequencyDataGrinder::InstrumentedModuleInformation;
  using IndexedFrequencyDataGrinder::parser_;
};

class IndexedFrequencyDataGrinderTest : public testing::PELibUnitTest {
 public:
  typedef testing::PELibUnitTest Super;
  typedef TestIndexedFrequencyDataGrinder::InstrumentedModuleInformation
      InstrumentedModuleInformation;

  static const size_t kNumBasicBlocks = 5;
  static const size_t kNumColumns = 3;

  IndexedFrequencyDataGrinderTest()
      : cmd_line_(base::FilePath(L"indexed_frequency_data_grinder.exe")) {
  }

  virtual void SetUp() OVERRIDE {
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
  }

  void InitParser(trace::parser::ParseEventHandlerImpl* handler,
                  const wchar_t* file_path) {
    ASSERT_TRUE(handler != NULL);
    ASSERT_TRUE(parser_.Init(handler));
    base::FilePath trace_file(testing::GetExeTestDataRelativePath(file_path));
    ASSERT_TRUE(parser_.OpenTraceFile(trace_file));
  }

  void RunGrinderTest(const wchar_t* trace_file,
                      ModuleIndexedFrequencyMap* module_entry_counts) {
    ASSERT_TRUE(trace_file != NULL);
    ASSERT_TRUE(module_entry_counts != NULL);
    base::FilePath json_path;
    ASSERT_NO_FATAL_FAILURE(GrindTraceFileToJson(trace_file, &json_path));
    ASSERT_NO_FATAL_FAILURE(LoadJson(json_path, module_entry_counts));
  }

  void GrindTraceFileToJson(const wchar_t* trace_file,
                            base::FilePath* json_path) {
    ASSERT_TRUE(trace_file != NULL);
    ASSERT_TRUE(json_path != NULL);

    json_path->clear();

    // Consume the trace file.
    TestIndexedFrequencyDataGrinder grinder;
    cmd_line_.AppendSwitch("pretty-print");
    grinder.ParseCommandLine(&cmd_line_);
    ASSERT_NO_FATAL_FAILURE(InitParser(&grinder, trace_file));
    grinder.SetParser(&parser_);
    ASSERT_TRUE(parser_.Consume());

    // Grind and output the data to a JSON file.
    base::FilePath temp_path;
    file_util::ScopedFILE json_file(
        CreateAndOpenTemporaryFileInDir(temp_dir_.path(), &temp_path));
    ASSERT_TRUE(json_file.get() != NULL);
    ASSERT_TRUE(grinder.Grind());
    ASSERT_TRUE(grinder.OutputData(json_file.get()));
    *json_path = temp_path;
  }

  void LoadJson(const base::FilePath& json_path,
                ModuleIndexedFrequencyMap* module_entry_counts) {
    ASSERT_TRUE(!json_path.empty());
    ASSERT_TRUE(module_entry_counts != NULL);

    IndexedFrequencyDataSerializer serializer;
    ASSERT_TRUE(serializer.LoadFromJson(json_path, module_entry_counts));
  }

  void CreateExpectedCounts(int multiplier, IndexedFrequencyMap* expected) {
    ASSERT_TRUE(expected != NULL);
    expected->clear();

    for (size_t i = 0; i < kNumBasicBlocks; ++i) {
      for (size_t c = 0; c < kNumColumns; ++c) {
        (*expected)[std::make_pair(i * i, c)] = (i + c + 1) * multiplier;
      }
    }
  }

  void InitModuleInfo(InstrumentedModuleInformation* module_info) {
    ASSERT_TRUE(module_info != NULL);
    module_info->original_module.path = kImageFileName;
    module_info->original_module.base_address = kBaseAddress;
    module_info->original_module.module_size = kModuleSize;
    module_info->original_module.module_checksum = kImageChecksum;
    module_info->original_module.module_time_date_stamp = kTimeDateStamp;

    for (size_t i = 0; i < kNumBasicBlocks; ++i) {
      using grinder::basic_block_util::RelativeAddress;
      using grinder::basic_block_util::RelativeAddressRange;

      module_info->block_ranges.push_back(
          RelativeAddressRange(RelativeAddress(i * i), i + 1));
    }
  }

  void GetFrequencyData(const ModuleInformation& module_info,
                        size_t frequency_size,
                        ScopedFrequencyData* data) {
    ASSERT_TRUE(IsValidFrequencySize(frequency_size));
    ASSERT_TRUE(data != NULL);

    static const size_t kMaxDataSize =
        kNumColumns * kNumBasicBlocks * sizeof(uint32);
    static const size_t kBufferSize =
        sizeof(TraceIndexedFrequencyData) + kMaxDataSize - 1;

    uint8* buffer = new uint8[kBufferSize];
    ASSERT_TRUE(buffer != NULL);
    ::memset(buffer, 0, kBufferSize);

    data->reset(reinterpret_cast<TraceIndexedFrequencyData*>(buffer));
    (*data)->module_base_addr =
        reinterpret_cast<ModuleAddr>(module_info.base_address);
    (*data)->module_base_size = module_info.module_size;
    (*data)->module_checksum = module_info.module_checksum;
    (*data)->module_time_date_stamp = module_info.module_time_date_stamp;
    (*data)->num_entries = kNumBasicBlocks;
    (*data)->num_columns = kNumColumns;
    (*data)->data_type = common::IndexedFrequencyData::BRANCH;
    (*data)->frequency_size = frequency_size;

    for (size_t i = 0; i < kNumBasicBlocks; ++i) {
      for (size_t c = 0; c < kNumColumns; ++c) {
        uint8 value = i + c + 1;
        size_t offset = (i * kNumColumns) + c;
        switch (frequency_size) {
          case 1:
            (*data)->frequency_data[offset] = value;
            break;
          case 2:
            reinterpret_cast<uint16*>(&(*data)->frequency_data)[offset] = value;
            break;
          case 4:
            reinterpret_cast<uint32*>(&(*data)->frequency_data)[offset] = value;
            break;
        }
      }
    }
  }

 protected:
  base::ScopedTempDir temp_dir_;
  CommandLine cmd_line_;
  trace::parser::Parser parser_;
};

}  // namespace

TEST_F(IndexedFrequencyDataGrinderTest, ParseCommandLineSucceeds) {
  TestIndexedFrequencyDataGrinder grinder1;
  EXPECT_TRUE(grinder1.ParseCommandLine(&cmd_line_));

  TestIndexedFrequencyDataGrinder grinder2;
  cmd_line_.AppendSwitch("pretty-print");
  EXPECT_TRUE(grinder2.ParseCommandLine(&cmd_line_));
}

TEST_F(IndexedFrequencyDataGrinderTest, SetParserSucceeds) {
  TestIndexedFrequencyDataGrinder grinder;

  grinder.ParseCommandLine(&cmd_line_);

  ASSERT_NO_FATAL_FAILURE(InitParser(
      &grinder, testing::kBranchTraceFiles[0]));

  grinder.SetParser(&parser_);
  EXPECT_EQ(&parser_, grinder.parser_);
}

TEST_F(IndexedFrequencyDataGrinderTest, GrindFailsOnNoEvents) {
  TestIndexedFrequencyDataGrinder grinder;

  grinder.ParseCommandLine(&cmd_line_);

  ASSERT_NO_FATAL_FAILURE(InitParser(
      &grinder, testing::kBranchTraceFiles[0]));
  grinder.SetParser(&parser_);

  EXPECT_FALSE(grinder.Grind());
}

TEST_F(IndexedFrequencyDataGrinderTest, UpdateBasicBlockFrequencyData) {
  InstrumentedModuleInformation module_info;
  ASSERT_NO_FATAL_FAILURE(InitModuleInfo(&module_info));

  TestIndexedFrequencyDataGrinder grinder;
  ScopedFrequencyData data;
  // Validate 1-byte frequency data.
  ASSERT_NO_FATAL_FAILURE(
      GetFrequencyData(module_info.original_module, 1, &data));
  ASSERT_EQ(common::IndexedFrequencyData::BRANCH, data->data_type);
  ASSERT_EQ(1U, data->frequency_size);
  grinder.UpdateBasicBlockFrequencyData(module_info, data.get());
  EXPECT_EQ(1U, grinder.frequency_data_map().size());

  IndexedFrequencyMap expected_counts;
  CreateExpectedCounts(1, &expected_counts);
  EXPECT_THAT(grinder.frequency_data_map().begin()->second,
              testing::ContainerEq(expected_counts));

  data.reset();
  // Validate 2-byte frequency data.
  ASSERT_NO_FATAL_FAILURE(
      GetFrequencyData(module_info.original_module, 2, &data));
  ASSERT_EQ(2U, data->frequency_size);
  grinder.UpdateBasicBlockFrequencyData(module_info, data.get());
  EXPECT_EQ(1U, grinder.frequency_data_map().size());

  CreateExpectedCounts(2, &expected_counts);
  EXPECT_THAT(grinder.frequency_data_map().begin()->second,
              testing::ContainerEq(expected_counts));

  data.reset();
  // Validate 4-byte frequency data.
  ASSERT_NO_FATAL_FAILURE(
      GetFrequencyData(module_info.original_module, 4, &data));
  ASSERT_EQ(4U, data->frequency_size);
  grinder.UpdateBasicBlockFrequencyData(module_info, data.get());
  EXPECT_EQ(1U, grinder.frequency_data_map().size());

  CreateExpectedCounts(3, &expected_counts);
  EXPECT_THAT(grinder.frequency_data_map().begin()->second,
              testing::ContainerEq(expected_counts));
}

TEST_F(IndexedFrequencyDataGrinderTest, GrindBranchEntryDataSucceeds) {
  ModuleIndexedFrequencyMap entry_counts;
  ASSERT_NO_FATAL_FAILURE(
      RunGrinderTest(testing::kBranchTraceFiles[0], &entry_counts));
  // TODO(rogerm): Inspect value for bb-entry specific expected data.
}


}  // namespace grinders
}  // namespace grinder
