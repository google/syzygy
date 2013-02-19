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

#include "syzygy/grinder/basic_block_entry_count_serializer.h"

#include "base/file_util.h"
#include "base/scoped_temp_dir.h"
#include "base/values.h"
#include "base/json/json_reader.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/metadata.h"
#include "syzygy/pe/unittest_util.h"

namespace grinder {

namespace {

using base::DictionaryValue;
using base::FundamentalValue;
using base::JSONReader;
using base::ListValue;
using base::Value;
using basic_block_util::EntryCountMap;
using basic_block_util::EntryCountType;
using basic_block_util::ModuleEntryCountMap;
using basic_block_util::ModuleInformation;
using testing::ContainerEq;

const wchar_t kImageFileName[] = L"foo.dll";
const uint32 kBaseAddress = 0xDEADBEEF;
const uint32 kModuleSize = 0x1000;
const uint32 kImageChecksum = 0xCAFEBABE;
const uint32 kTimeDateStamp = 0xBABECAFE;

class TestBasicBlockEntryCountSerializer
    : public BasicBlockEntryCountSerializer {
 public:
  using BasicBlockEntryCountSerializer::PopulateFromJsonValue;
  using BasicBlockEntryCountSerializer::pretty_print_;
};

class BasicBlockEntryCountSerializerTest : public testing::PELibUnitTest {
 public:
  typedef testing::PELibUnitTest Super;

  virtual void SetUp() OVERRIDE {
    Super::SetUp();
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
  }

  void InitModuleInfo(ModuleInformation* module_info) {
    ASSERT_TRUE(module_info != NULL);
    module_info->image_file_name = kImageFileName;
    module_info->base_address = kBaseAddress;
    module_info->module_size = kModuleSize;
    module_info->image_checksum = kImageChecksum;
    module_info->time_date_stamp = kTimeDateStamp;
  }
 protected:
  ScopedTempDir temp_dir_;
};

}  // namespace

TEST_F(BasicBlockEntryCountSerializerTest, Accessors) {
  TestBasicBlockEntryCountSerializer serializer;
  EXPECT_FALSE(serializer.pretty_print_);

  serializer.set_pretty_print(true);
  EXPECT_TRUE(serializer.pretty_print_);
}

TEST_F(BasicBlockEntryCountSerializerTest, LoadFromJsonFails) {
  TestBasicBlockEntryCountSerializer serializer;
  ModuleEntryCountMap entry_count_map;

  FilePath does_not_exist(temp_dir_.path().AppendASCII("does_not_exist.json"));
  EXPECT_FALSE(serializer.LoadFromJson(does_not_exist, &entry_count_map));

  FilePath some_path(testing::GetExeTestDataRelativePath(
      testing::kCoverageTraceFiles[0]));
  EXPECT_FALSE(serializer.LoadFromJson(some_path, &entry_count_map));
}

TEST_F(BasicBlockEntryCountSerializerTest, PopulateFromJsonValueFails) {
  ModuleEntryCountMap entry_count_map;
  TestBasicBlockEntryCountSerializer serializer;

  // It should fail if the outermost JSON object is not a list.
  scoped_ptr<Value> int_value(Value::CreateIntegerValue(7));
  ASSERT_FALSE(serializer.PopulateFromJsonValue(int_value.get(),
                                                &entry_count_map));

  // It should fail if the outermost list does not contain dictionaries.
  scoped_ptr<ListValue> list_value(new ListValue());
  list_value->Append(Value::CreateBooleanValue(true));
  ASSERT_FALSE(serializer.PopulateFromJsonValue(list_value.get(),
                                                &entry_count_map));
  list_value->Clear();

  // It should fail if the list entry does not contain a metadata key.
  DictionaryValue* dict_value = new DictionaryValue();
  list_value->Append(dict_value);
  ASSERT_FALSE(serializer.PopulateFromJsonValue(list_value.get(),
                                                &entry_count_map));

  // It should fail if the metadata value is not a dictionary.
  dict_value->Set("metadata", Value::CreateStringValue("foo"));
  ASSERT_FALSE(serializer.PopulateFromJsonValue(list_value.get(),
                                                &entry_count_map));

  // After adding the metadata value, it should still fail since there is no
  // entry_count_map key.
  static const char kMetadataStr[] =
      "{\n"
      "  \"command_line\": \"foo.exe\",\n"
      "  \"creation_time\": \"Wed, 19 Sep 2012 17:33:52 GMT\",\n"
      "  \"toolchain_version\": {\n"
      "    \"major\": 0,\n"
      "    \"minor\": 2,\n"
      "    \"build\": 7,\n"
      "    \"patch\": 0,\n"
      "    \"last_change\": \"0\"\n"
      "  },\n"
      "  \"module_signature\": {\n"
      "    \"path\": \"C:\\\\foo\\\\bar.dll\",\n"
      "    \"base_address\": 1904279552,\n"
      "    \"module_size\": 180224,\n"
      "    \"module_time_date_stamp\": \"0x46F7885059FE32\",\n"
      "    \"module_checksum\": \"0x257AF\"\n"
      "  }\n"
      "}\n";
  std::string error_msg;
  scoped_ptr<Value> metadata(JSONReader().ReadAndReturnError(
      kMetadataStr, true, NULL, &error_msg));
  EXPECT_EQ(std::string(), error_msg);
  ASSERT_TRUE(metadata.get() != NULL);
  dict_value->Set("metadata", metadata.release());
  ASSERT_FALSE(serializer.PopulateFromJsonValue(list_value.get(),
                                                &entry_count_map));

  // It should still fail since the entry_counts key has the wrong value type.
  dict_value->Set("entry_counts", Value::CreateStringValue("foo"));
  ASSERT_FALSE(serializer.PopulateFromJsonValue(list_value.get(),
                                                &entry_count_map));

  // It should still fail since the entry_counts list contains an invalid value.
  ListValue* entry_counts = new ListValue();
  dict_value->Set("entry_counts", entry_counts);
  entry_counts->Append(Value::CreateStringValue("foo"));
  ASSERT_FALSE(serializer.PopulateFromJsonValue(list_value.get(),
                                                &entry_count_map));

  // It should succeed once we start putting numbers into the entry_counts list.
  EntryCountMap expected_values;
  entry_counts->Clear();
  for (size_t i = 0; i < expected_values.size(); ++i) {
    scoped_ptr<ListValue> entry(new ListValue());
    entry->Append(Value::CreateIntegerValue(i * i));
    entry->Append(Value::CreateIntegerValue(100 * i));
    expected_values[i * i] = 100 * i;

    entry_counts->Append(entry.release());
  }

  ASSERT_TRUE(serializer.PopulateFromJsonValue(list_value.get(),
                                               &entry_count_map));

  EXPECT_EQ(1U, entry_count_map.size());
  EXPECT_THAT(entry_count_map.begin()->second,
              testing::ContainerEq(expected_values));
}

TEST_F(BasicBlockEntryCountSerializerTest, RoundTrip) {
  ModuleInformation module_info;
  ASSERT_NO_FATAL_FAILURE(InitModuleInfo(&module_info));

  ModuleEntryCountMap entry_count_map;
  EntryCountMap& counters = entry_count_map[module_info];
  size_t num_basic_blocks = 100;
  for (size_t i = 0; i < num_basic_blocks; ++i)
    counters[i * i] = i + 1;

  FilePath json_path(temp_dir_.path().AppendASCII("test.json"));

  TestBasicBlockEntryCountSerializer serializer;
  serializer.set_pretty_print(true);
  ASSERT_TRUE(serializer.SaveAsJson(entry_count_map, json_path));

  ModuleEntryCountMap new_entry_count_map;
  serializer.LoadFromJson(json_path, &new_entry_count_map);

  EXPECT_THAT(new_entry_count_map, ContainerEq(entry_count_map));
}

}  // namespace grinder
