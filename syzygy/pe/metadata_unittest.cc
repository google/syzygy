// Copyright 2011 Google Inc. All Rights Reserved.
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

#include "syzygy/pe/metadata.h"

#include "base/file_util.h"
#include "base/json/json_reader.h"
#include "gtest/gtest.h"
#include "syzygy/core/json_file_writer.h"
#include "syzygy/core/serialization.h"
#include "syzygy/core/unittest_util.h"

namespace pe {

typedef PEFile::AbsoluteAddress AbsoluteAddress;

using base::DictionaryValue;
using base::Value;

namespace {

void InitMetadata(Metadata* metadata) {
  std::string command_line = "foo.exe --bar --baz=blarg";

  base::Time creation_time;
  EXPECT_TRUE(base::Time::FromString("Thu, 7 Jul 2011 13:45:00 GMT",
                                     &creation_time));

  SyzygyVersion toolchain_version(1, 2, 3, 4, "5");

  PEFile::Signature module_signature;
  module_signature.path = L"C:\\foo\\foo.dll";
  module_signature.base_address = AbsoluteAddress(0x4001000);
  module_signature.module_size = 2 * 1024 * 1024;
  module_signature.module_time_date_stamp = 0xdeadbeefu;
  module_signature.module_checksum = 0xbaadf00du;

  metadata->set_command_line(command_line);
  metadata->set_creation_time(creation_time);
  metadata->set_toolchain_version(toolchain_version);
  metadata->set_module_signature(module_signature);
}

bool TestJSONSerialization(bool pretty_print) {
  base::FilePath temp_file_path;
  FILE* temp_file = base::CreateAndOpenTemporaryFile(&temp_file_path);
  if (temp_file == NULL)
    return false;

  bool success = true;

  // Output to file.
  Metadata metadata1;
  InitMetadata(&metadata1);
  core::JSONFileWriter json_file(temp_file, pretty_print);
  EXPECT_TRUE(success = metadata1.SaveToJSON(&json_file));
  fclose(temp_file);

  // Read the file.
  std::string file_string;
  if (success)
    EXPECT_TRUE(success =
        base::ReadFileToString(temp_file_path, &file_string));

  // Parse the JSON, extracting the root dictionary.
  scoped_ptr<Value> value;
  DictionaryValue* metadata_dict = NULL;
  if (success) {
    value.reset(base::JSONReader::Read(file_string));
    EXPECT_TRUE(success =
        (value.get() != NULL && value->GetType() == Value::TYPE_DICTIONARY));
    if (success)
      metadata_dict = static_cast<DictionaryValue*>(value.get());
  }

  // Parse the metadata from the Value.
  Metadata metadata2;
  if (success) {
    DCHECK(metadata_dict != NULL);
    EXPECT_TRUE(success = metadata2.LoadFromJSON(*metadata_dict));
  }

  // Compare the two structures.
  if (success)
    EXPECT_TRUE(success = (metadata1 == metadata2));

  // Always delete the temporary file.
  if (!base::DeleteFile(temp_file_path, false))
    success = false;

  return success;
}

}  // namespace

TEST(MetadataTest, Equality) {
  Metadata metadata1;
  Metadata metadata2;
  InitMetadata(&metadata1);
  InitMetadata(&metadata2);
  EXPECT_EQ(metadata1, metadata2);
}

TEST(MetadataTest, Inequality) {
  Metadata metadata1;
  Metadata metadata2;
  InitMetadata(&metadata1);
  EXPECT_NE(metadata1, metadata2);
}

TEST(MetadataTest, SaveToBlock) {
  Metadata metadata1;
  InitMetadata(&metadata1);

  BlockGraph block_graph;
  BlockGraph::Block* block =
      block_graph.AddBlock(BlockGraph::DATA_BLOCK, 0, "Metadata");
  EXPECT_TRUE(metadata1.SaveToBlock(block));

  Metadata metadata2;
  EXPECT_TRUE(metadata2.LoadFromBlock(block));
  EXPECT_EQ(metadata1, metadata2);
}

TEST(MetadataTest, Serialization) {
  Metadata metadata;
  InitMetadata(&metadata);
  EXPECT_TRUE(testing::TestSerialization(metadata));
}

TEST(MetadataTest, JSONSerializationNoPrettyPrint) {
  EXPECT_TRUE(TestJSONSerialization(true));
}

TEST(MetadataTest, JSONSerializationPrettyPrint) {
  EXPECT_TRUE(TestJSONSerialization(false));
}

}  // namespace pe
