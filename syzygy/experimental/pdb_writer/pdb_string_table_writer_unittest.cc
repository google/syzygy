// Copyright 2014 Google Inc. All Rights Reserved.
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

#include "syzygy/experimental/pdb_writer/pdb_string_table_writer.h"

#include "base/memory/ref_counted.h"
#include "gtest/gtest.h"
#include "syzygy/pdb/pdb_byte_stream.h"
#include "syzygy/pdb/pdb_constants.h"
#include "syzygy/pdb/pdb_util.h"

namespace pdb {

TEST(PdbWriterTest, WriteStringTable) {
  const char* kStrings[] = { "string_a", "string_b", "", "string ccc" };
  const size_t kNumStrings = sizeof(kStrings) / sizeof(char*);
  const size_t kExpectedNumNonEmptyStrings = 3;
  const uint32 kExpectedSize = 30;
  const uint32 kExpectedStringOffsets[] = { 0, 9, 18, 19 };

  StringTable strings(kStrings, kStrings + kNumStrings);

  scoped_refptr<PdbByteStream> reader(new PdbByteStream());
  scoped_refptr<WritablePdbStream> writer(reader->GetWritablePdbStream());

  EXPECT_TRUE(WriteStringTable(strings, writer));

  EXPECT_EQ(reader->length(), writer->pos());

  uint32 signature = 0;
  EXPECT_TRUE(reader->Read(&signature, 1));
  EXPECT_EQ(kPdbStringTableSignature, signature);

  uint32 version = 0;
  EXPECT_TRUE(reader->Read(&version, 1));
  EXPECT_EQ(kPdbStringTableVersion, version);

  uint32 size = 0;
  EXPECT_TRUE(reader->Read(&size, 1));
  EXPECT_EQ(kExpectedSize, size);

  for (size_t i = 0; i < kNumStrings; ++i) {
    std::string read_string;
    ReadString(reader, &read_string);
    EXPECT_EQ(strings[i], read_string);
  }

  uint32 num_strings = 0;
  EXPECT_TRUE(reader->Read(&num_strings, 1));
  EXPECT_EQ(kNumStrings, num_strings);

  for (size_t i = 0; i < kNumStrings; ++i) {
    uint32 offset = 0;
    EXPECT_TRUE(reader->Read(&offset, 1));
    EXPECT_EQ(kExpectedStringOffsets[i], offset);
  }

  uint32 num_non_empty_strings = 0;
  EXPECT_TRUE(reader->Read(&num_non_empty_strings, 1));
  EXPECT_EQ(kExpectedNumNonEmptyStrings, num_non_empty_strings);
}

TEST(PdbWriterTest, WriteEmptyStringTable) {
  const size_t kNumStrings = 0;
  const size_t kExpectedNumNonEmptyStrings = 0;
  const uint32 kExpectedSize = 0;

  StringTable strings;

  scoped_refptr<PdbByteStream> reader(new PdbByteStream());
  scoped_refptr<WritablePdbStream> writer(reader->GetWritablePdbStream());

  EXPECT_TRUE(WriteStringTable(strings, writer));

  EXPECT_EQ(reader->length(), writer->pos());

  uint32 signature = 0;
  EXPECT_TRUE(reader->Read(&signature, 1));
  EXPECT_EQ(kPdbStringTableSignature, signature);

  uint32 version = 0;
  EXPECT_TRUE(reader->Read(&version, 1));
  EXPECT_EQ(kPdbStringTableVersion, version);

  uint32 size = 0;
  EXPECT_TRUE(reader->Read(&size, 1));
  EXPECT_EQ(kExpectedSize, size);

  uint32 num_strings = 0;
  EXPECT_TRUE(reader->Read(&num_strings, 1));
  EXPECT_EQ(kNumStrings, num_strings);

  uint32 num_non_empty_strings = 0;
  EXPECT_TRUE(reader->Read(&num_non_empty_strings, 1));
  EXPECT_EQ(kExpectedNumNonEmptyStrings, num_non_empty_strings);
}

}  // namespace pdb
