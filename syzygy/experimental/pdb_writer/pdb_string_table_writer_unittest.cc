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
#include "syzygy/common/binary_stream.h"
#include "syzygy/pdb/pdb_byte_stream.h"
#include "syzygy/pdb/pdb_constants.h"
#include "syzygy/pdb/pdb_util.h"
#include "syzygy/pdb/pdb_stream_reader.h"

namespace pdb {

TEST(PdbWriterTest, WriteStringTable) {
  const char* kStrings[] = { "string_a", "string_b", "", "string ccc" };
  const size_t kNumStrings = sizeof(kStrings) / sizeof(char*);
  const size_t kExpectedNumNonEmptyStrings = 3;
  const uint32_t kExpectedSize = 30;
  const uint32_t kExpectedStringOffsets[] = {0, 9, 18, 19};

  StringTable strings(kStrings, kStrings + kNumStrings);

  scoped_refptr<PdbByteStream> stream(new PdbByteStream());
  scoped_refptr<WritablePdbStream> writer(stream->GetWritableStream());

  EXPECT_TRUE(WriteStringTable(strings, writer.get()));

  EXPECT_EQ(stream->length(), writer->pos());

  pdb::PdbStreamReaderWithPosition reader(stream.get());
  common::BinaryStreamParser parser(&reader);

  uint32_t signature = 0;
  EXPECT_TRUE(parser.Read(&signature));
  EXPECT_EQ(kPdbStringTableSignature, signature);

  uint32_t version = 0;
  EXPECT_TRUE(parser.Read(&version));
  EXPECT_EQ(kPdbStringTableVersion, version);

  uint32_t size = 0;
  EXPECT_TRUE(parser.Read(&size));
  EXPECT_EQ(kExpectedSize, size);

  for (size_t i = 0; i < kNumStrings; ++i) {
    std::string read_string;
    parser.ReadString(&read_string);
    EXPECT_EQ(strings[i], read_string);
  }

  uint32_t num_strings = 0;
  EXPECT_TRUE(parser.Read(&num_strings));
  EXPECT_EQ(kNumStrings, num_strings);

  for (size_t i = 0; i < kNumStrings; ++i) {
    uint32_t offset = 0;
    EXPECT_TRUE(parser.Read(&offset));
    EXPECT_EQ(kExpectedStringOffsets[i], offset);
  }

  uint32_t num_non_empty_strings = 0;
  EXPECT_TRUE(parser.Read(&num_non_empty_strings));
  EXPECT_EQ(kExpectedNumNonEmptyStrings, num_non_empty_strings);
}

TEST(PdbWriterTest, WriteEmptyStringTable) {
  const size_t kNumStrings = 0;
  const size_t kExpectedNumNonEmptyStrings = 0;
  const uint32_t kExpectedSize = 0;

  StringTable strings;

  scoped_refptr<PdbByteStream> stream(new PdbByteStream());
  scoped_refptr<WritablePdbStream> writer(stream->GetWritableStream());

  EXPECT_TRUE(WriteStringTable(strings, writer.get()));

  EXPECT_EQ(stream->length(), writer->pos());

  uint32_t signature = 0;
  pdb::PdbStreamReaderWithPosition reader(stream.get());
  common::BinaryStreamParser parser(&reader);

  EXPECT_TRUE(parser.Read(&signature));
  EXPECT_EQ(kPdbStringTableSignature, signature);

  uint32_t version = 0;
  EXPECT_TRUE(parser.Read(&version));
  EXPECT_EQ(kPdbStringTableVersion, version);

  uint32_t size = 0;
  EXPECT_TRUE(parser.Read(&size));
  EXPECT_EQ(kExpectedSize, size);

  uint32_t num_strings = 0;
  EXPECT_TRUE(parser.Read(&num_strings));
  EXPECT_EQ(kNumStrings, num_strings);

  uint32_t num_non_empty_strings = 0;
  EXPECT_TRUE(parser.Read(&num_non_empty_strings));
  EXPECT_EQ(kExpectedNumNonEmptyStrings, num_non_empty_strings);
}

}  // namespace pdb
