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

#include "syzygy/pdb/pdb_stream_reader.h"

#include "gtest/gtest.h"
#include "syzygy/pdb/pdb_byte_stream.h"

namespace pdb {

namespace {

}  // namespace

TEST(PdbStreamReaderTest, Read) {
  const uint8_t kData[] = { 0, 1, 2, 10 };
  scoped_refptr<PdbByteStream> stream(new PdbByteStream());
  stream->Init(kData, sizeof(kData));

  PdbStreamReader reader(stream.get());

  uint8_t data[sizeof(kData)] = {};
  EXPECT_EQ(0U, reader.Position());
  EXPECT_FALSE(reader.AtEnd());
  EXPECT_TRUE(reader.Read(sizeof(data), data));
  EXPECT_EQ(sizeof(kData), reader.Position());
  EXPECT_TRUE(reader.AtEnd());
  EXPECT_EQ(0U, ::memcmp(kData, data, sizeof(kData)));

  EXPECT_FALSE(reader.Read(1, data));

  // Seek the underlying stream back to the start, and redo the read.
  ASSERT_TRUE(stream->Seek(0));
  EXPECT_EQ(0U, reader.Position());
  EXPECT_FALSE(reader.AtEnd());
  EXPECT_TRUE(reader.Read(sizeof(data), data));
  EXPECT_EQ(0U, ::memcmp(kData, data, sizeof(kData)));
}

}  // namespace pdb
