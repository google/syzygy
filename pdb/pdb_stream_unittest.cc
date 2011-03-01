// Copyright 2011 Google Inc.
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

#include "syzygy/pdb/pdb_stream.h"
#include "gtest/gtest.h"

namespace {

using pdb::PdbStream;

class TestPdbStream : public PdbStream {
 public:
  explicit TestPdbStream(int length) : PdbStream(length) {
  }

  using PdbStream::pos;

 protected:
  // A simple implementation of ReadBytes.
  int ReadBytes(void* dest, int count) {
    if (pos() == length())
      return 0;
    else if (count > length() - pos())
      return -1;

    Seek(pos() + count);
    return count;
  }
};

}  // namespace

TEST(PdbStreamTest, Constructor) {
  TestPdbStream stream(5);
  EXPECT_EQ(5, stream.length());
  EXPECT_EQ(0, stream.pos());
}

TEST(PdbStreamTest, Read) {
  TestPdbStream stream(12);
  uint8 num8;
  uint16 num16;
  uint32 num32;

  // 3 valid reads.
  EXPECT_EQ(3, stream.Read(&num8, 3));   // 0..2
  EXPECT_EQ(2, stream.Read(&num16, 2));  // 3..6
  EXPECT_EQ(1, stream.Read(&num32, 1));  // 7..10

  // Try to read over the end of the stream.
  EXPECT_EQ(-1, stream.Read(&num32, 1));

  // Read to the end of the stream.
  EXPECT_EQ(1, stream.Read(&num8, 1));  // 11
  EXPECT_EQ(0, stream.Read(&num8, 4));
  EXPECT_EQ(0, stream.Read(&num16, 2));
  EXPECT_EQ(0, stream.Read(&num32, 1));
}

TEST(PdbStreamTest, Seek) {
  TestPdbStream stream(5);
  EXPECT_EQ(0, stream.pos());

  // Valid seeks.
  EXPECT_TRUE(stream.Seek(0));
  EXPECT_EQ(0, stream.pos());

  EXPECT_TRUE(stream.Seek(3));
  EXPECT_EQ(3, stream.pos());

  EXPECT_TRUE(stream.Seek(5));
  EXPECT_EQ(5, stream.pos());

  // Invalid seek.
  EXPECT_FALSE(stream.Seek(6));
  EXPECT_EQ(5, stream.pos());
}
