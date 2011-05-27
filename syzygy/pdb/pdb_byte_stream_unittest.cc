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

#include "syzygy/pdb/pdb_byte_stream.h"
#include "gtest/gtest.h"

namespace {

using pdb::PdbByteStream;
using pdb::PdbStream;

class TestPdbByteStream : public PdbByteStream {
 public:
  TestPdbByteStream() : PdbByteStream() {
  }

  using PdbByteStream::ReadBytes;
};

class TestPdbStream : public PdbStream {
 public:
  explicit TestPdbStream(size_t length) : PdbStream(length) {
  }

 protected:
  bool ReadBytes(void* dest, size_t count, size_t* bytes_read) {
    DCHECK(dest != NULL);
    DCHECK(bytes_read != NULL);

    if (pos() == length()) {
      bytes_read = 0;
      return true;
    }

    count = std::min(count, length() - pos());
    memset(dest, 0xFF, count);
    Seek(pos() + count);
    *bytes_read = count;

    return true;
  }
};

}  // namespace

TEST(PdbByteStreamTest, InitFromByteArray) {
  uint8 data[] = {1, 2, 3, 4, 5, 6, 7, 8};

  PdbByteStream stream;
  EXPECT_TRUE(stream.Init(data, arraysize(data)));
  EXPECT_EQ(arraysize(data), stream.length());
  EXPECT_TRUE(stream.data() != NULL);

  for (size_t i = 0; i < stream.length(); ++i) {
    uint8 num = 0;
    EXPECT_TRUE(stream.Read(&num, 1));
    EXPECT_EQ(data[i], num);
  }
}

TEST(PdbByteStreamTest, InitFromPdbStream) {
  TestPdbStream test_stream(64);

  PdbByteStream stream;
  EXPECT_TRUE(stream.Init(&test_stream));
  EXPECT_EQ(test_stream.length(), stream.length());
  EXPECT_TRUE(stream.data() != NULL);

  for (size_t i = 0; i < stream.length(); ++i) {
    uint8 num = 0;
    EXPECT_TRUE(stream.Read(&num, 1));
    EXPECT_EQ(0xFF, num);
  }
}

TEST(PdbByteStreamTest, ReadBytes) {
  size_t len = 17;
  TestPdbStream test_stream(len);

  TestPdbByteStream stream;
  EXPECT_TRUE(stream.Init(&test_stream));

  int total_bytes = 0;
  while (true) {
    uint8 buffer[4];
    size_t bytes_read = 0;
    EXPECT_TRUE(stream.ReadBytes(buffer, sizeof(buffer), &bytes_read));
    if (bytes_read == 0)
      break;
    total_bytes += bytes_read;
  }

  EXPECT_EQ(len, total_bytes);
}
