// Copyright 2015 Google Inc. All Rights Reserved.
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

#include "syzygy/common/binary_stream.h"

#include "base/strings/string_piece.h"
#include "gtest/gtest.h"

namespace common {

namespace {

const char kTestString[] = "asdf";

class BinaryBufferStreamReaderTest : public testing::Test {
 public:
  void SetUp() override {
    // Initialize the read buffer to garbage.
    ::memset(buf_, 0xCC, sizeof(buf_));
  }

  char* buf() { return buf_; }

 protected:
  char buf_[1024];
};

}  // namespace

TEST_F(BinaryBufferStreamReaderTest, EmptyConstruction) {
  BinaryBufferStreamReader reader(nullptr, 0);
  EXPECT_FALSE(reader.Read(1, buf()));
}

TEST_F(BinaryBufferStreamReaderTest, BufferAndLenConstruction) {
  BinaryBufferStreamReader reader(kTestString, sizeof(kTestString));
  EXPECT_EQ(0U, reader.Position());
  EXPECT_FALSE(reader.AtEnd());
  // Read the string in one slurp.
  EXPECT_TRUE(reader.Read(sizeof(kTestString), buf()));
  EXPECT_EQ(sizeof(kTestString), reader.Position());
  EXPECT_TRUE(reader.AtEnd());

  EXPECT_EQ(0, ::memcmp(kTestString, buf(), sizeof(kTestString)));
  // Should be unable to read more bytes.
  EXPECT_FALSE(reader.Read(1, buf()));
}


TEST_F(BinaryBufferStreamReaderTest, StringPieceConstruction) {
  BinaryBufferStreamReader reader(
      base::StringPiece(kTestString, sizeof(kTestString)));
  // Read the string in one slurp.
  EXPECT_TRUE(reader.Read(sizeof(kTestString), buf()));

  EXPECT_EQ(0, ::memcmp(kTestString, buf(), sizeof(kTestString)));
  // Should be unable to read more bytes.
  EXPECT_FALSE(reader.Read(1, buf()));
}

using BinaryStreamParserTest = BinaryBufferStreamReaderTest;

TEST_F(BinaryStreamParserTest, ReadEmpty) {
  BinaryBufferStreamReader empty(nullptr, 0);
  BinaryStreamParser parser(&empty);

  EXPECT_EQ(&empty, parser.stream_reader());

  char chr = 0x1C;
  EXPECT_FALSE(parser.Read(&chr));
  EXPECT_EQ(0x1C, chr);
}

TEST_F(BinaryStreamParserTest, ReadData) {
  const uint32_t kTestData32 = 0xCAFEBABE;

  BinaryBufferStreamReader reader(&kTestData32, sizeof(kTestData32));
  BinaryStreamParser parser(&reader);

  uint32_t data = 0;
  EXPECT_TRUE(parser.Read(&data));
  EXPECT_EQ(kTestData32, data);

  char chr = 0x1C;
  EXPECT_FALSE(parser.Read(&chr));
  EXPECT_EQ(0x1C, chr);
}

TEST_F(BinaryStreamParserTest, ReadBytes) {
  const uint32_t kTestData32 = 0xCAFEBABE;

  BinaryBufferStreamReader reader(&kTestData32, sizeof(kTestData32));
  BinaryStreamParser parser(&reader);

  uint32_t data = 0;
  EXPECT_TRUE(parser.ReadBytes(sizeof(data), &data));
  EXPECT_EQ(kTestData32, data);

  char chr = 0x1C;
  EXPECT_FALSE(parser.Read(&chr));
  EXPECT_EQ(0x1C, chr);
}

TEST_F(BinaryStreamParserTest, ReadMultiple) {
  static const uint16_t kTestData[] = {0, 1, 2, 3, 4, 5, 6, 7};

  BinaryBufferStreamReader reader(kTestData, sizeof(kTestData));
  BinaryStreamParser parser(&reader);

  std::vector<uint16_t> data;
  const size_t kNumToRead = 3;
  static_assert(kNumToRead * 3 > arraysize(kTestData), "Array too small");

  // Read the first third of the data.
  EXPECT_TRUE(parser.ReadMultiple(kNumToRead, &data));
  EXPECT_EQ(kNumToRead, data.size());

  // Read the second third of the data.
  EXPECT_TRUE(parser.ReadMultiple(kNumToRead, &data));
  EXPECT_EQ(kNumToRead * 2, data.size());

  // Read past the end of the data.
  EXPECT_FALSE(parser.ReadMultiple(kNumToRead, &data));
  EXPECT_EQ(arraysize(kTestData), data.size());

  EXPECT_TRUE(std::equal(data.begin(), data.end(), kTestData));

  EXPECT_TRUE(reader.AtEnd());
}

TEST_F(BinaryStreamParserTest, ReadString) {
  // Two strings back-to-back.
  static const char kTestData[] = {
      'h', 'e', 'l', 'l', 'o', '\0', 'w', 'o', 'r', 'l', 'd'};

  BinaryBufferStreamReader reader(kTestData, sizeof(kTestData));
  BinaryStreamParser parser(&reader);

  std::string hello;
  EXPECT_TRUE(parser.ReadString(&hello));
  EXPECT_EQ("hello", hello);
  EXPECT_EQ(5U, hello.size());

  std::string world;
  EXPECT_FALSE(parser.ReadString(&world));
  EXPECT_EQ("world", world);
  EXPECT_EQ(5u, world.size());

  char chr = 0x1C;
  EXPECT_FALSE(parser.Read(&chr));
  EXPECT_EQ(0x1C, chr);
}

TEST_F(BinaryStreamParserTest, ReadWideString) {
  // Two strings back-to-back.
  static const wchar_t kTestData[] = {
      'h', 'e', 'l', 'l', 'o', '\0', 'w', 'o', 'r', 'l', 'd'};

  BinaryBufferStreamReader reader(kTestData, sizeof(kTestData));
  BinaryStreamParser parser(&reader);

  std::wstring hello;
  EXPECT_TRUE(parser.ReadString(&hello));
  EXPECT_EQ(L"hello", hello);
  EXPECT_EQ(5U, hello.size());

  std::wstring world;
  EXPECT_FALSE(parser.ReadString(&world));
  EXPECT_EQ(L"world", world);
  EXPECT_EQ(5u, world.size());

  wchar_t chr = 0x1C;
  EXPECT_FALSE(parser.Read(&chr));
  EXPECT_EQ(0x1C, chr);
}

TEST_F(BinaryStreamParserTest, AlignTo) {
  std::vector<uint8_t> data(1024, 0xCC);
  BinaryBufferStreamReader reader(&data.at(0), data.size());
  BinaryStreamParser parser(&reader);

  EXPECT_EQ(0U, reader.Position());
  // Shouldn't move, zero is aligned to all by definition.
  EXPECT_TRUE(parser.AlignTo(5));
  EXPECT_TRUE(parser.AlignTo(4));
  EXPECT_EQ(0U, reader.Position());

  EXPECT_TRUE(parser.ReadBytes(5, buf_));
  EXPECT_EQ(5U, reader.Position());

  // Try a couple of alignments.
  EXPECT_TRUE(parser.AlignTo(4));
  EXPECT_EQ(8U, reader.Position());

  EXPECT_TRUE(parser.AlignTo(5));
  EXPECT_EQ(10U, reader.Position());

  EXPECT_FALSE(parser.AlignTo(data.size() + 1));
  EXPECT_TRUE(reader.AtEnd());
}

}  // namespace common
