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

#include "syzygy/common/buffer_parser.h"
#include "gtest/gtest.h"

namespace common {

namespace {

const char kDataBuffer[] = {
  0, 1, 2, 3, 4, 5, 6, 7,
  8, 9, 10, 11, 12, 13, 14, 15,
  16, 17
};
size_t kDataBufferSize = sizeof(kDataBuffer);

}  // namespace

TEST(BinaryBufferParser, ContainsSucceedsInBuffer) {
  BinaryBufferParser parser(kDataBuffer, kDataBufferSize);

  // Verify that Contains succeeds and returns the right pointer
  // for ranges in the buffer.
  for (size_t offset = 0; offset < kDataBufferSize; ++offset) {
    for (size_t len = 0; len < kDataBufferSize - offset; ++len) {
      ASSERT_TRUE(parser.Contains(offset, len));
    }
  }
}

TEST(BinaryBufferParser, ContainsFailsOnOutOfBuffer) {
  BinaryBufferParser parser(kDataBuffer, kDataBufferSize);

  // Verify that Contains fails for ranges not in the buffer.
  for (size_t offset = 0; offset < kDataBufferSize + 1; ++offset) {
    ASSERT_FALSE(parser.Contains(offset, kDataBufferSize - offset + 1));
  }
}

TEST(BinaryBufferParser, ContainsFailsOnOverflow) {
  BinaryBufferParser parser(kDataBuffer, kDataBufferSize);

  // Verify that Contains fails for offsets that overflow the buffer.
  for (size_t offset = 1; offset < kDataBufferSize; ++offset) {
    ASSERT_FALSE(parser.Contains(-static_cast<int>(offset), offset));
    ASSERT_FALSE(parser.Contains(offset, -static_cast<int>(offset)));
  }
}

TEST(BinaryBufferParser, GetAtSucceedsInBuffer) {
  BinaryBufferParser parser(kDataBuffer, kDataBufferSize);

  // Verify that GetAt succeeds and returns the right pointer
  // for ranges in the buffer.
  for (size_t offset = 0; offset < kDataBufferSize; ++offset) {
    for (size_t len = 0; len < kDataBufferSize - offset; ++len) {
      const void* ptr = NULL;

      ASSERT_TRUE(parser.GetAt(offset, len, &ptr));
      ASSERT_TRUE(ptr != NULL);
      if (len > 0) {
        ASSERT_EQ(offset, *reinterpret_cast<const char*>(ptr));
      }
    }
  }
}

TEST(BinaryBufferParser, GetAtTyped) {
  struct Foo { int a; int b; };
  static const char kBuffer[sizeof(Foo) + 1];
  BinaryBufferParser parser(kBuffer, sizeof(kBuffer));

  const Foo* foo = NULL;
  ASSERT_TRUE(parser.GetAt(0, &foo));
  ASSERT_EQ(parser.data(), foo);

  ASSERT_TRUE(parser.GetAt(1, &foo));
  ASSERT_FALSE(parser.GetAt(2, &foo));
}

template <class CharType>
void TestGetStringAt() {
  static const CharType kBuf[] = {
      L'a', L'b', L'c', L'd', L'\0',
      L'e', L'f', L'g',
  };

  BinaryBufferParser parser(kBuf, sizeof(kBuf));
  const CharType* str = NULL;
  size_t len = 0;
  ASSERT_TRUE(parser.GetStringAt(0, &str, &len));
  ASSERT_EQ(4, len);

  ASSERT_TRUE(parser.GetStringAt(4 * sizeof(kBuf[0]), &str, &len));
  ASSERT_EQ(0, len);

  ASSERT_FALSE(parser.GetStringAt(5 * sizeof(kBuf[0]), &str, &len));
  ASSERT_FALSE(parser.GetStringAt(sizeof(kBuf), &str, &len));
}

TEST(BinaryBufferParser, GetStringAtSucceeds) {
  TestGetStringAt<char>();
}

TEST(BinaryBufferParser, GetStringAtWideSucceeds) {
  TestGetStringAt<wchar_t>();
}

TEST(BinaryBufferReader, IsAligned) {
  BinaryBufferReader reader(kDataBuffer, kDataBufferSize);

  EXPECT_TRUE(reader.IsAligned(1));
  EXPECT_TRUE(reader.IsAligned(2));
  EXPECT_TRUE(reader.IsAligned(4));
  EXPECT_TRUE(reader.IsAligned(8));

  EXPECT_TRUE(reader.Consume(1));

  EXPECT_TRUE(reader.IsAligned(1));
  EXPECT_FALSE(reader.IsAligned(2));
  EXPECT_FALSE(reader.IsAligned(4));
  EXPECT_FALSE(reader.IsAligned(8));

  EXPECT_TRUE(reader.Consume(3));
  EXPECT_TRUE(reader.IsAligned(1));
  EXPECT_TRUE(reader.IsAligned(2));
  EXPECT_TRUE(reader.IsAligned(4));
  EXPECT_FALSE(reader.IsAligned(8));
}

TEST(BinaryBufferReader, Align) {
  BinaryBufferReader reader(kDataBuffer, kDataBufferSize);

  EXPECT_TRUE(reader.Align(1));
  EXPECT_TRUE(reader.Align(2));
  EXPECT_TRUE(reader.Align(4));
  EXPECT_TRUE(reader.Align(8));

  EXPECT_EQ(0, reader.pos());

  EXPECT_TRUE(reader.Consume(1));
  EXPECT_TRUE(reader.Align(2));
  EXPECT_EQ(2, reader.pos());
  EXPECT_TRUE(reader.Align(4));
  EXPECT_EQ(4, reader.pos());
}

TEST(BinaryBufferReader, PeekSucceedsInBuffer) {
  BinaryBufferReader reader(kDataBuffer, kDataBufferSize);

  // Verify that Peek succeeds and returns the right pointer
  // for ranges in the buffer.
  for (size_t offset = 0; offset < kDataBufferSize; ++offset) {
    for (size_t len = 0; len < kDataBufferSize - offset; ++len) {
      const void* ptr = NULL;

      reader.set_pos(offset);
      ASSERT_TRUE(reader.Peek(len, &ptr));
      ASSERT_TRUE(ptr != NULL);
      if (len > 0) {
        ASSERT_EQ(offset, *reinterpret_cast<const char*>(ptr));
      }
    }
  }
}

TEST(BinaryBufferReader, Read) {
  BinaryBufferReader reader(kDataBuffer, kDataBufferSize);

  EXPECT_EQ(0, reader.pos());
  const char* ptr = NULL;
  EXPECT_TRUE(reader.Read(&ptr));
  EXPECT_EQ(0, *ptr);

  EXPECT_TRUE(reader.Read(2, &ptr));
  EXPECT_EQ(1, *ptr);

  EXPECT_TRUE(reader.Read(4, &ptr));
  EXPECT_EQ(3, *ptr);

  EXPECT_FALSE(reader.Read(kDataBufferSize, &ptr));
}

TEST(BinaryBufferReader, ReadCharString) {
  static const char kBuf[] = {
    L'a', L'b', L'c', L'd', L'\0', L'e', L'f', L'g', L'\0', L'h', L'i'
  };
  BinaryBufferReader reader(kBuf, sizeof(kBuf));

  const char* str = NULL;
  size_t str_len = 0;
  ASSERT_TRUE(reader.ReadString(&str, &str_len));
  EXPECT_STREQ("abcd", str);
  ASSERT_TRUE(reader.ReadString(&str, &str_len));
  EXPECT_STREQ("efg", str);
  ASSERT_FALSE(reader.ReadString(&str, &str_len));
}

TEST(BinaryBufferReader, ReadWideString) {
  static const wchar_t kBuf[] = {
    L'a', L'b', L'c', L'd', L'\0', L'e', L'f', L'g', L'\0', L'h', L'i'
  };
  BinaryBufferReader reader(kBuf, sizeof(kBuf));

  const wchar_t* str = NULL;
  size_t str_len = 0;
  ASSERT_TRUE(reader.ReadString(&str, &str_len));
  EXPECT_STREQ(L"abcd", str);
  ASSERT_TRUE(reader.ReadString(&str, &str_len));
  EXPECT_STREQ(L"efg", str);
  ASSERT_FALSE(reader.ReadString(&str, &str_len));
}

}  // namespace common
