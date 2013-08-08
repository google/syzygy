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

#include "syzygy/common/buffer_writer.h"

#include "gtest/gtest.h"

namespace common {

namespace {

struct {
  uint32 i;
  uint16 iarray[2];
  char string[2];
  char unused1;
  char unused2;
  wchar_t wstring[2];
} const kExpectedData = { 0x12345678, { 0xDEAD, 0xBEEF }, "f", 0, 0, L"b" };
COMPILE_ASSERT(sizeof(kExpectedData) == 16,
               alignment_issues_with_expected_data);

class BufferWriterTest : public ::testing::Test {
 public:
  virtual void SetUp() {
    ::memset(buffer_, 0, sizeof(buffer_));
  }

  void WriteData(BufferWriter* writer) {
    ASSERT_TRUE(writer != NULL);

    uint32 i = 0x12345678;  // 4 bytes.
    uint16 iarray[2] = { 0xDEAD, 0xBEEF };  // 4 bytes
    char string[] = "f";  // 2 bytes.
    wchar_t wstring[] = L"b";  // 4 bytes.

    ASSERT_EQ(0u, writer->pos());
    ASSERT_TRUE(writer->Write(sizeof(i), (void*)(&i)));  // 4 bytes.
    ASSERT_EQ(4u, writer->pos());
    ASSERT_TRUE(writer->Write(arraysize(iarray), iarray));  // 4 bytes.
    ASSERT_EQ(8u, writer->pos());
    ASSERT_TRUE(writer->WriteString(string));  // 2 bytes.
    ASSERT_EQ(10u, writer->pos());
    ASSERT_FALSE(writer->IsAligned(4));
    ASSERT_TRUE(writer->Align(4));  // 2 bytes.
    ASSERT_EQ(12u, writer->pos());
    ASSERT_TRUE(writer->WriteString(wstring));  // 4 bytes.
    ASSERT_EQ(16u, writer->pos());
  }

  std::vector<uint8> vector_;
  uint8 buffer_[16];
};

}  // namespace

TEST_F(BufferWriterTest, SimpleAccessorsAndMutators) {
  BufferWriter writer(buffer_, sizeof(buffer_));
  EXPECT_EQ(0u, writer.pos());
  EXPECT_EQ(sizeof(buffer_), writer.length());
  EXPECT_EQ(sizeof(buffer_), writer.RemainingBytes());

  writer.set_pos(10);
  EXPECT_EQ(10u, writer.pos());
  EXPECT_EQ(sizeof(buffer_) - 10, writer.RemainingBytes());

  // We should be able to set positions past the end of the buffer without
  // harm.
  writer.set_pos(sizeof(buffer_) + 10);
  EXPECT_EQ(sizeof(buffer_) + 10, writer.pos());
  EXPECT_EQ(0u, writer.RemainingBytes());
}

TEST_F(BufferWriterTest, WriteBehaviour) {
  BufferWriter writer(buffer_, sizeof(buffer_));

  EXPECT_TRUE(writer.Consume(1));
  EXPECT_EQ(1u, writer.pos());
  EXPECT_FALSE(writer.Consume(sizeof(buffer_)));  // Write past the end.
  EXPECT_FALSE(writer.Consume(0xFFFFFFFF));  // Overflow of pos_.

  uint8 data8[sizeof(buffer_)] = {};

  EXPECT_TRUE(writer.Write(1, data8));
  EXPECT_EQ(2u, writer.pos());
  EXPECT_FALSE(writer.Write(arraysize(data8), (void*)data8));

  uint16 data16[sizeof(buffer_) / 2] = {};
  EXPECT_TRUE(writer.Write(1, data16));
  EXPECT_EQ(4u, writer.pos());
  EXPECT_FALSE(writer.Write(arraysize(data16), data16));

  uint16 small_datum = 42;
  struct {
    uint8 buffer[sizeof(buffer_)];
  } big_datum = {};

  EXPECT_TRUE(writer.Write(small_datum));
  EXPECT_EQ(6u, writer.pos());
  EXPECT_FALSE(writer.Write(big_datum));

  char small_string[] = "h";
  char big_string[] = "the quick brown fox SAY WHAT?";
  COMPILE_ASSERT(sizeof(big_string) >= sizeof(buffer_),
                 big_string_too_small);

  EXPECT_TRUE(writer.WriteString(small_string));
  EXPECT_EQ(8u, writer.pos());
  EXPECT_FALSE(writer.WriteString(big_string));

  wchar_t small_wstring[] = L"z";
  wchar_t big_wstring[] = L"sally sells seashells";
  COMPILE_ASSERT(sizeof(big_wstring) >= sizeof(buffer_),
                 big_wstring_too_small);

  EXPECT_TRUE(writer.WriteString(small_wstring));
  EXPECT_EQ(12u, writer.pos());
  EXPECT_FALSE(writer.WriteString(big_wstring));
}

TEST_F(BufferWriterTest, AlignAndIsAligned) {
  BufferWriter writer(buffer_, sizeof(buffer_));

  EXPECT_TRUE(writer.IsAligned(1));
  EXPECT_TRUE(writer.IsAligned(2));
  EXPECT_TRUE(writer.IsAligned(4));
  EXPECT_TRUE(writer.IsAligned(8));

  writer.set_pos(3);
  EXPECT_TRUE(writer.IsAligned(1));
  EXPECT_FALSE(writer.IsAligned(2));
  EXPECT_FALSE(writer.IsAligned(4));
  EXPECT_FALSE(writer.IsAligned(8));

  EXPECT_TRUE(writer.Align(4));
  EXPECT_EQ(4u, writer.pos());
  EXPECT_TRUE(writer.IsAligned(1));
  EXPECT_TRUE(writer.IsAligned(2));
  EXPECT_TRUE(writer.IsAligned(4));
  EXPECT_FALSE(writer.IsAligned(8));

  EXPECT_TRUE(writer.Align(8));
  EXPECT_EQ(8u, writer.pos());
  EXPECT_TRUE(writer.IsAligned(1));
  EXPECT_TRUE(writer.IsAligned(2));
  EXPECT_TRUE(writer.IsAligned(4));
  EXPECT_TRUE(writer.IsAligned(8));

  // We don't have room for this alignment.
  COMPILE_ASSERT(32 > sizeof(buffer_), need_a_bigger_failing_alignment);
  EXPECT_FALSE(writer.Align(32));
}

TEST_F(BufferWriterTest, WriteToBuffer) {
  BufferWriter writer(buffer_, sizeof(buffer_));

  ASSERT_NO_FATAL_FAILURE(WriteData(&writer));
  EXPECT_EQ(sizeof(kExpectedData), writer.pos());
  EXPECT_EQ(0, ::memcmp(&kExpectedData, buffer_, sizeof(kExpectedData)));
}

TEST_F(BufferWriterTest, WriteToVector) {
  VectorBufferWriter writer(&vector_);
  vector_.resize(8);

  ASSERT_NO_FATAL_FAILURE(WriteData(&writer));
  EXPECT_EQ(sizeof(kExpectedData), writer.pos());
  EXPECT_EQ(0, ::memcmp(&kExpectedData, &vector_[0], sizeof(kExpectedData)));
}

}  // namespace common
