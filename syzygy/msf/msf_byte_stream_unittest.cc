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

#include "syzygy/msf/msf_byte_stream.h"

#include <algorithm>

#include "gtest/gtest.h"

namespace msf {

namespace {

class TestMsfStream : public MsfStream {
 public:
  explicit TestMsfStream(size_t length) : MsfStream(length) {}

  virtual ~TestMsfStream() {}

  bool ReadBytesAt(size_t pos, size_t count, void* dest) override {
    DCHECK(dest != NULL);

    if (count > length() - pos)
      return false;

    ::memset(dest, 0xFF, count);

    return true;
  }
};

}  // namespace

TEST(MsfByteStreamTest, InitFromByteArray) {
  uint8_t data[] = {1, 2, 3, 4, 5, 6, 7, 8};

  scoped_refptr<MsfByteStream> stream(new MsfByteStream());
  EXPECT_TRUE(stream->Init(data, arraysize(data)));
  EXPECT_EQ(arraysize(data), stream->length());
  EXPECT_TRUE(stream->data() != NULL);

  for (size_t i = 0; i < stream->length(); ++i) {
    uint8_t num = 0;
    EXPECT_TRUE(stream->ReadBytesAt(i, 1, &num));
    EXPECT_EQ(data[i], num);
  }
}

TEST(MsfByteStreamTest, InitFromMsfStream) {
  scoped_refptr<TestMsfStream> test_stream(new TestMsfStream(64));

  scoped_refptr<MsfByteStream> stream(new MsfByteStream());
  EXPECT_TRUE(stream->Init(test_stream.get()));
  EXPECT_EQ(test_stream->length(), stream->length());
  EXPECT_TRUE(stream->data() != NULL);

  for (size_t i = 0; i < stream->length(); ++i) {
    uint8_t num = 0;
    EXPECT_TRUE(stream->ReadBytesAt(i, 1, &num));
    EXPECT_EQ(0xFF, num);
  }
}

TEST(MsfByteStreamTest, InitFromMsfStreamPart) {
  uint8_t data[] = {0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8};
  scoped_refptr<MsfByteStream> test_stream(new MsfByteStream());
  EXPECT_TRUE(test_stream->Init(data, arraysize(data)));

  scoped_refptr<MsfByteStream> stream(new MsfByteStream());
  EXPECT_TRUE(stream->Init(test_stream.get(), 2, 7));
  EXPECT_EQ(7, stream->length());
  EXPECT_TRUE(stream->data() != NULL);

  for (size_t i = 0; i < stream->length(); ++i) {
    uint8_t num = 0;
    EXPECT_TRUE(stream->ReadBytesAt(i, 1, &num));
    EXPECT_EQ(data[i + 2], num);
  }
}

TEST(MsfByteStreamTest, ReadBytesAt) {
  uint8_t data[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13};
  scoped_refptr<MsfByteStream> stream(new MsfByteStream());
  EXPECT_TRUE(stream->Init(data, arraysize(data)));

  // Try a few in-bounds reads.
  for (size_t pos = 0; pos < sizeof(data); ++pos) {
    uint8_t buffer[4] = {};
    size_t to_read = std::min(sizeof(buffer), stream->length() - pos);
    EXPECT_TRUE(stream->ReadBytesAt(pos, to_read, buffer));

    EXPECT_EQ(0U, ::memcmp(buffer, data + pos, to_read));
  }

  // Try some out of bounds reads.
  for (size_t len = 1; len <= sizeof(data); ++len) {
    uint8_t buf[sizeof(data) + 1] = {};

    EXPECT_FALSE(stream->ReadBytesAt(sizeof(data) - len + 1, len, buf));
    for (auto c : buf)
      EXPECT_EQ(0U, c);
  }
}

TEST(MsfByteStreamTest, GetWritableStream) {
  scoped_refptr<MsfStream> stream(new MsfByteStream());
  scoped_refptr<WritableMsfStream> writer1 = stream->GetWritableStream();
  EXPECT_TRUE(writer1.get() != NULL);

  // NOTE: This is a condition that only needs to be true currently because
  //     of limitations in the WritableMsfByteStream implementation. When we
  //     move to a proper interface implementation with shared storage state,
  //     this limitation will be removed.
  scoped_refptr<WritableMsfStream> writer2 = stream->GetWritableStream();
  EXPECT_EQ(writer1.get(), writer2.get());
}

TEST(WritableMsfByteStreamTest, WriterChangesReaderLengthButNotCursor) {
  scoped_refptr<MsfStream> reader(new MsfByteStream());
  scoped_refptr<WritableMsfStream> writer = reader->GetWritableStream();
  ASSERT_TRUE(writer.get() != NULL);

  EXPECT_EQ(reader->length(), 0u);
  EXPECT_EQ(writer->length(), 0u);
  EXPECT_EQ(writer->pos(), 0u);
  writer->Consume(10);
  EXPECT_EQ(reader->length(), 10u);
  EXPECT_EQ(writer->length(), 10u);
  EXPECT_EQ(writer->pos(), 10u);
}

}  // namespace msf
