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

const size_t kTestDataLen = 593;

class PdbStreamReaderTest : public testing::Test {
 public:
  void SetUp() override {
    // Make some test data.
    data_.reserve(kTestDataLen);
    for (size_t i = 0; i < kTestDataLen; ++i)
      data_.push_back(static_cast<uint8_t>(i));

    stream_ = new PdbByteStream();
    stream_->Init(&data_.at(0), data_.size());
  }

  std::vector<uint8_t> data_;
  scoped_refptr<PdbByteStream> stream_;
};

}  // namespace

using PdbStreamReaderWithPositionTest = PdbStreamReaderTest;

TEST_F(PdbStreamReaderWithPositionTest, ReadAll) {
  PdbStreamReaderWithPosition reader(stream_.get());
  EXPECT_FALSE(reader.AtEnd());
  EXPECT_EQ(0U, reader.Position());

  uint8_t buf[kTestDataLen] = {};
  EXPECT_TRUE(reader.Read(kTestDataLen, buf));
  EXPECT_EQ(0, ::memcmp(&data_.at(0), buf, sizeof(buf)));

  EXPECT_TRUE(reader.AtEnd());
  EXPECT_EQ(kTestDataLen, reader.Position());
  EXPECT_FALSE(reader.Read(1, buf));
}

TEST_F(PdbStreamReaderWithPositionTest, ReadPartial) {
  // Create a stream over a subset of the pdb stream_.
  const size_t kStartOffs = 4;
  const size_t kLength = 7;
  PdbStreamReaderWithPosition reader(kStartOffs, kLength, stream_.get());
  EXPECT_FALSE(reader.AtEnd());
  EXPECT_EQ(0U, reader.Position());

  uint8_t buf[kLength] = {};
  EXPECT_TRUE(reader.Read(sizeof(buf), buf));
  EXPECT_EQ(0, ::memcmp(&data_.at(kStartOffs), buf, kLength));

  EXPECT_TRUE(reader.AtEnd());
  EXPECT_EQ(kLength, reader.Position());
  EXPECT_FALSE(reader.Read(1, buf));
}

TEST_F(PdbStreamReaderWithPositionTest, SetStream) {
  // Test the SetStream case.
  const size_t kStartOffs = 19;
  const size_t kLength = 37;
  PdbStreamReaderWithPosition reader;
  reader.SetStream(kStartOffs, kLength, stream_.get());
  EXPECT_FALSE(reader.AtEnd());
  EXPECT_EQ(0U, reader.Position());

  uint8_t buf[kLength] = {};
  EXPECT_TRUE(reader.Read(sizeof(buf), buf));
  EXPECT_EQ(0, ::memcmp(&data_.at(kStartOffs), buf, kLength));

  EXPECT_TRUE(reader.AtEnd());
  EXPECT_EQ(kLength, reader.Position());
  EXPECT_FALSE(reader.Read(1, buf));
}

TEST_F(PdbStreamReaderWithPositionTest, EmptyTailRead) {
  // Create an empty stream over the tail of the stream.
  PdbStreamReaderWithPosition tail_empty(stream_->length(), 0, stream_.get());
  EXPECT_TRUE(tail_empty.AtEnd());
  EXPECT_EQ(0U, tail_empty.Position());
  uint8_t buf[1] = {};
  EXPECT_FALSE(tail_empty.Read(1, buf));
}

TEST_F(PdbStreamReaderWithPositionTest, EmptyCenterRead) {
  // Create an empty stream over center of the stream.
  PdbStreamReaderWithPosition middle_empty(stream_->length() / 2, 0,
                                           stream_.get());
  EXPECT_TRUE(middle_empty.AtEnd());
  EXPECT_EQ(0U, middle_empty.Position());
  uint8_t buf[1] = {};
  EXPECT_FALSE(middle_empty.Read(1, buf));
}

TEST_F(PdbStreamReaderWithPositionTest, Consume) {
  PdbStreamReaderWithPosition reader(stream_.get());

  EXPECT_EQ(0U, reader.Position());
  const size_t kSeekLength = kTestDataLen / 3;
  // Consume forward from start.
  EXPECT_TRUE(reader.Consume(kSeekLength));
  EXPECT_EQ(kSeekLength, reader.Position());

  // Consume forward again.
  EXPECT_TRUE(reader.Consume(kSeekLength));
  EXPECT_EQ(2 * kSeekLength, reader.Position());

  uint8_t buf[10] = {};
  static_assert(sizeof(buf) < kSeekLength, "buffer too large");
  EXPECT_TRUE(reader.Read(sizeof(buf), buf));
  EXPECT_EQ(2 * kSeekLength + sizeof(buf), reader.Position());
  EXPECT_EQ(0, ::memcmp(&data_.at(2 * kSeekLength), buf, sizeof(buf)));

  // Consume past the end of the file, and check that the position
  // hasn't changed.
  EXPECT_FALSE(reader.Consume(kSeekLength));
  EXPECT_EQ(2 * kSeekLength + sizeof(buf), reader.Position());

  // Consume right to the end of the file.
  EXPECT_TRUE(reader.Consume(kTestDataLen - reader.Position()));
  EXPECT_EQ(kTestDataLen, reader.Position());

  // And validate that we can't go past the end.
  EXPECT_FALSE(reader.Consume(1));
}

TEST_F(PdbStreamReaderWithPositionTest, CopyConstructor) {
  const uint8_t kData[] = { 0, 1, 2, 10 };
  scoped_refptr<PdbByteStream> stream(new PdbByteStream());
  stream->Init(kData, sizeof(kData));

  PdbStreamReaderWithPosition reader(stream.get());

  uint8_t data1[sizeof(kData)] = {};
  EXPECT_EQ(0U, reader.Position());

  PdbStreamReaderWithPosition reader2(reader);
  EXPECT_EQ(0U, reader2.Position());
  EXPECT_EQ(stream.get(), reader2.stream().get());

  EXPECT_TRUE(reader.Read(sizeof(data1), data1));

  EXPECT_EQ(sizeof(kData), reader.Position());
  EXPECT_EQ(0, reader2.Position());
  EXPECT_TRUE(reader.AtEnd());
  EXPECT_FALSE(reader2.AtEnd());
  EXPECT_EQ(0U, ::memcmp(kData, data1, sizeof(kData)));
  EXPECT_FALSE(reader.Read(1, data1));

  uint8_t data2[sizeof(kData)] = {};
  EXPECT_TRUE(reader2.Read(sizeof(data2), data2));
  EXPECT_EQ(sizeof(kData), reader2.Position());
  EXPECT_TRUE(reader2.AtEnd());
  EXPECT_EQ(0U, ::memcmp(kData, data2, sizeof(kData)));
  EXPECT_FALSE(reader2.Read(1, data2));
}

}  // namespace pdb
