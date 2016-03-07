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

#include "syzygy/core/zstream.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/core/serialization.h"

namespace core {

namespace {

const uint8_t kSampleData[] =
    "This is some simple sample data. Simple is as "
    "simple does. Similar samples are amply simple to "
    "compress.";

class ZOutStreamTest : public ::testing::Test {
 public:
  void SetUp() {
    out_stream_.reset(CreateByteOutStream(std::back_inserter(compressed_)));
  }

  std::vector<uint8_t> compressed_;
  ScopedOutStreamPtr out_stream_;
};

class ZInStreamTest : public ::testing::Test {
 public:
  void SetUp() {
    // Compress the sample data so that we have something to read from.
    ScopedOutStreamPtr out_stream(
        CreateByteOutStream(std::back_inserter(compressed_)));
    ZOutStream zout(out_stream.get());
    ASSERT_TRUE(zout.Init());
    ASSERT_TRUE(zout.Write(sizeof(kSampleData), kSampleData));
    ASSERT_TRUE(zout.Flush());
    ASSERT_LT(0u, compressed_.size());

    in_stream_.reset(CreateByteInStream(compressed_.begin(),
                                        compressed_.end()));
  }

  std::vector<uint8_t> compressed_;
  ScopedInStreamPtr in_stream_;
  uint8_t buffer[2 * sizeof(kSampleData)];
};

}  // namespace

TEST_F(ZOutStreamTest, DoingNothingProducesNoData) {
  ZOutStream zip_stream(out_stream_.get());
  EXPECT_EQ(0u, compressed_.size());
  EXPECT_TRUE(zip_stream.Init());
  EXPECT_EQ(0u, compressed_.size());
}

TEST_F(ZOutStreamTest, DoingSomethingProducesData) {
  ZOutStream zip_stream(out_stream_.get());
  EXPECT_TRUE(zip_stream.Init());
  EXPECT_TRUE(zip_stream.Write(sizeof(kSampleData), kSampleData));
  EXPECT_TRUE(zip_stream.Flush());
  EXPECT_LT(0u, compressed_.size());
}

TEST_F(ZInStreamTest, ReadingTruncatedDataFails) {
  EXPECT_LT(2u, compressed_.size());
  compressed_.resize(compressed_.size() / 2);
  in_stream_.reset(CreateByteInStream(compressed_.begin(),
                                      compressed_.end()));

  ZInStream unzip_stream(in_stream_.get());
  EXPECT_TRUE(unzip_stream.Init());
  size_t bytes_read = 0;
  EXPECT_FALSE(unzip_stream.Read(sizeof(buffer), buffer, &bytes_read));
}

TEST_F(ZInStreamTest, DecompressionWorks) {
  ZInStream unzip_stream(in_stream_.get());
  EXPECT_TRUE(unzip_stream.Init());
  EXPECT_TRUE(unzip_stream.Read(sizeof(kSampleData), buffer));
  EXPECT_STREQ(reinterpret_cast<const char*>(buffer),
               reinterpret_cast<const char*>(kSampleData));
}

TEST(ZStreamTest, RoundTrip) {
  std::vector<uint8_t> compressed;
  std::vector<uint8_t> decompressed;

  ScopedOutStreamPtr out_stream(
      CreateByteOutStream(std::back_inserter(compressed)));
  ZOutStream zip_stream(out_stream.get());
  EXPECT_TRUE(zip_stream.Init());
  EXPECT_TRUE(zip_stream.Write(sizeof(kSampleData), kSampleData));
  EXPECT_TRUE(zip_stream.Flush());

  ScopedInStreamPtr in_stream(
      CreateByteInStream(compressed.begin(), compressed.end()));
  ZInStream unzip_stream(in_stream.get());
  EXPECT_TRUE(unzip_stream.Init());

  // We deliberately try to read more data than necessary to ensure that the
  // decoder recognizes the end of stream on its own.
  decompressed.resize(2 * sizeof(kSampleData));
  size_t bytes_read = 0;
  EXPECT_TRUE(unzip_stream.Read(decompressed.size(),
                                &decompressed[0],
                                &bytes_read));
  EXPECT_EQ(sizeof(kSampleData), bytes_read);
  decompressed.resize(bytes_read);

  // We shouldn't be able to read any more data from either stream.
  uint8_t buffer[1] = {};
  bytes_read = 0;
  EXPECT_TRUE(unzip_stream.Read(sizeof(buffer), buffer, &bytes_read));
  EXPECT_EQ(0, bytes_read);

  bytes_read = 0;
  EXPECT_TRUE(in_stream->Read(sizeof(buffer), buffer, &bytes_read));
  EXPECT_EQ(0, bytes_read);

  EXPECT_THAT(decompressed, testing::ElementsAreArray(kSampleData));
}

}  // namespace core
