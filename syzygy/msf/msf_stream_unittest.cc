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

#include "syzygy/msf/msf_stream.h"

#include "gtest/gtest.h"

namespace msf {

namespace {

class TestMsfStream : public MsfStream {
 public:
  explicit TestMsfStream(size_t length) : MsfStream(length) {}

  using MsfStream::pos;

  // A simple implementation of ReadBytes.
  bool ReadBytesAt(size_t pos, size_t count, void* dest) {
    DCHECK(dest != NULL);

    if (count > length() - pos) {
      return false;
    }

    return true;
  }
};

struct Foo {
  uint32_t i;
  double d;
};

struct Bar {
  Foo foo1;
  Foo foo2;
};

}  // namespace

TEST(MsfStreamTest, Constructor) {
  scoped_refptr<TestMsfStream> stream(new TestMsfStream(5));
  EXPECT_EQ(5, stream->length());
  EXPECT_EQ(0, stream->pos());

  scoped_refptr<TestMsfStream> stream2(new TestMsfStream(SIZE_MAX));
  EXPECT_EQ(0, stream2->length());
  EXPECT_EQ(0, stream2->pos());
}

TEST(MsfStreamTest, Read) {
  scoped_refptr<TestMsfStream> stream(new TestMsfStream(12));
  uint8_t num8;
  uint16_t num16;
  uint32_t num32;

  // 3 valid reads.
  EXPECT_TRUE(stream->Read(&num8, 3));   // 0..2
  EXPECT_TRUE(stream->Read(&num16, 2));  // 3..6
  EXPECT_TRUE(stream->Read(&num32, 1));  // 7..10

  // Try to read over the end of the stream.
  EXPECT_FALSE(stream->Read(&num32, 1));

  // Read to the end of the stream, using the version of read that reports
  // the number of items read.
  EXPECT_TRUE(stream->Read(&num8, 1));  // 11

  // Read over the end of the stream.
  EXPECT_FALSE(stream->Read(&num8, 4));
}

TEST(MsfStreamTest, ReadVector) {
  scoped_refptr<TestMsfStream> stream(new TestMsfStream(sizeof(Foo) * 10));

  std::vector<Foo> foos;

  // A couple of valid reads.
  EXPECT_TRUE(stream->Read(&foos, 2));  // 0..1
  EXPECT_EQ(2u, foos.size());
  EXPECT_TRUE(stream->Read(&foos, 3));  // 2..4
  EXPECT_EQ(3u, foos.size());

  // Try to read past the end of the stream->
  EXPECT_FALSE(stream->Read(&foos, 6));

  // There are 5 elements left. If we try to read Bars until the end of the
  // stream it should fail as 5 Foos = 2.5 Bars.
  std::vector<Bar> bars;
  EXPECT_FALSE(stream->Read(&bars));

  // However, we should be able to read Foos until the end of the stream.
  EXPECT_TRUE(stream->Read(&foos));
  EXPECT_EQ(5u, foos.size());
}

TEST(MsfStreamTest, Seek) {
  scoped_refptr<TestMsfStream> stream(new TestMsfStream(5));
  EXPECT_EQ(0, stream->pos());

  // Valid seeks.
  EXPECT_TRUE(stream->Seek(0));
  EXPECT_EQ(0, stream->pos());

  EXPECT_TRUE(stream->Seek(3));
  EXPECT_EQ(3, stream->pos());

  EXPECT_TRUE(stream->Seek(5));
  EXPECT_EQ(5, stream->pos());

  // Invalid seek.
  EXPECT_FALSE(stream->Seek(6));
  EXPECT_EQ(5, stream->pos());
}

}  // namespace msf
