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

  // A simple implementation of ReadBytes.
  bool ReadBytesAt(size_t pos, size_t count, void* dest) {
    ADD_FAILURE() << "No implementation here.";
    return false;
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

  scoped_refptr<TestMsfStream> stream2(new TestMsfStream(SIZE_MAX));
  EXPECT_EQ(0, stream2->length());
}

}  // namespace msf
