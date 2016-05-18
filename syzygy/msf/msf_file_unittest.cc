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

#include "syzygy/msf/msf_file.h"

#include <memory>

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace msf {

namespace {

class DummyMsfStream : public MsfStream {
 public:
  DummyMsfStream() : MsfStream(10) { ++instance_count_; }

  bool ReadBytesAt(size_t pos, size_t count, void* dest) override {
    return false;
  }

  static size_t instance_count() { return instance_count_; }

 protected:
  virtual ~DummyMsfStream() { --instance_count_; }

  static size_t instance_count_;
};

size_t DummyMsfStream::instance_count_;

}  // namespace

TEST(MsfFileTest, Clear) {
  MsfFile msf_file;
  EXPECT_EQ(0u, msf_file.StreamCount());
  EXPECT_EQ(0u, DummyMsfStream::instance_count());

  msf_file.AppendStream(new DummyMsfStream());
  EXPECT_EQ(1u, msf_file.StreamCount());
  EXPECT_EQ(1u, DummyMsfStream::instance_count());

  msf_file.AppendStream(new DummyMsfStream());
  EXPECT_EQ(2u, msf_file.StreamCount());
  EXPECT_EQ(2u, DummyMsfStream::instance_count());

  msf_file.SetStream(100, new DummyMsfStream());
  EXPECT_EQ(101u, msf_file.StreamCount());
  EXPECT_TRUE(msf_file.GetStream(99) == NULL);
  EXPECT_EQ(3u, DummyMsfStream::instance_count());

  msf_file.Clear();
  EXPECT_EQ(0u, msf_file.StreamCount());
  EXPECT_EQ(0u, DummyMsfStream::instance_count());
}

TEST(MsfFileTest, WorksAsExpected) {
  std::unique_ptr<MsfFile> msf(new MsfFile());
  EXPECT_EQ(0u, msf->StreamCount());
  EXPECT_EQ(0u, DummyMsfStream::instance_count());

  scoped_refptr<MsfStream> stream(new DummyMsfStream());
  EXPECT_EQ(1u, DummyMsfStream::instance_count());
  size_t index0 = msf->AppendStream(stream.get());
  EXPECT_EQ(0u, index0);
  EXPECT_EQ(1u, msf->StreamCount());
  EXPECT_EQ(stream.get(), msf->GetStream(index0));

  stream = new DummyMsfStream();
  EXPECT_EQ(2u, DummyMsfStream::instance_count());
  size_t index1 = msf->AppendStream(stream.get());
  EXPECT_EQ(1u, index1);
  EXPECT_EQ(2u, msf->StreamCount());
  EXPECT_EQ(stream.get(), msf->GetStream(index1));
  MsfStream* stream1 = stream.get();

  stream = new DummyMsfStream();
  EXPECT_EQ(3u, DummyMsfStream::instance_count());
  msf->ReplaceStream(index0, stream.get());
  EXPECT_EQ(2u, DummyMsfStream::instance_count());
  EXPECT_EQ(2u, msf->StreamCount());
  EXPECT_EQ(stream.get(), msf->GetStream(index0));
  MsfStream* stream0 = stream.get();
  stream = NULL;

  EXPECT_EQ(stream0, msf->GetStream(0));
  EXPECT_EQ(stream1, msf->GetStream(1));

  msf.reset(NULL);
  EXPECT_EQ(0u, DummyMsfStream::instance_count());
}

}  // namespace msf
