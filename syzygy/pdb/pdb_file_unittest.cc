// Copyright 2012 Google Inc.
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

#include "syzygy/pdb/pdb_file.h"

#include "base/memory/scoped_ptr.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace pdb {

namespace {

class DummyPdbStream : public PdbStream {
 public:
  DummyPdbStream() : PdbStream(10) {
    ++instance_count_;
  }

  virtual bool ReadBytes(void* dest, size_t count, size_t* bytes_read) {
    return false;
  }

  static size_t instance_count() { return instance_count_; }

 protected:
  virtual ~DummyPdbStream() {
    --instance_count_;
  }

  static size_t instance_count_;
};

size_t DummyPdbStream::instance_count_;

}  // namespace

TEST(PdbFileTest, Clear) {
  PdbFile pdb_file;
  EXPECT_EQ(0u, pdb_file.StreamCount());
  EXPECT_EQ(0u, DummyPdbStream::instance_count());

  pdb_file.AppendStream(new DummyPdbStream());
  EXPECT_EQ(1u, pdb_file.StreamCount());
  EXPECT_EQ(1u, DummyPdbStream::instance_count());

  pdb_file.AppendStream(new DummyPdbStream());
  EXPECT_EQ(2u, pdb_file.StreamCount());
  EXPECT_EQ(2u, DummyPdbStream::instance_count());

  pdb_file.SetStream(100, new DummyPdbStream());
  EXPECT_EQ(101u, pdb_file.StreamCount());
  EXPECT_TRUE(pdb_file.GetStream(99) == NULL);
  EXPECT_EQ(3u, DummyPdbStream::instance_count());

  pdb_file.Clear();
  EXPECT_EQ(0u, pdb_file.StreamCount());
  EXPECT_EQ(0u, DummyPdbStream::instance_count());
}

TEST(PdbFileTest, WorksAsExpected) {
  scoped_ptr<PdbFile> pdb(new PdbFile());
  EXPECT_EQ(0u, pdb->StreamCount());
  EXPECT_EQ(0u, DummyPdbStream::instance_count());

  scoped_refptr<PdbStream> stream(new DummyPdbStream());
  EXPECT_EQ(1u, DummyPdbStream::instance_count());
  size_t index0 = pdb->AppendStream(stream.get());
  EXPECT_EQ(0u, index0);
  EXPECT_EQ(1u, pdb->StreamCount());
  EXPECT_EQ(stream.get(), pdb->GetStream(index0));

  stream = new DummyPdbStream();
  EXPECT_EQ(2u, DummyPdbStream::instance_count());
  size_t index1 = pdb->AppendStream(stream.get());
  EXPECT_EQ(1u, index1);
  EXPECT_EQ(2u, pdb->StreamCount());
  EXPECT_EQ(stream.get(), pdb->GetStream(index1));
  PdbStream* stream1 = stream.get();

  stream = new DummyPdbStream();
  EXPECT_EQ(3u, DummyPdbStream::instance_count());
  pdb->ReplaceStream(index0, stream.get());
  EXPECT_EQ(2u, DummyPdbStream::instance_count());
  EXPECT_EQ(2u, pdb->StreamCount());
  EXPECT_EQ(stream.get(), pdb->GetStream(index0));
  PdbStream* stream0 = stream.get();
  stream = NULL;

  EXPECT_EQ(stream0, pdb->GetStream(0));
  EXPECT_EQ(stream1, pdb->GetStream(1));

  pdb.reset(NULL);
  EXPECT_EQ(0u, DummyPdbStream::instance_count());
}

}  // namespace pdb
