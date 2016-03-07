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

#include "syzygy/pdb/mutators/add_named_stream_mutator.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pdb/pdb_byte_stream.h"
#include "syzygy/pdb/pdb_reader.h"
#include "syzygy/pdb/unittest_util.h"

namespace pdb {
namespace mutators {

namespace {

using testing::_;
using testing::Invoke;
using testing::Ref;
using testing::Return;
using testing::StrictMock;

class MockAddNamedStreamMutator
    : public AddNamedStreamMutatorImpl<MockAddNamedStreamMutator> {
 public:
  static const char kMutatorName[];

  MOCK_METHOD1(AddNamedStreams, bool(const PdbFile& pdb_file));

  bool AddFooStream(const PdbFile& pdb_file) {
    scoped_refptr<PdbByteStream> stream(new PdbByteStream());
    EXPECT_TRUE(stream->Init(reinterpret_cast<const uint8_t*>(kMutatorName),
                             ::strlen(kMutatorName)));
    added_stream_ = stream;
    EXPECT_TRUE(SetNamedStream("foo", stream.get()));
    return true;
  }

  bool GetAndReplaceFooStream(const PdbFile& pdb_file) {
    scoped_refptr<PdbStream> foo = GetNamedStream("foo");
    EXPECT_TRUE(foo.get() != NULL);

    scoped_refptr<PdbByteStream> stream(new PdbByteStream());
    EXPECT_TRUE(stream->Init(foo.get()));

    added_stream_ = stream;
    EXPECT_FALSE(SetNamedStream("foo", stream.get()));
    return true;
  }

  scoped_refptr<PdbStream> added_stream_;
};

const char MockAddNamedStreamMutator::kMutatorName[] =
    "MockAddNamedStreamMutator";

class AddNamedStreamMutatorTest : public testing::Test {
 public:
  virtual void SetUp() override { testing::Test::SetUp(); }

  void ReadActualPdb() {
    base::FilePath pdb_path =
        testing::GetSrcRelativePath(testing::kTestPdbFilePath);
    PdbReader pdb_reader;
    EXPECT_TRUE(pdb_reader.Read(pdb_path, &pdb_file_));
  }

  void CheckFooStreamAdded() {
    // Read the named stream map and ensure the stream was properly added.
    PdbInfoHeader70 header = {};
    NameStreamMap name_stream_map;
    ASSERT_TRUE(pdb::ReadHeaderInfoStream(pdb_file_, &header,
                                          &name_stream_map));
    ASSERT_TRUE(name_stream_map.count("foo"));
    size_t stream_id = name_stream_map["foo"];
    ASSERT_GT(pdb_file_.StreamCount(), stream_id);
    scoped_refptr<PdbStream> stream(pdb_file_.GetStream(stream_id));
    ASSERT_EQ(mutator_.added_stream_.get(), stream.get());
  }

  StrictMock<MockAddNamedStreamMutator> mutator_;
  PdbFile pdb_file_;
};

}  // namespace

TEST_F(AddNamedStreamMutatorTest, FailsWithNoHeaderInfoStream) {
  EXPECT_FALSE(mutator_.MutatePdb(&pdb_file_));
}

TEST_F(AddNamedStreamMutatorTest, FailsIfAddNamedStreamsFails) {
  ASSERT_NO_FATAL_FAILURE(testing::InitMockPdbFile(&pdb_file_));
  EXPECT_CALL(mutator_, AddNamedStreams(Ref(pdb_file_))).Times(1).
      WillOnce(Return(false));
  EXPECT_FALSE(mutator_.MutatePdb(&pdb_file_));
}

TEST_F(AddNamedStreamMutatorTest, SucceedsWithNoInsertion) {
  ASSERT_NO_FATAL_FAILURE(testing::InitMockPdbFile(&pdb_file_));
  EXPECT_CALL(mutator_, AddNamedStreams(Ref(pdb_file_))).Times(1).
      WillOnce(Return(true));
  EXPECT_TRUE(mutator_.MutatePdb(&pdb_file_));
}

TEST_F(AddNamedStreamMutatorTest, SucceedsWithInsertionAndReplacement) {
  ASSERT_NO_FATAL_FAILURE(testing::InitMockPdbFile(&pdb_file_));

  EXPECT_CALL(mutator_, AddNamedStreams(Ref(pdb_file_))).Times(1).
      WillOnce(Invoke(&mutator_, &MockAddNamedStreamMutator::AddFooStream));
  EXPECT_TRUE(mutator_.MutatePdb(&pdb_file_));

  ASSERT_NO_FATAL_FAILURE(CheckFooStreamAdded());

  EXPECT_CALL(mutator_, AddNamedStreams(Ref(pdb_file_))).Times(1).
    WillOnce(Invoke(&mutator_,
                    &MockAddNamedStreamMutator::GetAndReplaceFooStream));
  EXPECT_TRUE(mutator_.MutatePdb(&pdb_file_));

  ASSERT_NO_FATAL_FAILURE(CheckFooStreamAdded());
}

}  // namespace mutators
}  // namespace pdb
