// Copyright 2013 Google Inc. All Rights Reserved.
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

#include "syzygy/pdb/pdb_mutator.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace pdb {

namespace {

using testing::Return;

class LenientMockPdbMutator : public PdbMutatorInterface {
 public:
  virtual ~LenientMockPdbMutator() { }
  virtual const char* name() const { return "MockPdbMutator"; }

  MOCK_METHOD1(MutatePdb, bool(PdbFile*));
};
typedef testing::StrictMock<LenientMockPdbMutator>
    MockPdbMutator;

class PdbMutatorTest : public testing::Test {
 public:
  PdbFile pdb_file_;
};

}  // namespace

TEST_F(PdbMutatorTest, ApplyMutatorsSucceeds) {
  MockPdbMutator m1, m2, m3;
  std::vector<PdbMutatorInterface*> mutators;
  mutators.push_back(&m1);
  mutators.push_back(&m2);
  mutators.push_back(&m3);

  EXPECT_CALL(m1, MutatePdb(&pdb_file_)).WillOnce(Return(true));
  EXPECT_CALL(m2, MutatePdb(&pdb_file_)).WillOnce(Return(true));
  EXPECT_CALL(m3, MutatePdb(&pdb_file_)).WillOnce(Return(true));

  EXPECT_TRUE(ApplyPdbMutators(mutators, &pdb_file_));
}

TEST_F(PdbMutatorTest, ApplyMutatorsFails) {
  MockPdbMutator m1, m2, m3;
  std::vector<PdbMutatorInterface*> mutators;
  mutators.push_back(&m1);
  mutators.push_back(&m2);
  mutators.push_back(&m3);

  EXPECT_CALL(m1, MutatePdb(&pdb_file_)).WillOnce(Return(true));
  EXPECT_CALL(m2, MutatePdb(&pdb_file_)).WillOnce(Return(false));

  EXPECT_FALSE(ApplyPdbMutators(mutators, &pdb_file_));
}

}  // namespace pdb
