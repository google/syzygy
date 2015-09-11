// Copyright 2015 Google Inc. All Rights Reserved.
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

#include "syzygy/pe/cvinfo_ext.h"

#include "gtest/gtest.h"

namespace pe {

TEST(CVInfoExtTest, LocalVarFlagsTest) {
  const uint16_t kNoFlags = 0x0000;
  LocalVarFlags flags = {kNoFlags};

  EXPECT_EQ(flags.raw, kNoFlags);

  flags.fIsParam = 1;
  EXPECT_EQ(Microsoft_Cci_Pdb::fIsParam, flags.raw);
  flags.raw = kNoFlags;

  flags.fAddrTaken = 1;
  EXPECT_EQ(Microsoft_Cci_Pdb::fAddrTaken, flags.raw);
  flags.raw = kNoFlags;

  flags.fCompGenx = 1;
  EXPECT_EQ(Microsoft_Cci_Pdb::fCompGenx, flags.raw);
  flags.raw = kNoFlags;

  flags.fIsAggregate = 1;
  EXPECT_EQ(Microsoft_Cci_Pdb::fIsAggregate, flags.raw);
  flags.raw = kNoFlags;

  flags.fIsAggregated = 1;
  EXPECT_EQ(Microsoft_Cci_Pdb::fIsAggregated, flags.raw);
  flags.raw = kNoFlags;

  flags.fIsAliased = 1;
  EXPECT_EQ(Microsoft_Cci_Pdb::fIsAliased, flags.raw);
  flags.raw = kNoFlags;

  flags.fIsAlias = 1;
  EXPECT_EQ(Microsoft_Cci_Pdb::fIsAlias, flags.raw);
  flags.raw = kNoFlags;
}

// TODO(siggi): Test the remaining unions from cvinfo_ext.h as well.

}  // namespace pe
