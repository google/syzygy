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

#include "syzygy/grinder/grinder_util.h"

#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/unittest_util.h"

namespace grinder {

TEST(GrinderUtilTest, GetBasicBlockAddresses) {
  base::FilePath pdb_path = testing::GetExeTestDataRelativePath(
      testing::kCoverageInstrumentedTestDllPdbName);

  RelativeAddressVector bb_addresses;
  EXPECT_TRUE(GetBasicBlockAddresses(pdb_path, &bb_addresses));
  EXPECT_LT(0u, bb_addresses.size());
}

}  // namespace grinder
