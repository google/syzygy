// Copyright 2011 Google Inc.
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

#include "syzygy/common/syzygy_version.h"
#include "syzygy/core/serialization.h"
#include "syzygy/core/unittest_util.h"
#include "gtest/gtest.h"

namespace common {

TEST(SyzygyVersionTest, Equality) {
  SyzygyVersion version1(SYZYGY_MAJOR, SYZYGY_MINOR, SYZYGY_PATCH,
                         SYZYGY_BUILD, SYZYGY_LASTCHANGE);
  SyzygyVersion version2;

  EXPECT_TRUE(version1 == kSyzygyVersion);
  EXPECT_FALSE(version2 == kSyzygyVersion);
}

TEST(SyzygyVersionTest, Compatibility) {
  // For now, this is the same unit test as Equality. However, we may eventually
  // change our notion of compatibility.
  SyzygyVersion version1(SYZYGY_MAJOR, SYZYGY_MINOR, SYZYGY_PATCH,
                         SYZYGY_BUILD, SYZYGY_LASTCHANGE);
  SyzygyVersion version2;

  EXPECT_TRUE(version1.IsCompatible(kSyzygyVersion));
  EXPECT_FALSE(version2.IsCompatible(kSyzygyVersion));
}

TEST(SyzygyVersionTest, Serialization) {
  EXPECT_TRUE(testing::TestSerialization(kSyzygyVersion));
}

}  // namespace common
