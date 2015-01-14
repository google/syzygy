// Copyright 2011 Google Inc. All Rights Reserved.
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

#include "syzygy/version/syzygy_version.h"

#include "gtest/gtest.h"
#include "syzygy/core/serialization.h"
#include "syzygy/core/unittest_util.h"

namespace version {

TEST(SyzygyVersionTest, Equality) {
  SyzygyVersion version1(SYZYGY_MAJOR, SYZYGY_MINOR, SYZYGY_BUILD,
                         SYZYGY_PATCH, SYZYGY_LASTCHANGE_FULL);
  SyzygyVersion version2;

  EXPECT_TRUE(version1 == kSyzygyVersion);
  EXPECT_FALSE(version2 == kSyzygyVersion);
}

TEST(SyzygyVersionTest, Compatibility) {
  // For now, this is the same unit test as Equality. However, we may eventually
  // change our notion of compatibility.
  SyzygyVersion version1(SYZYGY_MAJOR, SYZYGY_MINOR, SYZYGY_BUILD,
                         SYZYGY_PATCH, SYZYGY_LASTCHANGE_FULL);
  SyzygyVersion version2;

  EXPECT_TRUE(version1.IsCompatible(kSyzygyVersion));
  EXPECT_FALSE(version2.IsCompatible(kSyzygyVersion));
}

TEST(SyzygyVersionTest, CompareOctets) {
  SyzygyVersion v0001(0, 0, 0, 1, "a");
  SyzygyVersion v0010(0, 0, 1, 0, "b");
  SyzygyVersion v0100(0, 1, 0, 0, "c");
  SyzygyVersion v1000(1, 0, 0, 0, "d");

  EXPECT_EQ(0, v0001.CompareOctet(v0001));
  EXPECT_GT(0, v0001.CompareOctet(v0010));
  EXPECT_GT(0, v0001.CompareOctet(v0100));
  EXPECT_GT(0, v0001.CompareOctet(v1000));

  EXPECT_LT(0, v0010.CompareOctet(v0001));
  EXPECT_EQ(0, v0010.CompareOctet(v0010));
  EXPECT_GT(0, v0010.CompareOctet(v0100));
  EXPECT_GT(0, v0010.CompareOctet(v1000));

  EXPECT_LT(0, v0100.CompareOctet(v0001));
  EXPECT_LT(0, v0100.CompareOctet(v0010));
  EXPECT_EQ(0, v0100.CompareOctet(v0100));
  EXPECT_GT(0, v0100.CompareOctet(v1000));

  EXPECT_LT(0, v1000.CompareOctet(v0001));
  EXPECT_LT(0, v1000.CompareOctet(v0010));
  EXPECT_LT(0, v1000.CompareOctet(v0100));
  EXPECT_EQ(0, v1000.CompareOctet(v1000));

  // Two versions with the same octet but a different last-change string
  // should compare equal.
  SyzygyVersion v1000_2(1, 0, 0, 0, "e");
  EXPECT_EQ(0, v1000.CompareOctet(v1000_2));
}

TEST(SyzygyVersionTest, Serialization) {
  EXPECT_TRUE(testing::TestSerialization(kSyzygyVersion));
}

TEST(SyzygyVersionTest, Mutators) {
  SyzygyVersion version;
  EXPECT_EQ(0, version.major());
  EXPECT_EQ(0, version.minor());
  EXPECT_EQ(0, version.build());
  EXPECT_EQ(0, version.patch());
  EXPECT_TRUE(version.last_change() == "");

  version.set_major(1);
  version.set_minor(2);
  version.set_build(3);
  version.set_patch(4);
  version.set_last_change("5");

  EXPECT_EQ(1, version.major());
  EXPECT_EQ(2, version.minor());
  EXPECT_EQ(3, version.build());
  EXPECT_EQ(4, version.patch());
  EXPECT_TRUE(version.last_change() == "5");
}

TEST(SyzygyVersionTest, VersionString) {
  EXPECT_TRUE(kSyzygyVersion.GetVersionString() == SYZYGY_VERSION_STRING);

  // An empty last-change string should not be appended.
  SyzygyVersion version(0, 0, 0, 0, "");
  EXPECT_TRUE(version.GetVersionString() == "0.0.0.0");
}

}  // namespace version
