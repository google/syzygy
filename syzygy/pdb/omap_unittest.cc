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

#include "syzygy/pdb/omap.h"

#include "base/path_service.h"
#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pdb/unittest_util.h"

namespace pdb {

using core::RelativeAddress;

TEST(OmapTest, CreateOmap) {
  OMAP omap = CreateOmap(523, 644);
  EXPECT_EQ(523u, omap.rva);
  EXPECT_EQ(644u, omap.rvaTo);
}

TEST(OmapTest, OmapLess) {
  OMAP omap1 = CreateOmap(0, 0);
  OMAP omap2 = CreateOmap(1, 1);
  OMAP omap3 = CreateOmap(1, 2);

  EXPECT_TRUE(OmapLess(omap1, omap2));
  EXPECT_FALSE(OmapLess(omap2, omap1));
  EXPECT_FALSE(OmapLess(omap1, omap1));
  EXPECT_FALSE(OmapLess(omap2, omap2));
  EXPECT_FALSE(OmapLess(omap2, omap3));
  EXPECT_FALSE(OmapLess(omap3, omap2));
}

TEST(OmapTest, OmapVectorIsValid) {
  std::vector<OMAP> omaps;
  EXPECT_TRUE(OmapVectorIsValid(omaps));

  omaps.push_back(CreateOmap(0, 0));
  EXPECT_TRUE(OmapVectorIsValid(omaps));

  omaps.push_back(CreateOmap(1, 0));
  EXPECT_TRUE(OmapVectorIsValid(omaps));

  omaps.push_back(CreateOmap(1, 1));
  EXPECT_FALSE(OmapVectorIsValid(omaps));

  omaps.back().rva = 0;
  EXPECT_FALSE(OmapVectorIsValid(omaps));
}

TEST(OmapTest, Translate) {
  std::vector<OMAP> omaps;

  // We create mapping that sends [1000, 2000) to [2000, 3000) and
  // [2000, 3000) to [1000, 2000). Addresses < 1000 and >= 3000 remain fixed.
  omaps.push_back(CreateOmap(1000, 2000));
  omaps.push_back(CreateOmap(2000, 1000));
  omaps.push_back(CreateOmap(3000, 3000));

  ASSERT_TRUE(OmapVectorIsValid(omaps));

  // Try a mapping in each of the 4 distinct regions that the OMAP vector
  // imposes on the address space.
  EXPECT_EQ(RelativeAddress(500),
            TranslateAddressViaOmap(omaps, RelativeAddress(500)));
  EXPECT_EQ(RelativeAddress(2500),
            TranslateAddressViaOmap(omaps, RelativeAddress(1500)));
  EXPECT_EQ(RelativeAddress(1500),
            TranslateAddressViaOmap(omaps, RelativeAddress(2500)));
  EXPECT_EQ(RelativeAddress(3500),
            TranslateAddressViaOmap(omaps, RelativeAddress(3500)));
}

TEST(OmapTest, ReadOmapsFromPdbFile) {
  std::vector<OMAP> omap_to, omap_from;

  // We only test ReadOmapsFromPdbFile as this wraps ReadOmapsFromPdbReader and
  // inherently tests both.

  // We expect this to be false, as the original test_dll has no OMAP
  // information in it.
  base::FilePath pdb_path = testing::GetSrcRelativePath(
      testing::kTestDllFilePath);
  EXPECT_FALSE(ReadOmapsFromPdbFile(pdb_path, NULL, NULL));

  pdb_path = testing::GetSrcRelativePath(
      testing::kOmappedTestPdbFilePath);
  EXPECT_TRUE(ReadOmapsFromPdbFile(pdb_path, NULL, NULL));
  EXPECT_TRUE(ReadOmapsFromPdbFile(pdb_path, NULL, &omap_from));
  EXPECT_FALSE(omap_from.empty());
  EXPECT_TRUE(ReadOmapsFromPdbFile(pdb_path, &omap_to, NULL));
  EXPECT_FALSE(omap_to.empty());
  EXPECT_TRUE(ReadOmapsFromPdbFile(pdb_path, &omap_to, &omap_from));
  EXPECT_FALSE(omap_to.empty());
  EXPECT_FALSE(omap_from.empty());

  // Some additional testing to ensure reusing a PdbFile works.
  PdbReader pdb_reader;
  PdbFile pdb_file;
  ASSERT_TRUE(pdb_reader.Read(pdb_path, &pdb_file));
  ASSERT_TRUE(ReadOmapsFromPdbFile(pdb_file, &omap_to, &omap_from));
  ASSERT_TRUE(ReadOmapsFromPdbFile(pdb_file, &omap_to, &omap_from));
}

}  // namespace pdb
