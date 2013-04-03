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
#include "syzygy/pe/pdb_info.h"

#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pdb/pdb_util.h"
#include "syzygy/pe/unittest_util.h"

namespace pe {

namespace {

class PdbInfoTest: public testing::PELibUnitTest {
  // Insert your customizations here.
};

// Creates a buffer that can be interpreted as a CvInfoPdb70 struct.
CvInfoPdb70* CreateCvInfoPdb70(const char* path,
                               std::vector<unsigned char>* data) {
  size_t cv_len = sizeof(CvInfoPdb70);
  size_t path_len = ::strlen(path);
  size_t data_len = cv_len + path_len;

  data->clear();
  data->resize(data_len, 0);

  CvInfoPdb70* cv_info_pdb = reinterpret_cast<CvInfoPdb70*>(&data->at(0));
  ::strcpy(cv_info_pdb->pdb_file_name, path);

  return cv_info_pdb;
}

}  // namespace

TEST_F(PdbInfoTest, TestDllAndPdbAreConsistent) {
  const base::FilePath test_dll(
      testing::GetExeRelativePath(testing::kTestDllName));
  const base::FilePath test_dll_pdb(testing::GetExeRelativePath(
      testing::kTestDllPdbName));

  PdbInfo pdb_info;
  EXPECT_TRUE(pdb_info.Init(test_dll));

  pdb::PdbInfoHeader70 pdb_header;
  ASSERT_TRUE(pdb::ReadPdbHeader(test_dll_pdb, &pdb_header));

  EXPECT_TRUE(pdb_info.IsConsistent(pdb_header));
}

TEST_F(PdbInfoTest, BuildFromCvInfoPdb70) {
  const char kPath[] = "C:\\foo\\foo.pdb";
  const GUID kSignature = { 0xdeadbeef, 0xf00d, 0xcafe,
      { 'c', 'u', 't', 'e', 'c', 'a', 't', 's' } };

  std::vector<unsigned char> data;
  CvInfoPdb70* cv_info_pdb = CreateCvInfoPdb70(kPath, &data);
  cv_info_pdb->cv_signature = 0xdeadbeef;
  cv_info_pdb->pdb_age = 2;
  cv_info_pdb->signature = kSignature;

  PdbInfo pdb_info;
  EXPECT_TRUE(pdb_info.Init(*cv_info_pdb));

  pdb::PdbInfoHeader70 pdb_header = {};
  pdb_header.pdb_age = cv_info_pdb->pdb_age;
  pdb_header.signature = cv_info_pdb->signature;

  EXPECT_TRUE(pdb_info.IsConsistent(pdb_header));

  // An older PBD is not consistent with a newer image.
  pdb_header.pdb_age = cv_info_pdb->pdb_age - 1;
  EXPECT_FALSE(pdb_info.IsConsistent(pdb_header));

  // If the PDB age is newer than the image, we are consistent.
  pdb_header.pdb_age = cv_info_pdb->pdb_age + 1;
  EXPECT_TRUE(pdb_info.IsConsistent(pdb_header));
}

}  // namespace pe
