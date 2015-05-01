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

#include "syzygy/zap_timestamp/zap_timestamp.h"

#include "base/files/file_util.h"
#include "base/files/scoped_temp_dir.h"
#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/unittest_util.h"

namespace zap_timestamp {

namespace {

// We don't bother with having specific data for the 'Coverage' case.
#define TEST_DATA_PREFIX_0 L"syzygy\\zap_timestamp\\test_data\\"
#ifdef NDEBUG
#define TEST_DATA_PREFIX_1 L"Release\\"
#else
#define TEST_DATA_PREFIX_1 L"Debug\\"
#endif
#define TEST_DATA_PREFIX TEST_DATA_PREFIX_0 TEST_DATA_PREFIX_1

struct RawPePdbPathPair {
  const wchar_t* pe_path;
  const wchar_t* pdb_path;
};
RawPePdbPathPair kRawTestPaths[] = {
    { TEST_DATA_PREFIX L"copy0\\test_dll.dll",
      TEST_DATA_PREFIX L"copy0\\test_dll.pdb" },
    { TEST_DATA_PREFIX L"copy1\\test_dll.dll",
      TEST_DATA_PREFIX L"copy1\\test_dll.pdb" },
    { TEST_DATA_PREFIX L"copy2\\test_dll.dll",
      TEST_DATA_PREFIX L"copy2\\test_dll.pdb" } };

struct PePdbPathPair {
  base::FilePath pe_path;
  base::FilePath pdb_path;
};

class ZapTimestampTest : public testing::Test {
 public:
  virtual void SetUp() override {
    testing::Test::SetUp();

    temp_dir_.CreateUniqueTempDir();

    // Get the full test data paths.
    for (size_t i = 0; i < arraysize(kRawTestPaths); ++i) {
      PePdbPathPair pair;
      pair.pe_path = testing::GetSrcRelativePath(kRawTestPaths[i].pe_path);
      pair.pdb_path = testing::GetSrcRelativePath(kRawTestPaths[i].pdb_path);
      test_paths_.push_back(pair);
    }

    temp_pe_path_ = temp_dir_.path().Append(L"test_dll.dll");
    temp_pdb_path_ = temp_dir_.path().Append(L"test_dll.pdb");
  }

  void CopyTestData(const base::FilePath& pe_path,
                    const base::FilePath& pdb_path) {
    ASSERT_TRUE(base::CopyFile(pe_path, temp_pe_path_));
    ASSERT_TRUE(base::CopyFile(pdb_path, temp_pdb_path_));
  }

  void CopyTestData(size_t index) {
    ASSERT_GT(test_paths_.size(), index);
    ASSERT_NO_FATAL_FAILURE(CopyTestData(
        test_paths_[index].pe_path, test_paths_[index].pdb_path));
  }

  void CopyNoPdbTestData() {
    base::FilePath pe_path = testing::GetSrcRelativePath(
        L"syzygy\\zap_timestamp\\test_data\\test_dll_no_pdb.dll");
    temp_pe_path_ = temp_dir_.path().Append(L"test_dll_no_pdb.dll");
    temp_pdb_path_.clear();
    ASSERT_TRUE(base::CopyFileW(pe_path, temp_pe_path_));
  }

  base::ScopedTempDir temp_dir_;
  std::vector<PePdbPathPair> test_paths_;

  base::FilePath temp_pe_path_;
  base::FilePath temp_pdb_path_;
};

}  // namespace

TEST_F(ZapTimestampTest, InitFailsForNonExistentPath) {
  ZapTimestamp zap;
  zap.set_input_image(base::FilePath(L"nonexistent_pe_file.dll"));
  zap.set_overwrite(true);
  EXPECT_FALSE(zap.Init());
}

TEST_F(ZapTimestampTest, InitFailsForMismatchedPeAndPdb) {
  ASSERT_NO_FATAL_FAILURE(CopyTestData(
      test_paths_[0].pe_path, test_paths_[1].pdb_path));
  ZapTimestamp zap;
  zap.set_input_image(temp_pe_path_);
  zap.set_overwrite(true);
  EXPECT_FALSE(zap.Init());
}

TEST_F(ZapTimestampTest, InitFailsWithMissingPdb) {
  ASSERT_NO_FATAL_FAILURE(CopyTestData(0));
  ASSERT_TRUE(base::DeleteFile(temp_pdb_path_, false));
  ZapTimestamp zap;
  zap.set_input_image(temp_pe_path_);
  zap.set_overwrite(true);
  EXPECT_FALSE(zap.Init());
}

TEST_F(ZapTimestampTest, InitAutoFindPdb) {
  ASSERT_NO_FATAL_FAILURE(CopyTestData(0));
  ZapTimestamp zap;
  zap.set_input_image(temp_pe_path_);
  zap.set_overwrite(true);
  EXPECT_TRUE(zap.Init());
  EXPECT_EQ(temp_pdb_path_, zap.input_pdb());
}

TEST_F(ZapTimestampTest, InitExplicitPdb) {
  ASSERT_NO_FATAL_FAILURE(CopyTestData(0));
  ZapTimestamp zap;
  zap.set_input_image(temp_pe_path_);
  zap.set_input_pdb(temp_pdb_path_);
  zap.set_overwrite(true);
  EXPECT_TRUE(zap.Init());
}

TEST_F(ZapTimestampTest, IsIdempotent) {
  // Zap the first set of the PE and PDB files.
  ASSERT_NO_FATAL_FAILURE(CopyTestData(0));
  ZapTimestamp zap0;
  zap0.set_input_image(temp_pe_path_);
  zap0.set_overwrite(true);
  EXPECT_TRUE(zap0.Init());
  EXPECT_EQ(temp_pdb_path_, zap0.output_pdb());
  EXPECT_TRUE(zap0.Zap());

  // Make a copy of the singly zapped files.
  base::FilePath pe_path_0 = temp_dir_.path().Append(L"test_dll_0.dll");
  base::FilePath pdb_path_0 = temp_dir_.path().Append(L"test_dll_0.pdb");
  ASSERT_TRUE(base::CopyFile(temp_pe_path_, pe_path_0));
  ASSERT_TRUE(base::CopyFile(temp_pdb_path_, pdb_path_0));

  // Zap them again.
  ZapTimestamp zap1;
  zap1.set_input_image(temp_pe_path_);
  zap1.set_overwrite(true);
  EXPECT_TRUE(zap1.Init());
  EXPECT_EQ(temp_pdb_path_, zap1.output_pdb());
  EXPECT_TRUE(zap1.Zap());

  // The singly and doubly zapped files should be the same.
  EXPECT_TRUE(base::ContentsEqual(temp_pe_path_, pe_path_0));
  EXPECT_TRUE(base::ContentsEqual(temp_pdb_path_, pdb_path_0));
}

TEST_F(ZapTimestampTest, SucceedsInferPdb) {
  ASSERT_NO_FATAL_FAILURE(CopyTestData(0));
  base::FilePath pe_path = temp_dir_.path().Append(L"test_dll.new.dll");
  base::FilePath pdb_path = temp_dir_.path().Append(L"test_dll.new.dll.pdb");

  // Zap the image. Let the PDB output be inferred.
  ZapTimestamp zap0;
  zap0.set_input_image(temp_pe_path_);
  zap0.set_output_image(pe_path);
  EXPECT_TRUE(zap0.Init());
  EXPECT_TRUE(zap0.Zap());
  EXPECT_TRUE(base::PathExists(pe_path));
  EXPECT_TRUE(base::PathExists(pdb_path));
}

TEST_F(ZapTimestampTest, SucceedsExplicitPdb) {
  ASSERT_NO_FATAL_FAILURE(CopyTestData(0));
  base::FilePath pe_path = temp_dir_.path().Append(L"test_dll.new.dll");
  base::FilePath pdb_path = temp_dir_.path().Append(L"test_dll.new.dll.pdb");

  // Zap the image. Provide an explicit output PDB.
  ZapTimestamp zap0;
  zap0.set_input_image(temp_pe_path_);
  zap0.set_output_image(pe_path);
  zap0.set_output_pdb(pdb_path);
  EXPECT_TRUE(zap0.Init());
  EXPECT_TRUE(zap0.Zap());
  EXPECT_TRUE(base::PathExists(pe_path));
  EXPECT_TRUE(base::PathExists(pdb_path));
}

TEST_F(ZapTimestampTest, SucceedsDontWritePdb) {
  ASSERT_NO_FATAL_FAILURE(CopyTestData(0));
  base::FilePath pe_path = temp_dir_.path().Append(L"test_dll.new.dll");
  base::FilePath pdb_path = temp_dir_.path().Append(L"test_dll.new.dll.pdb");

  // Zap the image. Let the PDB output be inferred.
  ZapTimestamp zap0;
  zap0.set_input_image(temp_pe_path_);
  zap0.set_output_image(pe_path);
  zap0.set_write_pdb(false);
  EXPECT_TRUE(zap0.Init());
  EXPECT_TRUE(zap0.Zap());
  EXPECT_TRUE(base::PathExists(pe_path));
  EXPECT_FALSE(base::PathExists(pdb_path));
}

TEST_F(ZapTimestampTest, SucceedsDontWriteImage) {
  ASSERT_NO_FATAL_FAILURE(CopyTestData(0));
  base::FilePath pe_path = temp_dir_.path().Append(L"test_dll.new.dll");
  base::FilePath pdb_path = temp_dir_.path().Append(L"test_dll.new.dll.pdb");

  // Zap the image. Let the PDB output be inferred.
  ZapTimestamp zap0;
  zap0.set_input_image(temp_pe_path_);
  zap0.set_output_image(pe_path);
  zap0.set_write_image(false);
  EXPECT_TRUE(zap0.Init());
  EXPECT_TRUE(zap0.Zap());
  EXPECT_FALSE(base::PathExists(pe_path));
  EXPECT_TRUE(base::PathExists(pdb_path));
}

TEST_F(ZapTimestampTest, FailsBecauseWouldOverwritePe) {
  ASSERT_NO_FATAL_FAILURE(CopyTestData(0));
  base::FilePath pe_path = temp_dir_.path().Append(L"test_dll.new.dll");
  base::FilePath pdb_path = temp_dir_.path().Append(L"test_dll.new.dll.pdb");

  base::WriteFile(pe_path, "h", 1);

  // Zap the image. Let the PDB output be inferred.
  ZapTimestamp zap0;
  zap0.set_input_image(temp_pe_path_);
  zap0.set_output_image(pe_path);
  EXPECT_FALSE(zap0.Init());
}

TEST_F(ZapTimestampTest, FailsBecauseWouldOverwritePdb) {
  ASSERT_NO_FATAL_FAILURE(CopyTestData(0));
  base::FilePath pe_path = temp_dir_.path().Append(L"test_dll.new.dll");
  base::FilePath pdb_path = temp_dir_.path().Append(L"test_dll.new.dll.pdb");

  base::WriteFile(pdb_path, "h", 1);

  // Zap the image. Let the PDB output be inferred.
  ZapTimestamp zap0;
  zap0.set_input_image(temp_pe_path_);
  zap0.set_output_image(pe_path);
  EXPECT_FALSE(zap0.Init());
}

TEST_F(ZapTimestampTest, Succeeds) {
  // Zap the first set of the PE and PDB files.
  ASSERT_NO_FATAL_FAILURE(CopyTestData(0));
  ZapTimestamp zap0;
  zap0.set_input_image(temp_pe_path_);
  zap0.set_overwrite(true);
  EXPECT_TRUE(zap0.Init());
  EXPECT_EQ(temp_pdb_path_, zap0.input_pdb());
  EXPECT_TRUE(zap0.Zap());

  // Rename and move the PE and PDB file.
  base::FilePath pe_path_0 = temp_dir_.path().Append(L"test_dll_0.dll");
  base::FilePath pdb_path_0 = temp_dir_.path().Append(L"test_dll_0.pdb");
  ASSERT_TRUE(base::Move(temp_pe_path_, pe_path_0));
  ASSERT_TRUE(base::Move(temp_pdb_path_, pdb_path_0));

  // Zap the second set of the PE and PDB files.
  ASSERT_NO_FATAL_FAILURE(CopyTestData(1));
  ZapTimestamp zap1;
  zap1.set_input_image(temp_pe_path_);
  zap1.set_input_pdb(temp_pdb_path_);
  zap1.set_overwrite(true);
  EXPECT_TRUE(zap1.Init());
  EXPECT_TRUE(zap1.Zap());

  // Rename and move the PE and PDB file.
  base::FilePath pe_path_1 = temp_dir_.path().Append(L"test_dll_1.dll");
  base::FilePath pdb_path_1 = temp_dir_.path().Append(L"test_dll_1.pdb");
  ASSERT_TRUE(base::Move(temp_pe_path_, pe_path_1));
  ASSERT_TRUE(base::Move(temp_pdb_path_, pdb_path_1));

  // Zap the third set of the PE and PDB files.
  ASSERT_NO_FATAL_FAILURE(CopyTestData(2));
  ZapTimestamp zap2;
  zap2.set_input_image(temp_pe_path_);
  zap2.set_input_pdb(temp_pdb_path_);
  zap2.set_overwrite(true);
  EXPECT_TRUE(zap2.Init());
  EXPECT_TRUE(zap2.Zap());

  // The sets of zapped files should match.
  EXPECT_TRUE(base::ContentsEqual(temp_pe_path_, pe_path_0));
  EXPECT_TRUE(base::ContentsEqual(temp_pe_path_, pe_path_1));
  EXPECT_TRUE(base::ContentsEqual(temp_pdb_path_, pdb_path_0));
  EXPECT_TRUE(base::ContentsEqual(temp_pdb_path_, pdb_path_1));
}

TEST_F(ZapTimestampTest, IsIdempotentNoPdb) {
  // Zap the iage.
  ASSERT_NO_FATAL_FAILURE(CopyNoPdbTestData());
  ZapTimestamp zap0;
  zap0.set_input_image(temp_pe_path_);
  zap0.set_overwrite(true);
  zap0.set_write_pdb(false);
  EXPECT_TRUE(zap0.Init());
  EXPECT_TRUE(zap0.Zap());

  // Make a copy of the singly zapped image.
  base::FilePath pe_path_0 = temp_dir_.path().Append(L"test_dll_no_pdb_0.dll");
  ASSERT_TRUE(base::CopyFile(temp_pe_path_, pe_path_0));

  // Zap it again.
  ZapTimestamp zap1;
  zap1.set_input_image(temp_pe_path_);
  zap1.set_overwrite(true);
  zap1.set_write_pdb(false);
  EXPECT_TRUE(zap1.Init());
  EXPECT_TRUE(zap1.Zap());

  // The singly and doubly zapped files should be the same.
  EXPECT_TRUE(base::ContentsEqual(temp_pe_path_, pe_path_0));
}

}  // namespace zap_timestamp
