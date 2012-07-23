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

#include "syzygy/core/unittest_util.h"

#include "base/file_path.h"
#include "base/file_util.h"
#include "gtest/gtest.h"

namespace testing {

TEST(CoreUnittestUtils, GetRelativePath) {
  const FilePath kEmptyPath;
  const FilePath kCurrentDir(L".");
  const FilePath kPath1(L"C:\\foo\\bar");
  const FilePath kPath2(L"c:\\foo\\bar\\sub");
  const FilePath kPath3(L"c:\\foo\\other\\file");
  const FilePath kPath4(L"D:\\foo\\bar");
  const FilePath kRelPath1From2(L"..");
  const FilePath kRelPath2From1(L"sub");
  const FilePath kRelPath1From3(L"..\\..\\bar");
  const FilePath kRelPath3From1(L"..\\other\\file");

  EXPECT_EQ(kEmptyPath, GetRelativePath(kPath1, kPath4));
  EXPECT_EQ(kCurrentDir, GetRelativePath(kPath1, kPath1));
  EXPECT_EQ(kRelPath1From2,GetRelativePath(kPath1, kPath2));
  EXPECT_EQ(kRelPath2From1,GetRelativePath(kPath2, kPath1));
  EXPECT_EQ(kRelPath1From3,GetRelativePath(kPath1, kPath3));
  EXPECT_EQ(kRelPath3From1,GetRelativePath(kPath3, kPath1));

  FilePath sub_dir;
  ASSERT_TRUE(file_util::GetCurrentDirectory(&sub_dir));
  EXPECT_EQ(FilePath(L"blah"), GetRelativePath(sub_dir.Append(L"blah")));
}

}  // namespace testing
