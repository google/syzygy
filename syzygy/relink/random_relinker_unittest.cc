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

#include "syzygy/relink/random_relinker.h"
#include "base/file_util.h"
#include "gtest/gtest.h"
#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/pe_file.h"
#include "syzygy/pe/unittest_util.h"

namespace {

class RandomRelinkerTest : public testing::Test {
 public:
  void SetUp() {
    ASSERT_TRUE(file_util::CreateNewTempDirectory(L"", &temp_dir_));
  }

  void TearDown() {
    file_util::Delete(temp_dir_, true);
  }

 protected:
  FilePath temp_dir_;
};

}  // namespace


TEST_F(RandomRelinkerTest, Relink) {
  FilePath output_dll_path = temp_dir_.Append(testing::kDllName);
  ASSERT_TRUE(RandomRelinker::Relink(
      testing::GetExeRelativePath(testing::kDllName),
      testing::GetExeRelativePath(testing::kDllPdbName),
      output_dll_path,
      temp_dir_.Append(testing::kDllPdbName),
      0));
  ASSERT_NO_FATAL_FAILURE(testing::CheckTestDll(output_dll_path));
}
