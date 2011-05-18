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

class RandomRelinkerTest : public testing::PELibUnitTest {
  // Put any specializations here
};

TEST_F(RandomRelinkerTest, Relink) {
  FilePath temp_dir;
  ASSERT_NO_FATAL_FAILURE(CreateTemporaryDir(&temp_dir));
  FilePath output_dll_path = temp_dir.Append(kDllName);

  RandomRelinker relinker;
  relinker.set_seed(12345);
  ASSERT_TRUE(relinker.Relink(GetExeRelativePath(kDllName),
                              GetExeRelativePath(kDllPdbName),
                              output_dll_path,
                              temp_dir.Append(kDllPdbName)));
  ASSERT_NO_FATAL_FAILURE(CheckTestDll(output_dll_path));
}

TEST_F(RandomRelinkerTest, RelinkWithPadding) {
  FilePath temp_dir;
  ASSERT_NO_FATAL_FAILURE(CreateTemporaryDir(&temp_dir));
  FilePath output_dll_path = temp_dir.Append(kDllName);

  RandomRelinker relinker;
  relinker.set_seed(56789);
  relinker.set_padding_length(32);
  ASSERT_TRUE(relinker.Relink(GetExeRelativePath(kDllName),
                              GetExeRelativePath(kDllPdbName),
                              output_dll_path,
                              temp_dir.Append(kDllPdbName)));
  ASSERT_NO_FATAL_FAILURE(CheckTestDll(output_dll_path));
}
