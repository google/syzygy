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
//
#include "sawbuck/image_util/decomposer.h"

#include "base/path_service.h"
#include "base/string_util.h"
#include "gtest/gtest.h"
#include "sawbuck/image_util/block_graph.h"
#include "sawbuck/image_util/pe_file.h"

namespace {

FilePath GetExeRelativePath(const wchar_t* image_name) {
  FilePath exe_dir;
  PathService::Get(base::DIR_EXE, &exe_dir);

  return exe_dir.Append(image_name);
}

const wchar_t kDllName[] = L"test_dll.dll";

}  // namespace

namespace image_util {

TEST(DecomposerTest, Decompose) {
  FilePath image_path(GetExeRelativePath(kDllName));
  PEFile image_file;

  ASSERT_TRUE(image_file.Init(image_path));

  // Decompose the test image and look at the result.
  Decomposer decomposer(image_file, image_path);

  Decomposer::DecomposedImage decomposed;
  ASSERT_TRUE(decomposer.Decompose(&decomposed));

  EXPECT_TRUE(decomposed.header.dos_header != NULL);
  EXPECT_TRUE(decomposed.header.nt_headers != NULL);
  EXPECT_TRUE(decomposed.header.image_section_headers != NULL);

  EXPECT_TRUE(
      decomposed.header.data_directory[IMAGE_DIRECTORY_ENTRY_EXPORT]
          != NULL);
  EXPECT_TRUE(
      decomposed.header.data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT]
          != NULL);
  EXPECT_TRUE(
      decomposed.header.data_directory[IMAGE_DIRECTORY_ENTRY_RESOURCE]
          != NULL);
  EXPECT_TRUE(
      decomposed.header.data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
          != NULL);
  EXPECT_TRUE(
      decomposed.header.data_directory[IMAGE_DIRECTORY_ENTRY_DEBUG]
          != NULL);
  EXPECT_TRUE(
      decomposed.header.data_directory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG]
          != NULL);
  EXPECT_TRUE(
      decomposed.header.data_directory[IMAGE_DIRECTORY_ENTRY_IAT]
          != NULL);
}

// TODO(siggi): More tests.

}  // namespace image_util
