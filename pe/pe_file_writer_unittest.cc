// Copyright 2010 Google Inc.
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
#include "syzygy/pe/pe_file_writer.h"

#include "base/file_util.h"
#include "base/path_service.h"
#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/pe_file.h"
#include "syzygy/pe/unittest_util.h"

namespace {

using pe::Decomposer;
using pe::PEFile;

class PEFileWriterTest: public testing::PELibUnitTest {
  // Add customizations here.
};

}  // namespace

namespace pe {

TEST_F(PEFileWriterTest, LoadOriginalImage) {
  // This test baselines the other test(s) that operate on mutated, copied
  // versions of the DLLs.
  FilePath image_path(GetExeRelativePath(kDllName));
  ASSERT_NO_FATAL_FAILURE(CheckTestDll(image_path));
}

TEST_F(PEFileWriterTest, RewriteAndLoadImage) {
  // Create a temporary file we can write the new image to.
  FilePath temp_dir;
  ASSERT_NO_FATAL_FAILURE(CreateTemporaryDir(&temp_dir));
  FilePath temp_file = temp_dir.Append(kDllName);

  // Decompose the original test image.
  PEFile image_file;
  FilePath image_path(GetExeRelativePath(kDllName));
  ASSERT_TRUE(image_file.Init(image_path));

  Decomposer decomposer(image_file);
  core::BlockGraph block_graph;
  pe::ImageLayout image_layout(&block_graph);
  ASSERT_TRUE(decomposer.Decompose(&image_layout, NULL));

  PEFileWriter writer(image_layout);

  ASSERT_TRUE(writer.WriteImage(temp_file));
  ASSERT_NO_FATAL_FAILURE(CheckTestDll(temp_file));
}

}  // namespace pe
