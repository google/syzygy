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

#include "syzygy/pe/pe_file_writer.h"

#include "base/file_util.h"
#include "base/path_service.h"
#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/pe_file.h"
#include "syzygy/pe/unittest_util.h"

namespace pe {

namespace {

class PEFileWriterTest: public testing::PELibUnitTest {
  // Add customizations here.
};

}  // namespace

TEST_F(PEFileWriterTest, LoadOriginalImage) {
  // This test baselines the other test(s) that operate on mutated, copied
  // versions of the DLLs.
  FilePath image_path(testing::GetExeRelativePath(kDllName));
  ASSERT_NO_FATAL_FAILURE(CheckTestDll(image_path));
}

TEST_F(PEFileWriterTest, RewriteAndLoadImage) {
  // Create a temporary file we can write the new image to.
  FilePath temp_dir;
  ASSERT_NO_FATAL_FAILURE(CreateTemporaryDir(&temp_dir));
  FilePath temp_file = temp_dir.Append(kDllName);

  // Decompose the original test image.
  PEFile image_file;
  FilePath image_path(testing::GetExeRelativePath(kDllName));
  ASSERT_TRUE(image_file.Init(image_path));

  Decomposer decomposer(image_file);
  block_graph::BlockGraph block_graph;
  pe::ImageLayout image_layout(&block_graph);
  ASSERT_TRUE(decomposer.Decompose(&image_layout));

  PEFileWriter writer(image_layout);

  ASSERT_TRUE(writer.WriteImage(temp_file));
  ASSERT_NO_FATAL_FAILURE(CheckTestDll(temp_file));
}

TEST_F(PEFileWriterTest, UpdateFileChecksum) {
  FilePath temp_dir;
  ASSERT_NO_FATAL_FAILURE(CreateTemporaryDir(&temp_dir));

  // Verify that the function fails on non-existent paths.
  FilePath executable = temp_dir.Append(L"executable_file.exe");
  EXPECT_FALSE(PEFileWriter::UpdateFileChecksum(executable));

  // Verify that the function fails for non-image files.
  file_util::ScopedFILE file(file_util::OpenFile(executable, "wb"));
  // Grow the file to 16K.
  ASSERT_EQ(0, fseek(file.get(), 16 * 1024, SEEK_SET));
  file.reset();
  EXPECT_FALSE(PEFileWriter::UpdateFileChecksum(executable));

  // Make a copy of our test DLL and check that we work on that.
  FilePath input_path(testing::GetExeRelativePath(kDllName));
  FilePath image_path(temp_dir.Append(kDllName));
  EXPECT_TRUE(file_util::CopyFile(input_path, image_path));
  EXPECT_TRUE(PEFileWriter::UpdateFileChecksum(image_path));
}

}  // namespace pe
