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
#include "syzygy/pe/decomposer.h"

#include "base/file_util.h"
#include "base/path_service.h"
#include "base/string_util.h"
#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/unittest_util.h"

namespace {

class DecomposerTest: public testing::PELibUnitTest {
  // Insert your customizations here.
};

}  // namespace

namespace pe {

TEST_F(DecomposerTest, Decompose) {
  FilePath image_path(GetExeRelativePath(kDllName));
  PEFile image_file;

  ASSERT_TRUE(image_file.Init(image_path));

  // Decompose the test image and look at the result.
  Decomposer decomposer(image_file, image_path);

  Decomposer::DecomposedImage decomposed;
  Decomposer::CoverageStatistics stats;
  ASSERT_TRUE(decomposer.Decompose(&decomposed, &stats,
                                   Decomposer::STANDARD_DECOMPOSITION));

  EXPECT_TRUE(decomposed.header.dos_header != NULL);
  EXPECT_TRUE(decomposed.header.nt_headers != NULL);

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

  // We expect there to be at least one code section and one data section.
  EXPECT_TRUE(stats.sections.code.section_count > 0);
  EXPECT_TRUE(stats.sections.data.section_count > 0);

  // We expect section-summary stats to agree with the per-section-type stats.
  EXPECT_EQ(stats.sections.summary.section_count,
      stats.sections.code.section_count + stats.sections.data.section_count +
      stats.sections.unknown.section_count);
  EXPECT_EQ(stats.sections.summary.data_size,
      stats.sections.code.data_size + stats.sections.data.data_size +
      stats.sections.unknown.data_size);
  EXPECT_EQ(stats.sections.summary.virtual_size,
      stats.sections.code.virtual_size + stats.sections.data.virtual_size +
      stats.sections.unknown.virtual_size);

  // We expect there to be at least code and one data block.
  EXPECT_TRUE(stats.blocks.code.summary.block_count > 0);
  EXPECT_TRUE(stats.blocks.data.summary.block_count > 0);
}

TEST_F(DecomposerTest, BlockGraphSerializationRoundTrip) {
  FilePath image_path(GetExeRelativePath(kDllName));
  PEFile image_file;

  ASSERT_TRUE(image_file.Init(image_path));

  // Decompose the test image and look at the result.
  Decomposer decomposer(image_file, image_path);

  Decomposer::DecomposedImage decomposed;
  Decomposer::CoverageStatistics stats;
  ASSERT_TRUE(decomposer.Decompose(&decomposed, &stats,
                                   Decomposer::STANDARD_DECOMPOSITION));

  FilePath temp_dir;
  CreateTemporaryDir(&temp_dir);
  FilePath temp_file_path = temp_dir.Append(L"test_dll.dll.bg");

  // Save the BlockGraph.
  {
    file_util::ScopedFILE temp_file(file_util::OpenFile(temp_file_path, "wb"));
    core::FileOutStream out_stream(temp_file.get());
    core::NativeBinaryOutArchive out_archive(&out_stream);
    EXPECT_TRUE(SaveDecomposition(image_file, decomposed, &out_archive));
  }

  // Load the BlockGraph, and compare it to the original.
  {
    file_util::ScopedFILE temp_file(file_util::OpenFile(temp_file_path, "rb"));
    core::FileInStream in_stream(temp_file.get());
    core::NativeBinaryInArchive in_archive(&in_stream);
    PEFile in_image_file;
    Decomposer::DecomposedImage in_decomposed;
    EXPECT_TRUE(LoadDecomposition(&in_image_file, &in_decomposed, &in_archive));

    EXPECT_TRUE(testing::BlockGraphsEqual(decomposed.image,
                                          in_decomposed.image));
  }
}

// TODO(siggi): More tests.

}  // namespace pe
