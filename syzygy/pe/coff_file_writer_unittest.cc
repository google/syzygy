// Copyright 2013 Google Inc. All Rights Reserved.
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

#include "syzygy/pe/coff_file_writer.h"

#include <cstring>

#include "base/path_service.h"
#include "base/files/file_util.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/block_graph/typed_block.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/coff_decomposer.h"
#include "syzygy/pe/coff_file.h"
#include "syzygy/pe/pe_utils.h"
#include "syzygy/pe/unittest_util.h"

namespace pe {

using block_graph::BlockGraph;
using block_graph::ConstTypedBlock;
using core::RelativeAddress;

typedef testing::ApplicationTestBase CoffFileWriterTest;

TEST_F(CoffFileWriterTest, RedecomposeAfterWrite) {
  // Compute paths.
  base::FilePath temp_dir;
  ASSERT_NO_FATAL_FAILURE(CreateTemporaryDir(&temp_dir));

  base::FilePath image_path_0(
      testing::GetExeTestDataRelativePath(testing::kTestDllCoffObjName));
  base::FilePath image_path_1(temp_dir.Append(testing::kTestDllName));

  // Decompose the original image.
  CoffFile image_file_0;
  ASSERT_TRUE(image_file_0.Init(image_path_0));

  CoffDecomposer decomposer_0(image_file_0);
  block_graph::BlockGraph block_graph_0;
  pe::ImageLayout image_layout_0(&block_graph_0);
  ASSERT_TRUE(decomposer_0.Decompose(&image_layout_0));

  // Write temporary image file.
  CoffFileWriter writer_0(&image_layout_0);
  ASSERT_TRUE(writer_0.WriteImage(image_path_1));

  // Redecompose.
  CoffFile image_file_1;
  ASSERT_TRUE(image_file_1.Init(image_path_1));

  CoffDecomposer decomposer_1(image_file_1);
  block_graph::BlockGraph block_graph_1;
  pe::ImageLayout image_layout_1(&block_graph_1);
  ASSERT_TRUE(decomposer_1.Decompose(&image_layout_1));

  // Compare the results of the two decompositions.
  EXPECT_EQ(image_layout_0.sections, image_layout_1.sections);
  EXPECT_EQ(image_layout_0.blocks.size(), image_layout_1.blocks.size());

  ConstTypedBlock<IMAGE_FILE_HEADER> file_header_0;
  ConstTypedBlock<IMAGE_FILE_HEADER> file_header_1;
  BlockGraph::Block* headers_block_0 =
      image_layout_0.blocks.GetBlockByAddress(RelativeAddress(0));
  BlockGraph::Block* headers_block_1 =
      image_layout_1.blocks.GetBlockByAddress(RelativeAddress(0));
  ASSERT_TRUE(headers_block_0 != NULL);
  ASSERT_TRUE(headers_block_1 != NULL);
  ASSERT_TRUE(file_header_0.Init(0, headers_block_0));
  ASSERT_TRUE(file_header_1.Init(0, headers_block_1));
  EXPECT_TRUE(std::memcmp(&file_header_0[0], &file_header_1[0],
                          sizeof(file_header_0[0])) == 0);
}

}  // namespace pe
