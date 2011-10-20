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
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/unittest_util.h"

namespace {

class DecomposerTest: public testing::PELibUnitTest {
  // Insert your customizations here.
};

}  // namespace

namespace pe {

bool operator==(const ImageLayout::SegmentInfo& a,
                const ImageLayout::SegmentInfo& b) {
  return a.name == b.name && a.addr == b.addr &&
      a.size == b.size && a.data_size == b.data_size &&
      a.characteristics == b.characteristics;
}

TEST_F(DecomposerTest, Decompose) {
  FilePath image_path(GetExeRelativePath(kDllName));
  PEFile image_file;

  ASSERT_TRUE(image_file.Init(image_path));

  // Decompose the test image and look at the result.
  Decomposer decomposer(image_file, image_path);

  core::BlockGraph block_graph;
  ImageLayout image_layout(&block_graph);
  Decomposer::CoverageStatistics stats;
  ASSERT_TRUE(decomposer.Decompose(&image_layout, &stats));

  // There should be some blocks in the graph and in the layout.
  EXPECT_NE(0U, block_graph.blocks().size());
  EXPECT_NE(0U, image_layout.blocks.address_space_impl().size());

  // All the blocks in the graph should be represented in the address space.
  EXPECT_EQ(block_graph.blocks().size(),
            image_layout.blocks.address_space_impl().size());

  EXPECT_EQ(
      IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE | IMAGE_FILE_DLL,
      image_layout.header_info.characteristics);
  // These are by observation on VC 2008, please amend as necessary
  // for other/future toolchains.
  EXPECT_LE(0x07, image_layout.header_info.major_linker_version);
  EXPECT_EQ(0x00, image_layout.header_info.minor_linker_version);
  EXPECT_EQ(0x10000000, image_layout.header_info.image_base);
  EXPECT_EQ(0x1000, image_layout.header_info.section_alignment);
  EXPECT_EQ(0x200, image_layout.header_info.file_alignment);

  EXPECT_EQ(0x0005, image_layout.header_info.major_operating_system_version);
  EXPECT_EQ(0x0000, image_layout.header_info.minor_operating_system_version);

  EXPECT_EQ(0x0000, image_layout.header_info.major_image_version);
  EXPECT_EQ(0x0000, image_layout.header_info.minor_image_version);

  EXPECT_EQ(0x0005, image_layout.header_info.major_subsystem_version);
  EXPECT_EQ(0x0000, image_layout.header_info.minor_subsystem_version);

  EXPECT_EQ(0x00000000, image_layout.header_info.win32_version_value);
  EXPECT_EQ(0x00000400, image_layout.header_info.size_of_headers);

  EXPECT_EQ(0x0003, image_layout.header_info.subsystem);
  EXPECT_EQ(IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE |
      IMAGE_DLLCHARACTERISTICS_NX_COMPAT,
      image_layout.header_info.dll_characteristics);

  EXPECT_EQ(0x00100000, image_layout.header_info.size_of_stack_reserve);
  EXPECT_EQ(0x1000, image_layout.header_info.size_of_stack_commit);
  EXPECT_EQ(0x100000, image_layout.header_info.size_of_heap_reserve);
  EXPECT_EQ(0x1000, image_layout.header_info.size_of_heap_commit);
  EXPECT_EQ(0, image_layout.header_info.loader_flags);

  ASSERT_EQ(6, image_layout.segments.size());

  EXPECT_EQ(".text", image_layout.segments[0].name);
  EXPECT_NE(0U, image_layout.segments[0].addr.value());
  EXPECT_NE(0U, image_layout.segments[0].size);
  EXPECT_NE(0U, image_layout.segments[0].data_size);
  EXPECT_EQ(IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
            image_layout.segments[0].characteristics);

  EXPECT_EQ(".rdata", image_layout.segments[1].name);
  EXPECT_NE(0U, image_layout.segments[1].addr.value());
  EXPECT_NE(0U, image_layout.segments[1].size);
  EXPECT_NE(0U, image_layout.segments[1].data_size);
  EXPECT_EQ(IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
            image_layout.segments[1].characteristics);

  EXPECT_EQ(".data", image_layout.segments[2].name);
  EXPECT_NE(0U, image_layout.segments[2].addr.value());
  EXPECT_NE(0U, image_layout.segments[2].size);
  EXPECT_NE(0U, image_layout.segments[2].data_size);
  EXPECT_EQ(
      IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
      image_layout.segments[2].characteristics);

  EXPECT_EQ(".tls", image_layout.segments[3].name);
  EXPECT_NE(0U, image_layout.segments[3].addr.value());
  EXPECT_NE(0U, image_layout.segments[3].size);
  EXPECT_NE(0U, image_layout.segments[3].data_size);
  EXPECT_EQ(
      IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
      image_layout.segments[3].characteristics);

  EXPECT_EQ(".rsrc", image_layout.segments[4].name);
  EXPECT_NE(0U, image_layout.segments[4].addr.value());
  EXPECT_NE(0U, image_layout.segments[4].size);
  EXPECT_NE(0U, image_layout.segments[4].data_size);
  EXPECT_EQ(IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
      image_layout.segments[4].characteristics);

  EXPECT_EQ(".reloc", image_layout.segments[5].name);
  EXPECT_NE(0U, image_layout.segments[5].addr.value());
  EXPECT_NE(0U, image_layout.segments[5].size);
  EXPECT_NE(0U, image_layout.segments[5].data_size);
  EXPECT_EQ(IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_DISCARDABLE |
      IMAGE_SCN_MEM_READ, image_layout.segments[5].characteristics);

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

  core::BlockGraph block_graph;
  ImageLayout image_layout(&block_graph);
  Decomposer::CoverageStatistics stats;
  ASSERT_TRUE(decomposer.Decompose(&image_layout, &stats));

  FilePath temp_dir;
  CreateTemporaryDir(&temp_dir);
  FilePath temp_file_path = temp_dir.Append(L"test_dll.dll.bg");

  // Save the BlockGraph.
  {
    file_util::ScopedFILE temp_file(file_util::OpenFile(temp_file_path, "wb"));
    core::FileOutStream out_stream(temp_file.get());
    core::NativeBinaryOutArchive out_archive(&out_stream);
    EXPECT_TRUE(
        SaveDecomposition(image_file, block_graph, image_layout, &out_archive));
  }

  // Load the BlockGraph, and compare it to the original.
  {
    file_util::ScopedFILE temp_file(file_util::OpenFile(temp_file_path, "rb"));
    core::FileInStream in_stream(temp_file.get());
    core::NativeBinaryInArchive in_archive(&in_stream);
    PEFile in_image_file;
    core::BlockGraph in_block_graph;
    ImageLayout in_image_layout(&block_graph);
    EXPECT_TRUE(LoadDecomposition(&in_archive,
                                  &in_image_file,
                                  &in_block_graph,
                                  &in_image_layout));

    EXPECT_TRUE(testing::BlockGraphsEqual(block_graph,
                                          in_block_graph));
    EXPECT_THAT(image_layout.blocks.address_space_impl().ranges(),
        testing::ContainerEq(
            in_image_layout.blocks.address_space_impl().ranges()));

    EXPECT_EQ(0, memcmp(&image_layout.header_info,
                        &in_image_layout.header_info,
                        sizeof(image_layout.header_info)));
    EXPECT_THAT(image_layout.segments,
                testing::ContainerEq(in_image_layout.segments));
  }
}

TEST_F(DecomposerTest, BasicBlockDecompose) {
  FilePath image_path(GetExeRelativePath(kDllName));
  PEFile image_file;

  ASSERT_TRUE(image_file.Init(image_path));

  // Decompose the test image and look at the result.
  Decomposer decomposer(image_file, image_path);

  core::BlockGraph block_graph;
  ImageLayout image_layout(&block_graph);
  Decomposer::CoverageStatistics stats;
  ASSERT_TRUE(decomposer.Decompose(&image_layout, &stats));

  Decomposer::BasicBlockBreakdown breakdown;
  ASSERT_TRUE(decomposer.BasicBlockDecompose(image_layout, &breakdown));
  ASSERT_TRUE(breakdown.basic_block_address_space.begin() !=
      breakdown.basic_block_address_space.end());
}

}  // namespace pe
