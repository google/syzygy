// Copyright 2011 Google Inc. All Rights Reserved.
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
// Contains unittests for the functionality defined in image_layout.h.

#include "syzygy/pe/image_layout.h"

#include "gmock/gmock.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/unittest_util.h"

namespace pe {

using block_graph::BlockGraph;
using core::RelativeAddress;

namespace {

class ImageLayoutTest: public testing::PELibUnitTest {
  // Insert your customizations here.
};

// Returns true if the given sections are equivalent, ignoring the data_size.
bool SectionsAreEqual(const ImageLayout::SectionInfo& a,
                      const ImageLayout::SectionInfo& b) {
  return a.name == b.name && a.addr == b.addr && a.size == b.size &&
      a.characteristics == b.characteristics;
}

}  // namespace

TEST_F(ImageLayoutTest, BuildCanonicalImageLayout) {
  base::FilePath image_path(testing::GetExeRelativePath(testing::kTestDllName));
  PEFile image_file;

  ASSERT_TRUE(image_file.Init(image_path));

  Decomposer decomposer(image_file);
  BlockGraph block_graph;
  ImageLayout image_layout(&block_graph);
  ASSERT_TRUE(decomposer.Decompose(&image_layout));

  ImageLayout canonical_image_layout(&block_graph);
  EXPECT_TRUE(BuildCanonicalImageLayout(&canonical_image_layout));

  // We expect the sections to be in the same order and have the same size and
  // addresses. We do not check the data size, as it is effectively impossible
  // for us to perform the exact same logic as the original toolchain here, and
  // we often see different results. In fact, we are more aggressive at trimming
  // NULLS from the end of a section, especially when it comes to .relocs.
  EXPECT_EQ(image_layout.sections.size(),
            canonical_image_layout.sections.size());
  for (size_t i = 0; i < image_layout.sections.size(); ++i) {
    EXPECT_TRUE(SectionsAreEqual(image_layout.sections[i],
                                 canonical_image_layout.sections[i]));
  }

  BlockGraph::AddressSpace::RangeMapConstIter block_it1 =
      image_layout.blocks.begin();
  BlockGraph::AddressSpace::RangeMapConstIter block_it2 =
      canonical_image_layout.blocks.begin();
  while (true) {
    if (block_it1 == image_layout.blocks.end())
      break;
    if (block_it2 == canonical_image_layout.blocks.end())
      break;

    // We expect the same block to be mapped to the same position in each
    // image.
    EXPECT_EQ(block_it1->first, block_it2->first);
    EXPECT_EQ(block_it1->second, block_it2->second);

    ++block_it1;
    ++block_it2;
  }
}

TEST_F(ImageLayoutTest, CopyImageLayoutWithoutPadding) {
  base::FilePath image_path(testing::GetExeRelativePath(testing::kTestDllName));
  PEFile image_file;

  ASSERT_TRUE(image_file.Init(image_path));

  Decomposer decomposer(image_file);
  BlockGraph block_graph;
  ImageLayout orig_image_layout(&block_graph);
  ASSERT_TRUE(decomposer.Decompose(&orig_image_layout));

  ImageLayout image_layout(&block_graph);
  EXPECT_TRUE(CopyImageLayoutWithoutPadding(orig_image_layout, &image_layout));

  EXPECT_LT(image_layout.blocks.size(), orig_image_layout.blocks.size());
  EXPECT_EQ(image_layout.blocks.size(), block_graph.blocks().size());

  BlockGraph::BlockMap::const_iterator block_it =
      block_graph.blocks().begin();
  for (; block_it != block_graph.blocks().end(); ++block_it) {
    const BlockGraph::Block* block = &(block_it->second);
    EXPECT_EQ(0u, block->attributes() & BlockGraph::PADDING_BLOCK);
  }
}

}  // namespace pe
