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
// Contains unittests for ImageSourceMap.

#include "syzygy/pe/image_source_map.h"

#include "gmock/gmock.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pdb/omap.h"
#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/unittest_util.h"

// A comparison operator for OMAP objects so that we can use ContainerEq.
bool operator==(const OMAP& omap1, const OMAP& omap2) {
  return omap1.rva == omap2.rva &&
      omap1.rvaTo == omap2.rvaTo;
}

namespace pe {

using block_graph::BlockGraph;
using core::RelativeAddress;

namespace {

class ImageSourceMapTest: public testing::PELibUnitTest {
  // Insert your customizations here.
};

// Acts as a constructor for OMAP objects.
OMAP BuildOmap(ULONG rva, ULONG rvaTo) {
  OMAP omap = { rva, rvaTo };
  return omap;
}

// Returns true if the given OMAP vector is valid. That is, if it is sorted
// according to rva values.
bool IsValidOmapVector(const std::vector<OMAP>& omap) {
  for (size_t i = 1; i < omap.size(); ++i) {
    if (omap[i].rva <= omap[i - 1].rva)
      return false;
  }
  return true;
}

}  // namespace

TEST_F(ImageSourceMapTest, FromUntransformedImageLayout) {
  base::FilePath image_path(testing::GetExeRelativePath(testing::kTestDllName));
  PEFile image_file;

  ASSERT_TRUE(image_file.Init(image_path));

  Decomposer decomposer(image_file);
  BlockGraph block_graph;
  ImageLayout image_layout(&block_graph);
  ASSERT_TRUE(decomposer.Decompose(&image_layout));

  ImageSourceMap source_map;
  BuildImageSourceMap(image_layout, &source_map);
  EXPECT_GT(source_map.size(), 0u);

  // We expect every entry of the resulting map to be an identity mapping.
  ImageSourceMap::RangePairs::const_iterator it =
      source_map.range_pairs().begin();
  for (; it != source_map.range_pairs().end(); ++it)
    EXPECT_EQ(it->first, it->second);
}

TEST_F(ImageSourceMapTest, OmapConversion) {
  // We imagine an original image with the following layout:
  //
  //     512             128           128
  // +---------+-------+-----+-------+-----+-------+
  // | HEADERS | empty |  A  | empty |  B  | empty |
  // +---------+-------+-----+-------+-----+-------+
  // 0         512     1024  1152    1536  1664    2048
  //
  // and consider it post-transform with this layout:
  //
  //     512             128   128
  // +---------+-------+-----+-----+-------+
  // | HEADERS | empty |  B  |  A  | empty |
  // +---------+-------+-----+-----+-------+
  // 0         512     1024  1152  1280    1536

  const RelativeAddressRange h_old(RelativeAddress(0), 512);
  const RelativeAddressRange h_new(RelativeAddress(0), 512);
  const RelativeAddressRange a_old(RelativeAddress(1024), 128);
  const RelativeAddressRange a_new(RelativeAddress(1152), 128);
  const RelativeAddressRange b_old(RelativeAddress(1536), 128);
  const RelativeAddressRange b_new(RelativeAddress(1024), 128);
  const size_t size_new = 1536;

  ImageSourceMap source_map;
  ASSERT_TRUE(source_map.Push(h_new, h_old));
  ASSERT_TRUE(source_map.Push(b_new, b_old));
  ASSERT_TRUE(source_map.Push(a_new, a_old));

  std::vector<OMAP> omap_to;
  BuildOmapVectorFromImageSourceMap(
      RelativeAddressRange(RelativeAddress(0), size_new), source_map, &omap_to);
  EXPECT_TRUE(IsValidOmapVector(omap_to));

  std::vector<OMAP> expected;
  expected.push_back(BuildOmap(0, 0));
  expected.push_back(BuildOmap(512, kInvalidOmapRvaTo));
  expected.push_back(BuildOmap(1024, 1536));
  expected.push_back(BuildOmap(1152, 1024));
  expected.push_back(BuildOmap(1280, kInvalidOmapRvaTo));
  expected.push_back(BuildOmap(1536, kInvalidOmapRvaTo));
  EXPECT_THAT(expected, testing::ContainerEq(omap_to));
}

TEST_F(ImageSourceMapTest, OmapShrinkingRanges) {
  ImageSourceMap source_map;
  RelativeAddressRange src(RelativeAddress(0), 10);
  RelativeAddressRange dst(RelativeAddress(0), 8);
  ASSERT_TRUE(source_map.Push(src, dst));

  std::vector<OMAP> omap_to;
  BuildOmapVectorFromImageSourceMap(src, source_map, &omap_to);

  // Ensure that every address in the source range gets mapped to some address
  // in the destination range.
  for (RelativeAddress rva = src.start(); rva != src.end(); rva += 1) {
    RelativeAddress mapped_rva = pdb::TranslateAddressViaOmap(omap_to, rva);
    EXPECT_TRUE(dst.Contains(mapped_rva, 1));
  }
}

}  // namespace pe
