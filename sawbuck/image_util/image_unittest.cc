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
//
#include "sawbuck/image_util/image.h"
#include "gtest/gtest.h"

namespace image_util {

TEST(ImageTest, Create) {
  Image image;
}

TEST(ImageTest, AddBlock) {
  Image image;

  Image::Block* block = image.AddBlock(Image::CODE_BLOCK, 0x20, "code");
  ASSERT_TRUE(block != NULL);

  ASSERT_EQ(Image::CODE_BLOCK, block->type());
  ASSERT_EQ(0x20, block->size());
  ASSERT_STREQ("code", block->name().c_str());
  ASSERT_EQ(NULL, block->data());
  ASSERT_EQ(0, block->data_size());
}

TEST(ImageAddressSpaceTest, AddBlock) {
  Image image;
  Image::AddressSpace address_space(RelativeAddress(0), 0x2000, &image);

  // We should be able to insert this block.
  Image::Block* block = address_space.AddBlock(Image::CODE_BLOCK,
                                               RelativeAddress(0x1000),
                                               0x20,
                                               "code");

  // But inserting anything that intersects with it should fail.
  EXPECT_EQ(NULL, address_space.AddBlock(Image::CODE_BLOCK,
                                         RelativeAddress(0x1000),
                                         0x20,
                                         "code"));

  // Overlapping from below.
  EXPECT_EQ(NULL, address_space.AddBlock(Image::CODE_BLOCK,
                                         RelativeAddress(0xFF0),
                                         0x20,
                                         "code"));
  // Enclosing.
  EXPECT_EQ(NULL, address_space.AddBlock(Image::CODE_BLOCK,
                                         RelativeAddress(0xFF0),
                                         0x30,
                                         "code"));
  // Itersecting to end.
  EXPECT_EQ(NULL, address_space.AddBlock(Image::CODE_BLOCK,
                                         RelativeAddress(0x1010),
                                         0x10,
                                         "code"));
  // Intersecting, overlapping the back.
  EXPECT_EQ(NULL, address_space.AddBlock(Image::CODE_BLOCK,
                                         RelativeAddress(0x1010),
                                         0x20,
                                         "code"));

  // We should be able to insert blocks above and below the one above.
  EXPECT_TRUE(address_space.AddBlock(Image::CODE_BLOCK,
                                     RelativeAddress(0xFF0),
                                     0x10,
                                     "code") != NULL);
  EXPECT_TRUE(address_space.AddBlock(Image::CODE_BLOCK,
                                     RelativeAddress(0x1020),
                                     0x10,
                                     "code") != NULL);
}

TEST(ImageAddressSpaceTest, InsertBlock) {
  Image image;
  Image::AddressSpace address_space(RelativeAddress(0), 0x2000, &image);

  Image::Block* block1 = image.AddBlock(Image::CODE_BLOCK, 0x10, "code");
  Image::Block* block2 = image.AddBlock(Image::CODE_BLOCK, 0x10, "code");
  Image::Block* block3 = image.AddBlock(Image::CODE_BLOCK, 0x10, "code");

  ASSERT_TRUE(address_space.InsertBlock(RelativeAddress(0x1000), block1));
  ASSERT_FALSE(address_space.InsertBlock(RelativeAddress(0x1000), block2));
  ASSERT_TRUE(address_space.InsertBlock(RelativeAddress(0x1010), block2));
  ASSERT_FALSE(address_space.InsertBlock(RelativeAddress(0x1018), block3));
  ASSERT_TRUE(address_space.InsertBlock(RelativeAddress(0x1030), block3));

  RelativeAddress addr;
  EXPECT_TRUE(address_space.GetAddressOf(block1, &addr));
  EXPECT_EQ(0x1000, addr.value());

  EXPECT_TRUE(address_space.GetAddressOf(block2, &addr));
  EXPECT_EQ(0x1010, addr.value());

  EXPECT_TRUE(address_space.GetAddressOf(block3, &addr));
  EXPECT_EQ(0x1030, addr.value());
}

TEST(ImageAddressSpaceTest, GetBlockByAddress) {
  Image image;
  Image::AddressSpace address_space(RelativeAddress(0), 0x2000, &image);

  Image::Block* block1 = address_space.AddBlock(Image::CODE_BLOCK,
                                                RelativeAddress(0x1000),
                                                0x10,
                                                "code");
  Image::Block* block2 = address_space.AddBlock(Image::CODE_BLOCK,
                                                RelativeAddress(0x1010),
                                                0x10,
                                                "code");
  Image::Block* block3 = address_space.AddBlock(Image::CODE_BLOCK,
                                                RelativeAddress(0x1030),
                                                0x10,
                                                "code");

  EXPECT_EQ(NULL, address_space.GetBlockByAddress(RelativeAddress(0xFFF)));

  EXPECT_EQ(block1, address_space.GetBlockByAddress(RelativeAddress(0x1000)));
  EXPECT_EQ(block1, address_space.GetBlockByAddress(RelativeAddress(0x100F)));

  EXPECT_EQ(block2, address_space.GetBlockByAddress(RelativeAddress(0x1010)));
  EXPECT_EQ(block2, address_space.GetBlockByAddress(RelativeAddress(0x101F)));

  EXPECT_EQ(NULL, address_space.GetBlockByAddress(RelativeAddress(0x1020)));
  EXPECT_EQ(NULL, address_space.GetBlockByAddress(RelativeAddress(0x102F)));

  EXPECT_EQ(block3, address_space.GetBlockByAddress(RelativeAddress(0x1030)));
  EXPECT_EQ(block3, address_space.GetBlockByAddress(RelativeAddress(0x103F)));

  EXPECT_EQ(NULL, address_space.GetBlockByAddress(RelativeAddress(0x1040)));
}

TEST(ImageAddressSpaceTest, GetFirstItersectingBlock) {
  Image image;
  Image::AddressSpace address_space(RelativeAddress(0), 0x2000, &image);

  Image::Block* block1 = address_space.AddBlock(Image::CODE_BLOCK,
                                                RelativeAddress(0x1000),
                                                0x10,
                                                "code");
  Image::Block* block2 = address_space.AddBlock(Image::CODE_BLOCK,
                                                RelativeAddress(0x1010),
                                                0x10,
                                                "code");
  Image::Block* block3 = address_space.AddBlock(Image::CODE_BLOCK,
                                                RelativeAddress(0x1030),
                                                0x10,
                                                "code");

  EXPECT_EQ(NULL,
      address_space.GetFirstItersectingBlock(RelativeAddress(0xFFF), 0x1));
  EXPECT_EQ(block1,
      address_space.GetFirstItersectingBlock(RelativeAddress(0xFFF), 0x2));
  EXPECT_EQ(block1,
      address_space.GetFirstItersectingBlock(RelativeAddress(0x100F), 0x1));
  EXPECT_EQ(block1,
      address_space.GetFirstItersectingBlock(RelativeAddress(0x100F), 0x2));

  EXPECT_EQ(block2,
      address_space.GetFirstItersectingBlock(RelativeAddress(0x1010), 0x40));
}

TEST(ImageAddressSpaceTest, GetBlockAddress) {
  Image image;
  Image::AddressSpace address_space(RelativeAddress(0), 0x2000, &image);

  Image::Block* block1 = address_space.AddBlock(Image::CODE_BLOCK,
                                                RelativeAddress(0x1000),
                                                0x10,
                                                "code");
  Image::Block* block2 = address_space.AddBlock(Image::CODE_BLOCK,
                                                RelativeAddress(0x1010),
                                                0x10,
                                                "code");
  Image::Block* block3 = image.AddBlock(Image::CODE_BLOCK, 0x10, "code");

  RelativeAddress addr;
  EXPECT_TRUE(address_space.GetAddressOf(block1, &addr));
  EXPECT_EQ(0x1000, addr.value());

  EXPECT_TRUE(address_space.GetAddressOf(block2, &addr));
  EXPECT_EQ(0x1010, addr.value());

  EXPECT_FALSE(address_space.GetAddressOf(block3, &addr));
}

// TODO(siggi): Write unittests for block references.

}  // namespace image_util
