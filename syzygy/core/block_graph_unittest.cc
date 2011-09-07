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
#include "syzygy/core/block_graph.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"

namespace core {

TEST(BlockGraphTest, Create) {
  BlockGraph image;
}

TEST(BlockGraphTest, AddBlock) {
  BlockGraph image;

  BlockGraph::Block* block =
      image.AddBlock(BlockGraph::CODE_BLOCK, 0x20, "block");
  ASSERT_TRUE(block != NULL);

  // Test initialization.
  ASSERT_EQ(BlockGraph::CODE_BLOCK, block->type());
  ASSERT_EQ(0x20, block->size());
  ASSERT_STREQ("block", block->name());
  ASSERT_EQ(kInvalidAddress, block->addr());
  ASSERT_EQ(kInvalidAddress, block->original_addr());
  ASSERT_EQ(kInvalidSection, block->section());
  ASSERT_EQ(0, block->attributes());
  ASSERT_EQ(NULL, block->data());
  ASSERT_EQ(0, block->data_size());
  ASSERT_FALSE(block->owns_data());

  block->set_attribute(0x20);
  ASSERT_EQ(0x20, block->attributes());
  block->set_attribute(0x10);
  ASSERT_EQ(0x30, block->attributes());
  block->clear_attribute(0x20);
  ASSERT_EQ(0x10, block->attributes());

  // Test accessors.
  static const uint8 kTestData[] = "who's your daddy?";
  block->set_data(kTestData);
  ASSERT_EQ(kTestData, block->data());
  block->set_data_size(sizeof(kTestData));
  ASSERT_EQ(sizeof(kTestData), block->data_size());

  block->set_owns_data(true);
  ASSERT_TRUE(block->owns_data());
  block->set_owns_data(false);
  ASSERT_FALSE(block->owns_data());
}

TEST(BlockGraphTest, RemoveBlock) {
  BlockGraph image;

  // Add some blocks to the image.
  BlockGraph::Block* b1 = image.AddBlock(BlockGraph::CODE_BLOCK, 0x20, "b1");
  BlockGraph::Block* b2 = image.AddBlock(BlockGraph::CODE_BLOCK, 0x20, "b2");
  BlockGraph::Block* b3 = image.AddBlock(BlockGraph::CODE_BLOCK, 0x20, "b3");
  BlockGraph::Block* b4 = image.AddBlock(BlockGraph::CODE_BLOCK, 0x20, "b4");
  ASSERT_TRUE(b1 != NULL);
  ASSERT_TRUE(b2 != NULL);
  ASSERT_TRUE(b3 != NULL);
  ASSERT_TRUE(b4 != NULL);
  EXPECT_EQ(4u, image.blocks().size());

  // Add a reference from block 1 to block 2.
  BlockGraph::Reference ref12(BlockGraph::PC_RELATIVE_REF, 1, b2, 9);
  ASSERT_TRUE(b1->SetReference(0, ref12));
  EXPECT_THAT(b1->references(), testing::Contains(std::make_pair(0, ref12)));
  EXPECT_THAT(b2->referrers(), testing::Contains(std::make_pair(b1, 0)));
  EXPECT_EQ(1u, b1->references().size());
  EXPECT_EQ(1u, b2->referrers().size());

  // Try to delete Block 1. This should fail because it has references.
  ASSERT_FALSE(image.RemoveBlock(b1));
  EXPECT_EQ(4u, image.blocks().size());

  // Try to delete Block 2. This should fail because it has referrers.
  ASSERT_FALSE(image.RemoveBlockById(b2->id()));
  EXPECT_EQ(4u, image.blocks().size());

  // Try to delete a block that doesn't belong to the block graph. This
  // should fail.
  BlockGraph other_image;
  BlockGraph::Block* other_block =
      other_image.AddBlock(BlockGraph::CODE_BLOCK, 0x20, "other_block");
  ASSERT_FALSE(image.RemoveBlock(other_block));
  EXPECT_EQ(4u, image.blocks().size());

  // Try to delete a block with an invalid ID. This should fail.
  ASSERT_FALSE(image.RemoveBlockById(15));
  EXPECT_EQ(4u, image.blocks().size());

  // Delete block 3.
  ASSERT_TRUE(image.RemoveBlock(b3));
  EXPECT_EQ(3u, image.blocks().size());

  // Delete block 4.
  ASSERT_TRUE(image.RemoveBlockById(b4->id()));
  EXPECT_EQ(2u, image.blocks().size());
}

TEST(BlockGraphTest, References) {
  BlockGraph image;

  BlockGraph::Block* b1 = image.AddBlock(BlockGraph::CODE_BLOCK, 0x20, "b1");
  BlockGraph::Block* b2 = image.AddBlock(BlockGraph::CODE_BLOCK, 0x20, "b2");
  BlockGraph::Block* b3 = image.AddBlock(BlockGraph::CODE_BLOCK, 0x20, "b3");
  ASSERT_TRUE(b1 != NULL);
  ASSERT_TRUE(b2 != NULL);
  ASSERT_TRUE(b3 != NULL);

  ASSERT_TRUE(b1->references().empty());
  ASSERT_TRUE(b1->referrers().empty());
  ASSERT_TRUE(b2->references().empty());
  ASSERT_TRUE(b2->referrers().empty());
  ASSERT_TRUE(b3->references().empty());
  ASSERT_TRUE(b3->referrers().empty());

  // Add the first reference, and test that we get a backref.
  BlockGraph::Reference r_pc(BlockGraph::PC_RELATIVE_REF, 1, b2, 9);
  ASSERT_EQ(BlockGraph::PC_RELATIVE_REF, r_pc.type());
  ASSERT_EQ(1, r_pc.size());
  ASSERT_EQ(b2, r_pc.referenced());
  ASSERT_EQ(9, r_pc.offset());

  ASSERT_TRUE(b1->SetReference(0, r_pc));
  EXPECT_THAT(b2->referrers(), testing::Contains(std::make_pair(b1, 0)));

  ASSERT_TRUE(b1->SetReference(1, r_pc));
  EXPECT_THAT(b2->referrers(), testing::Contains(std::make_pair(b1, 1)));

  BlockGraph::Reference r_abs(BlockGraph::ABSOLUTE_REF, 1, b2, 13);
  ASSERT_FALSE(b1->SetReference(1, r_abs));
  BlockGraph::Reference r_rel(BlockGraph::RELATIVE_REF, 1, b2, 17);
  ASSERT_TRUE(b1->SetReference(2, r_rel));
  BlockGraph::Reference r_file(BlockGraph::FILE_OFFSET_REF, 4, b2, 23);
  ASSERT_TRUE(b1->SetReference(4, r_file));

  // Test that the reference map is as expected.
  BlockGraph::Block::ReferenceMap expected;
  expected.insert(std::make_pair(0, r_pc));
  expected.insert(std::make_pair(1, r_abs));
  expected.insert(std::make_pair(2, r_rel));
  expected.insert(std::make_pair(4, r_file));
  EXPECT_THAT(b1->references(), testing::ContainerEq(expected));

  // Test reference transfer.
  // This should fail, as all the references will fall outside b3.
  // TODO(chrisha): We need to create a logging MessageHandler that we can
  //     put test expectations on. This test is meant to fail, but we don't
  //     want to see the error message it would produce! Ideally, this should
  //     live in 'syzygy/testing' or something of the like, as it could be
  //     used across many unittests. For now, we simply disable logging for
  //     this test.
  int old_level = logging::GetMinLogLevel();
  logging::SetMinLogLevel(logging::LOG_FATAL);
  ASSERT_FALSE(b2->TransferReferrers(b3->size(), b3));
  logging::SetMinLogLevel(old_level);

  // Now move the references from b2 to b3
  ASSERT_TRUE(b2->TransferReferrers(0, b3));
  // Test that b2 no longer has referrers.
  EXPECT_THAT(b2->referrers(), BlockGraph::Block::ReferrerSet());

  // Test that the references transferred as expected.
  expected.clear();
  expected.insert(std::make_pair(0,
      BlockGraph::Reference(BlockGraph::PC_RELATIVE_REF, 1, b3, 9)));
  expected.insert(std::make_pair(1,
      BlockGraph::Reference(BlockGraph::ABSOLUTE_REF, 1, b3, 13)));
  expected.insert(std::make_pair(2,
      BlockGraph::Reference(BlockGraph::RELATIVE_REF, 1, b3, 17)));
  expected.insert(std::make_pair(4,
      BlockGraph::Reference(BlockGraph::FILE_OFFSET_REF, 4, b3, 23)));
  EXPECT_THAT(b1->references(), testing::ContainerEq(expected));

  // Remove the references.
  ASSERT_TRUE(b1->RemoveReference(0));
  ASSERT_TRUE(b1->RemoveReference(1));
  ASSERT_TRUE(b1->RemoveReference(2));
  ASSERT_TRUE(b1->RemoveReference(4));
  EXPECT_THAT(b1->references(), BlockGraph::Block::ReferenceMap());

  EXPECT_THAT(b2->referrers(), BlockGraph::Block::ReferrerSet());
}

TEST(BlockGraphTest, Labels) {
  BlockGraph image;

  BlockGraph::Block* block =
      image.AddBlock(BlockGraph::CODE_BLOCK, 0x20, "labeled");
  ASSERT_TRUE(block->labels().empty());
  for (int i = 0; i < 0x20; ++i) {
    ASSERT_FALSE(block->HasLabel(i));
  }

  EXPECT_TRUE(block->SetLabel(13, "foo"));
  EXPECT_FALSE(block->SetLabel(13, "foo2"));

  EXPECT_TRUE(block->SetLabel(17, "bar"));
  EXPECT_FALSE(block->SetLabel(17, "bar2"));

  for (int i = 0; i < 0x20; ++i) {
    if (i == 13 || i == 17) {
      ASSERT_TRUE(block->HasLabel(i));
    } else {
      ASSERT_FALSE(block->HasLabel(i));
    }
  }

  BlockGraph::Block::LabelMap expected;
  expected.insert(std::make_pair(13, "foo"));
  expected.insert(std::make_pair(17, "bar"));
  EXPECT_THAT(block->labels(), testing::ContainerEq(expected));
}

TEST(BlockGraphAddressSpaceTest, AddBlock) {
  BlockGraph image;
  BlockGraph::AddressSpace address_space(&image);

  // We should be able to insert this block.
  BlockGraph::Block* block = address_space.AddBlock(BlockGraph::CODE_BLOCK,
                                                    RelativeAddress(0x1000),
                                                    0x20,
                                                    "code");
  ASSERT_TRUE(block != NULL);
  EXPECT_EQ(0x1000, block->addr().value());
  EXPECT_EQ(0x1000, block->original_addr().value());

  // But inserting anything that intersects with it should fail.
  EXPECT_EQ(NULL, address_space.AddBlock(BlockGraph::CODE_BLOCK,
                                         RelativeAddress(0x1000),
                                         0x20,
                                         "code"));

  // Overlapping from below.
  EXPECT_EQ(NULL, address_space.AddBlock(BlockGraph::CODE_BLOCK,
                                         RelativeAddress(0xFF0),
                                         0x20,
                                         "code"));
  // Enclosing.
  EXPECT_EQ(NULL, address_space.AddBlock(BlockGraph::CODE_BLOCK,
                                         RelativeAddress(0xFF0),
                                         0x30,
                                         "code"));
  // Itersecting to end.
  EXPECT_EQ(NULL, address_space.AddBlock(BlockGraph::CODE_BLOCK,
                                         RelativeAddress(0x1010),
                                         0x10,
                                         "code"));
  // Intersecting, overlapping the back.
  EXPECT_EQ(NULL, address_space.AddBlock(BlockGraph::CODE_BLOCK,
                                         RelativeAddress(0x1010),
                                         0x20,
                                         "code"));

  // We should be able to insert blocks above and below the one above.
  EXPECT_TRUE(address_space.AddBlock(BlockGraph::CODE_BLOCK,
                                     RelativeAddress(0xFF0),
                                     0x10,
                                     "code") != NULL);
  EXPECT_TRUE(address_space.AddBlock(BlockGraph::CODE_BLOCK,
                                     RelativeAddress(0x1020),
                                     0x10,
                                     "code") != NULL);
}

TEST(BlockGraphAddressSpaceTest, InsertBlock) {
  BlockGraph image;
  BlockGraph::AddressSpace address_space(&image);

  BlockGraph::Block* block1 =
      image.AddBlock(BlockGraph::CODE_BLOCK, 0x10, "code");
  BlockGraph::Block* block2 =
      image.AddBlock(BlockGraph::CODE_BLOCK, 0x10, "code");
  BlockGraph::Block* block3 =
      image.AddBlock(BlockGraph::CODE_BLOCK, 0x10, "code");

  ASSERT_TRUE(address_space.InsertBlock(RelativeAddress(0x1000), block1));
  ASSERT_FALSE(address_space.InsertBlock(RelativeAddress(0x1000), block2));
  ASSERT_TRUE(address_space.InsertBlock(RelativeAddress(0x1010), block2));
  ASSERT_FALSE(address_space.InsertBlock(RelativeAddress(0x1018), block3));
  ASSERT_TRUE(address_space.InsertBlock(RelativeAddress(0x1030), block3));

  RelativeAddress addr;
  EXPECT_TRUE(address_space.GetAddressOf(block1, &addr));
  EXPECT_EQ(0x1000, addr.value());
  EXPECT_EQ(0x1000, block1->addr().value());
  EXPECT_EQ(0x1000, block1->original_addr().value());

  EXPECT_TRUE(address_space.GetAddressOf(block2, &addr));
  EXPECT_EQ(0x1010, addr.value());
  EXPECT_EQ(0x1010, block2->addr().value());
  EXPECT_EQ(0x1010, block2->original_addr().value());

  EXPECT_TRUE(address_space.GetAddressOf(block3, &addr));
  EXPECT_EQ(0x1030, addr.value());
  EXPECT_EQ(0x1030, block3->addr().value());
  EXPECT_EQ(0x1030, block3->original_addr().value());

  // Insert a block into a second address space.
  BlockGraph::AddressSpace address_space2(&image);
  EXPECT_TRUE(address_space2.InsertBlock(RelativeAddress(0x2000), block1));
  EXPECT_TRUE(address_space.GetAddressOf(block1, &addr));
  EXPECT_EQ(0x1000, addr.value());

  EXPECT_TRUE(address_space2.GetAddressOf(block1, &addr));
  EXPECT_EQ(0x2000, addr.value());

  EXPECT_EQ(0x2000, block1->addr().value());
  EXPECT_EQ(0x1000, block1->original_addr().value());
}

TEST(BlockGraphAddressSpaceTest, GetBlockByAddress) {
  BlockGraph image;
  BlockGraph::AddressSpace address_space(&image);

  BlockGraph::Block* block1 = address_space.AddBlock(BlockGraph::CODE_BLOCK,
                                                     RelativeAddress(0x1000),
                                                     0x10,
                                                     "code");
  BlockGraph::Block* block2 = address_space.AddBlock(BlockGraph::CODE_BLOCK,
                                                     RelativeAddress(0x1010),
                                                     0x10,
                                                     "code");
  BlockGraph::Block* block3 = address_space.AddBlock(BlockGraph::CODE_BLOCK,
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

TEST(BlockGraphAddressSpaceTest, GetFirstIntersectingBlock) {
  BlockGraph image;
  BlockGraph::AddressSpace address_space(&image);

  BlockGraph::Block* block1 = address_space.AddBlock(BlockGraph::CODE_BLOCK,
                                                     RelativeAddress(0x1000),
                                                     0x10,
                                                     "code");
  BlockGraph::Block* block2 = address_space.AddBlock(BlockGraph::CODE_BLOCK,
                                                     RelativeAddress(0x1010),
                                                     0x10,
                                                     "code");
  BlockGraph::Block* block3 = address_space.AddBlock(BlockGraph::CODE_BLOCK,
                                                     RelativeAddress(0x1030),
                                                     0x10,
                                                     "code");

  EXPECT_EQ(NULL,
      address_space.GetFirstIntersectingBlock(RelativeAddress(0xFFF), 0x1));
  EXPECT_EQ(block1,
      address_space.GetFirstIntersectingBlock(RelativeAddress(0xFFF), 0x2));
  EXPECT_EQ(block1,
      address_space.GetFirstIntersectingBlock(RelativeAddress(0x100F), 0x1));
  EXPECT_EQ(block1,
      address_space.GetFirstIntersectingBlock(RelativeAddress(0x100F), 0x2));

  EXPECT_EQ(block2,
      address_space.GetFirstIntersectingBlock(RelativeAddress(0x1010), 0x40));
}

TEST(BlockGraphAddressSpaceTest, GetBlockAddress) {
  BlockGraph image;
  BlockGraph::AddressSpace address_space(&image);

  BlockGraph::Block* block1 = address_space.AddBlock(BlockGraph::CODE_BLOCK,
                                                     RelativeAddress(0x1000),
                                                     0x10,
                                                     "code");
  BlockGraph::Block* block2 = address_space.AddBlock(BlockGraph::CODE_BLOCK,
                                                     RelativeAddress(0x1010),
                                                     0x10,
                                                     "code");
  BlockGraph::Block* block3 =
      image.AddBlock(BlockGraph::CODE_BLOCK, 0x10, "code");

  RelativeAddress addr;
  EXPECT_TRUE(address_space.GetAddressOf(block1, &addr));
  EXPECT_EQ(0x1000, addr.value());

  EXPECT_TRUE(address_space.GetAddressOf(block2, &addr));
  EXPECT_EQ(0x1010, addr.value());

  EXPECT_FALSE(address_space.GetAddressOf(block3, &addr));
}

TEST(BlockGraphAddressSpaceTest, MergeIntersectingBlocks) {
  BlockGraph image;
  BlockGraph::AddressSpace address_space(&image);
  BlockGraph::Block* block1 = address_space.AddBlock(BlockGraph::CODE_BLOCK,
                                                     RelativeAddress(0x1000),
                                                     0x10,
                                                     "block1");
  BlockGraph::Block* block2 = address_space.AddBlock(BlockGraph::CODE_BLOCK,
                                                     RelativeAddress(0x1010),
                                                     0x10,
                                                     "block2");
  BlockGraph::Block* block3 = address_space.AddBlock(BlockGraph::CODE_BLOCK,
                                                     RelativeAddress(0x1030),
                                                     0x10,
                                                     "block3");
  ASSERT_TRUE(block2->SetLabel(0, "0x1010"));
  ASSERT_TRUE(block2->SetLabel(4, "0x1014"));
  ASSERT_TRUE(block3->SetLabel(0, "0x1030"));
  ASSERT_TRUE(block3->SetLabel(4, "0x1034"));

  ASSERT_TRUE(block1->SetReference(0x1,
      BlockGraph::Reference(BlockGraph::ABSOLUTE_REF, 4, block2, 0x0)));
  ASSERT_TRUE(block1->SetReference(0x6,
      BlockGraph::Reference(BlockGraph::ABSOLUTE_REF, 4, block3, 0x0)));
  ASSERT_TRUE(block2->SetReference(0x1,
      BlockGraph::Reference(BlockGraph::PC_RELATIVE_REF, 1, block1, 0x4)));
  ASSERT_TRUE(block2->SetReference(0x6,
      BlockGraph::Reference(BlockGraph::PC_RELATIVE_REF, 4, block3, 0x4)));
  ASSERT_TRUE(block3->SetReference(0x1,
      BlockGraph::Reference(BlockGraph::PC_RELATIVE_REF, 4, block2, 0x4)));

  BlockGraph::Block* merged = address_space.MergeIntersectingBlocks(
      BlockGraph::AddressSpace::Range(RelativeAddress(0x1014), 0x30));

  ASSERT_TRUE(merged != NULL);
  ASSERT_EQ(RelativeAddress(0x1010), merged->addr());
  ASSERT_EQ(0x34, merged->size());

  BlockGraph::Block::LabelMap expected_labels;
  expected_labels.insert(std::make_pair(0x00, "0x1010"));
  expected_labels.insert(std::make_pair(0x04, "0x1014"));
  expected_labels.insert(std::make_pair(0x20, "0x1030"));
  expected_labels.insert(std::make_pair(0x24, "0x1034"));
  EXPECT_THAT(merged->labels(), testing::ContainerEq(expected_labels));

  BlockGraph::Block::ReferenceMap expected_refs;
  expected_refs.insert(std::make_pair(0x1,
      BlockGraph::Reference(BlockGraph::PC_RELATIVE_REF, 1, block1, 0x4)));
  expected_refs.insert(std::make_pair(0x6,
      BlockGraph::Reference(BlockGraph::PC_RELATIVE_REF, 4, merged, 0x24)));
  expected_refs.insert(std::make_pair(0x21,
      BlockGraph::Reference(BlockGraph::PC_RELATIVE_REF, 4, merged, 0x4)));
  EXPECT_THAT(merged->references(), testing::ContainerEq(expected_refs));

  expected_refs.clear();
  expected_refs.insert(std::make_pair(0x1,
      BlockGraph::Reference(BlockGraph::ABSOLUTE_REF, 4, merged, 0x0)));
  expected_refs.insert(std::make_pair(0x6,
      BlockGraph::Reference(BlockGraph::ABSOLUTE_REF, 4, merged, 0x20)));
  EXPECT_THAT(block1->references(), testing::ContainerEq(expected_refs));

  // We expect that the block graph and the address space have the same size,
  // as MergeIntersectingBlocks deletes the old blocks from the BlockGraph.
  EXPECT_EQ(image.blocks().size(), address_space.address_space_impl().size());
}

TEST(BlockGraphTest, Serialization) {
  BlockGraph image;

  BlockGraph::Block* b1 = image.AddBlock(BlockGraph::CODE_BLOCK, 0x20, "b1");
  BlockGraph::Block* b2 = image.AddBlock(BlockGraph::CODE_BLOCK, 0x20, "b2");
  BlockGraph::Block* b3 = image.AddBlock(BlockGraph::CODE_BLOCK, 0x20, "b3");
  ASSERT_TRUE(b1 != NULL && b2 != NULL);

  uint8* b1_data = b1->AllocateData(b1->size());
  for (size_t i = 0; i < b1->size(); ++i) {
    b1_data[i] = 0;
  }

  ASSERT_TRUE(b1->references().empty());
  ASSERT_TRUE(b1->referrers().empty());
  ASSERT_TRUE(b2->references().empty());
  ASSERT_TRUE(b2->referrers().empty());
  ASSERT_TRUE(b3->references().empty());
  ASSERT_TRUE(b3->referrers().empty());

  BlockGraph::Reference r_pc(BlockGraph::PC_RELATIVE_REF, 1, b2, 9);
  ASSERT_TRUE(b1->SetReference(0, r_pc));
  ASSERT_TRUE(b1->SetReference(1, r_pc));

  BlockGraph::Reference r_abs(BlockGraph::ABSOLUTE_REF, 1, b2, 13);
  ASSERT_FALSE(b1->SetReference(1, r_abs));

  BlockGraph::Reference r_rel(BlockGraph::RELATIVE_REF, 1, b2, 17);
  ASSERT_TRUE(b1->SetReference(2, r_rel));

  BlockGraph::Reference r_file(BlockGraph::FILE_OFFSET_REF, 4, b2, 23);
  ASSERT_TRUE(b1->SetReference(4, r_file));

  ByteVector byte_vector;
  ScopedOutStreamPtr out_stream(
      CreateByteOutStream(std::back_inserter(byte_vector)));
  NativeBinaryOutArchive out_archive(out_stream.get());
  ASSERT_TRUE(out_archive.Save(image));

  BlockGraph image_copy;
  ScopedInStreamPtr in_stream(
      CreateByteInStream(byte_vector.begin(), byte_vector.end()));
  NativeBinaryInArchive in_archive(in_stream.get());
  ASSERT_TRUE(in_archive.Load(&image_copy));

  EXPECT_TRUE(testing::BlockGraphsEqual(image, image_copy));
}

}  // namespace core
