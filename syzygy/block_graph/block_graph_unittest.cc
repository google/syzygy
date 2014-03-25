// Copyright 2012 Google Inc. All Rights Reserved.
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

#include "syzygy/block_graph/block_graph.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/block_graph/typed_block.h"
#include "syzygy/block_graph/unittest_util.h"
#include "syzygy/core/unittest_util.h"

namespace block_graph {

using core::ByteVector;
using core::CreateByteInStream;
using core::CreateByteOutStream;
using core::NativeBinaryInArchive;
using core::NativeBinaryOutArchive;
using core::RelativeAddress;
using core::ScopedInStreamPtr;
using core::ScopedOutStreamPtr;

const size_t kPtrSize = sizeof(core::RelativeAddress);

TEST(SectionTest, CreationAndProperties) {
  BlockGraph::Section section(0, "foo", 1);
  ASSERT_EQ(0, section.id());
  ASSERT_EQ("foo", section.name());
  ASSERT_EQ(1u, section.characteristics());

  section.set_name("bar");
  ASSERT_EQ("bar", section.name());

  section.set_characteristic((1 << 5) | (1 << 6));
  ASSERT_EQ((1u | (1 << 5) | (1 << 6)), section.characteristics());

  section.clear_characteristic(1 | (1<<5));
  ASSERT_EQ(1u << 6, section.characteristics());

  section.set_characteristics(0);
  ASSERT_EQ(0u, section.characteristics());
}

TEST(SectionTest, Comparison) {
  BlockGraph::Section section0(0, "foo", 0);
  BlockGraph::Section section1(0, "foo", 0);
  BlockGraph::Section section2(1, "bar", 1);

  EXPECT_EQ(section0, section1);
  EXPECT_NE(section0, section2);
}

TEST(SectionTest, Serialization) {
  BlockGraph::Section section0(0, "foo", 0);
  EXPECT_TRUE(testing::TestSerialization(section0));
}

class BlockTest: public testing::Test {
 public:
  virtual void SetUp() {
    block_ = image_.AddBlock(kBlockType, kBlockSize, kBlockName);
    ASSERT_TRUE(block_ != NULL);
  }

 protected:
  static const BlockGraph::BlockType kBlockType = BlockGraph::CODE_BLOCK;
  static const size_t kBlockSize = 0x20;
  static const char* kBlockName;
  static const uint8 kTestData[];

  BlockGraph image_;
  BlockGraph::Block* block_;
};

const char* BlockTest::kBlockName = "block";
const uint8 BlockTest::kTestData[] = "who's your daddy?";

TEST(ReferenceTest, Initialization) {
  BlockGraph block_graph;
  BlockGraph::Block* block =
      block_graph.AddBlock(BlockGraph::CODE_BLOCK, 10, "foo");
  BlockGraph::Reference ref(BlockGraph::RELATIVE_REF, 4, block, 0, 0);
  ASSERT_EQ(BlockGraph::RELATIVE_REF, ref.type());
  ASSERT_EQ(4u, ref.size());
  ASSERT_EQ(block, ref.referenced());
  ASSERT_EQ(0, ref.offset());
  ASSERT_EQ(0, ref.base());
  ASSERT_TRUE(ref.IsValid());
  ASSERT_TRUE(ref.IsDirect());
}

TEST(ReferenceTest, IndirectReference) {
  BlockGraph block_graph;
  BlockGraph::Block* block =
      block_graph.AddBlock(BlockGraph::CODE_BLOCK, 10, "foo");
  BlockGraph::Reference ref(BlockGraph::RELATIVE_REF, 4, block, -8, 4);
  ASSERT_TRUE(ref.IsValid());
  ASSERT_FALSE(ref.IsDirect());
}

TEST(LabelTest, Initialization) {
  BlockGraph::Label label;
  ASSERT_TRUE(label.name().empty());
  ASSERT_EQ(0u, label.attributes());
}

TEST(LabelTest, InitializationFullConstructor) {
  BlockGraph::Label label("foo", BlockGraph::CODE_LABEL);
  ASSERT_EQ(std::string("foo"), label.name());
  ASSERT_EQ(BlockGraph::CODE_LABEL, label.attributes());
}

TEST(LabelTest, Attributes) {
  BlockGraph::Label label;
  ASSERT_EQ(0u, label.attributes());

  label.set_attribute(BlockGraph::CODE_LABEL);
  ASSERT_EQ(BlockGraph::CODE_LABEL, label.attributes());

  label.set_attribute(BlockGraph::JUMP_TABLE_LABEL);
  ASSERT_EQ(BlockGraph::CODE_LABEL | BlockGraph::JUMP_TABLE_LABEL,
            label.attributes());

  ASSERT_TRUE(label.has_attributes(
      BlockGraph::CODE_LABEL | BlockGraph::JUMP_TABLE_LABEL));
  ASSERT_TRUE(label.has_attributes(BlockGraph::CODE_LABEL));
  ASSERT_TRUE(label.has_attributes(BlockGraph::JUMP_TABLE_LABEL));
  ASSERT_FALSE(label.has_attributes(BlockGraph::DATA_LABEL));

  ASSERT_TRUE(label.has_any_attributes(
      BlockGraph::CODE_LABEL | BlockGraph::DATA_LABEL));

  label.set_attributes(BlockGraph::CASE_TABLE_LABEL);
  ASSERT_EQ(BlockGraph::CASE_TABLE_LABEL, label.attributes());

  label.clear_attribute(BlockGraph::CASE_TABLE_LABEL);
  ASSERT_EQ(0u, label.attributes());
}

TEST(LabelTest, IsValid) {
  BlockGraph::Label label;

  // A label must have some attributes.
  ASSERT_FALSE(label.IsValid());

  // A code label is fine on its own and also with debug and scope labels, but
  // not with anything else.
  label.set_attribute(BlockGraph::CODE_LABEL);
  ASSERT_TRUE(label.IsValid());
  label.set_attribute(BlockGraph::DEBUG_START_LABEL);
  ASSERT_TRUE(label.IsValid());
  label.set_attribute(BlockGraph::DEBUG_END_LABEL);
  ASSERT_TRUE(label.IsValid());
  label.set_attribute(BlockGraph::SCOPE_START_LABEL);
  ASSERT_TRUE(label.IsValid());
  label.set_attribute(BlockGraph::SCOPE_END_LABEL);
  ASSERT_TRUE(label.IsValid());
  label.set_attribute(BlockGraph::JUMP_TABLE_LABEL);
  ASSERT_FALSE(label.IsValid());

  // A jump table must be with a data label and nothing else.
  label.set_attributes(BlockGraph::JUMP_TABLE_LABEL);
  ASSERT_FALSE(label.IsValid());
  label.set_attribute(BlockGraph::DATA_LABEL);
  ASSERT_TRUE(label.IsValid());
  label.set_attribute(BlockGraph::CODE_LABEL);
  ASSERT_FALSE(label.IsValid());

  // A case table must be with a data label and nothing else.
  label.set_attributes(BlockGraph::CASE_TABLE_LABEL);
  ASSERT_FALSE(label.IsValid());
  label.set_attribute(BlockGraph::DATA_LABEL);
  ASSERT_TRUE(label.IsValid());
  label.set_attribute(BlockGraph::CODE_LABEL);
  ASSERT_FALSE(label.IsValid());

  // A data label with no case or jump table must be on its own.
  label.set_attributes(BlockGraph::DATA_LABEL);
  ASSERT_TRUE(label.IsValid());
  label.set_attribute(BlockGraph::CODE_LABEL);
  ASSERT_FALSE(label.IsValid());
}

TEST_F(BlockTest, Initialization) {
  // Test initialization.
  ASSERT_EQ(kBlockType, block_->type());
  ASSERT_EQ(kBlockSize, block_->size());
  ASSERT_EQ(1, block_->alignment());
  ASSERT_STREQ(kBlockName, block_->name().c_str());
  ASSERT_EQ(RelativeAddress::kInvalidAddress, block_->addr());
  ASSERT_EQ(BlockGraph::kInvalidSectionId, block_->section());
  ASSERT_EQ(0, block_->attributes());
  ASSERT_EQ(NULL, block_->data());
  ASSERT_EQ(0, block_->data_size());
  ASSERT_FALSE(block_->owns_data());
}

TEST_F(BlockTest, Accessors) {
  ASSERT_NE(BlockGraph::DATA_BLOCK, block_->type());
  block_->set_type(BlockGraph::DATA_BLOCK);
  ASSERT_EQ(BlockGraph::DATA_BLOCK, block_->type());

  ASSERT_NE(0x10U, block_->size());
  block_->set_size(0x10);
  ASSERT_EQ(0x10U, block_->size());

  ASSERT_STRNE("foo", block_->name().c_str());
  block_->set_name("foo");
  ASSERT_STREQ("foo", block_->name().c_str());

  ASSERT_STRNE("foo.o", block_->compiland_name().c_str());
  block_->set_compiland_name("foo.o");
  ASSERT_STREQ("foo.o", block_->compiland_name().c_str());

  ASSERT_NE(16U, block_->alignment());
  block_->set_alignment(16);
  ASSERT_EQ(16U, block_->alignment());

  // Test accessors.
  block_->set_attribute(0x20);
  ASSERT_EQ(0x20, block_->attributes());
  block_->set_attribute(0x10);
  ASSERT_EQ(0x30, block_->attributes());
  block_->clear_attribute(0x20);
  ASSERT_EQ(0x10, block_->attributes());

  block_->set_size(sizeof(kTestData));
  block_->SetData(kTestData, sizeof(kTestData));
  ASSERT_EQ(kTestData, block_->data());
  ASSERT_EQ(sizeof(kTestData), block_->data_size());
  ASSERT_FALSE(block_->owns_data());
}

TEST_F(BlockTest, AllocateData) {
  // Test AllocateData.
  uint8* data = block_->AllocateData(block_->size());
  ASSERT_TRUE(block_->owns_data());
  ASSERT_EQ(block_->size(), block_->data_size());
  ASSERT_EQ(data, block_->data());

  static const uint8 zeros[kBlockSize] = {};
  ASSERT_EQ(0, memcmp(&zeros[0], data, block_->size()));
}

TEST_F(BlockTest, CopyData) {
  // Test CopyData.
  uint8* data = block_->CopyData(sizeof(kTestData), kTestData);
  ASSERT_TRUE(block_->owns_data());
  ASSERT_EQ(sizeof(kTestData), block_->data_size());
  ASSERT_EQ(data, block_->data());
  ASSERT_EQ(0, memcmp(kTestData, data, block_->data_size()));
}

TEST_F(BlockTest, ResizeData) {
  // Set the block's data.
  block_->SetData(kTestData, sizeof(kTestData));

  // Shrinking the data should not take ownership.
  const uint8* data = block_->ResizeData(sizeof(kTestData) / 2);
  ASSERT_TRUE(data != NULL);
  ASSERT_TRUE(data == kTestData);
  ASSERT_FALSE(block_->owns_data());

  // Growing the data must always take ownership.
  data = block_->ResizeData(sizeof(kTestData));
  ASSERT_TRUE(data != NULL);
  ASSERT_TRUE(data != kTestData);
  ASSERT_TRUE(block_->owns_data());
  // The head of the data should be identical to the input.
  ASSERT_EQ(0, memcmp(data, kTestData, sizeof(kTestData) / 2));
  // And the tail should be zeros.
  static const uint8 kZeros[sizeof(kTestData) - sizeof(kTestData) / 2] = {};
  ASSERT_EQ(0, memcmp(data + sizeof(kTestData) / 2, kZeros, sizeof(kZeros)));

  // Now grow it from non-owned.
  block_->SetData(kTestData, sizeof(kTestData));
  data = block_->ResizeData(sizeof(kTestData) + sizeof(kZeros));
  ASSERT_TRUE(data != NULL);
  ASSERT_TRUE(data != kTestData);
  ASSERT_TRUE(block_->owns_data());

  // The head of the data should be identical to the input.
  ASSERT_EQ(0, memcmp(data, kTestData, sizeof(kTestData)));
  // And the tail should be zeros.
  ASSERT_EQ(0, memcmp(data + sizeof(kTestData), kZeros, sizeof(kZeros)));
}

TEST_F(BlockTest, GetMutableData) {
  // Set the block's data.
  block_->SetData(kTestData, sizeof(kTestData));

  // Getting a mutable pointer should copy the data to heap.
  uint8* data = block_->GetMutableData();
  ASSERT_TRUE(data != NULL);
  ASSERT_TRUE(data != kTestData);
  ASSERT_TRUE(block_->owns_data());
  ASSERT_EQ(sizeof(kTestData), block_->data_size());
  ASSERT_EQ(data, block_->data());
  ASSERT_EQ(0, memcmp(kTestData, data, block_->data_size()));

  // Getting the data a second time should return the same pointer.
  ASSERT_EQ(data, block_->GetMutableData());
}

TEST_F(BlockTest, InsertData) {
  // Create a block with a labelled array of pointers. Explicitly initialize
  // the last one with some data and let the block be longer than its
  // explicitly initialized length.
  BlockGraph::Block* block1 = image_.AddBlock(
      BlockGraph::CODE_BLOCK, 4 * kPtrSize, "Block1");
  block1->AllocateData(3 * kPtrSize);
  block1->source_ranges().Push(BlockGraph::Block::DataRange(0, 4 * kPtrSize),
                               BlockGraph::Block::SourceRange(
                               core::RelativeAddress(0), 4 * kPtrSize));
  BlockGraph::Reference outgoing_ref(BlockGraph::RELATIVE_REF,
                                     kPtrSize,
                                     block_,
                                     0, 0);
  block1->SetReference(0, outgoing_ref);
  block1->SetReference(kPtrSize, outgoing_ref);
  block1->SetLabel(0, "Pointer1", BlockGraph::DATA_LABEL);
  block1->SetLabel(kPtrSize, "Pointer2", BlockGraph::DATA_LABEL);
  block1->SetLabel(2 * kPtrSize, "Pointer3", BlockGraph::DATA_LABEL);
  TypedBlock<uint32> data1;
  ASSERT_TRUE(data1.Init(0, block1));
  data1[0] = 0xAAAAAAAA;
  data1[1] = 0xBBBBBBBB;
  data1[2] = 0xCCCCCCCC;

  // Create a block with a pointer to the first entry of block1.
  BlockGraph::Block* block2 = image_.AddBlock(
      BlockGraph::CODE_BLOCK, kPtrSize, "Block2");
  block2->SetReference(0, BlockGraph::Reference(BlockGraph::RELATIVE_REF,
                                                kPtrSize,
                                                block1,
                                                0, 0));

  // Create a block with a pointer to the second entry of block1.
  BlockGraph::Block* block3 = image_.AddBlock(
      BlockGraph::CODE_BLOCK, kPtrSize, "Block3");
  block3->SetReference(0, BlockGraph::Reference(BlockGraph::RELATIVE_REF,
                                                kPtrSize,
                                                block1,
                                                kPtrSize, kPtrSize));

  // Insert a new pointer entry in between the first and second entries.
  block1->InsertData(kPtrSize, kPtrSize, false);

  // Ensure the data_size and block size are as expected.
  EXPECT_EQ(5 * kPtrSize, block1->size());
  EXPECT_EQ(4 * kPtrSize, block1->data_size());

  // Ensure the source ranges are as expected.
  BlockGraph::Block::SourceRanges expected_src_ranges;
  expected_src_ranges.Push(
      BlockGraph::Block::DataRange(0, kPtrSize),
      BlockGraph::Block::SourceRange(core::RelativeAddress(0), kPtrSize));
  expected_src_ranges.Push(
      BlockGraph::Block::DataRange(2 * kPtrSize, 3 * kPtrSize),
      BlockGraph::Block::SourceRange(core::RelativeAddress(kPtrSize),
                                     3 * kPtrSize));
  EXPECT_THAT(expected_src_ranges.range_pairs(),
              testing::ContainerEq(block1->source_ranges().range_pairs()));

  // Ensure that the contents of the block's data are as expected.
  EXPECT_EQ(0xAAAAAAAAu, data1[0]);
  EXPECT_EQ(0x00000000u, data1[1]);
  EXPECT_EQ(0xBBBBBBBBu, data1[2]);
  EXPECT_EQ(0xCCCCCCCCu, data1[3]);

  // Ensure that the labels have been shifted appropriately.
  BlockGraph::Block::LabelMap expected_labels;
  expected_labels.insert(std::make_pair(
      0 * kPtrSize,
      BlockGraph::Label("Pointer1", BlockGraph::DATA_LABEL)));
  expected_labels.insert(std::make_pair(
      2 * kPtrSize,
      BlockGraph::Label("Pointer2", BlockGraph::DATA_LABEL)));
  expected_labels.insert(std::make_pair(
      3 * kPtrSize,
      BlockGraph::Label("Pointer3", BlockGraph::DATA_LABEL)));
  EXPECT_THAT(expected_labels, testing::ContainerEq(block1->labels()));

  // Ensure that the referrers are as expected.
  BlockGraph::Block::ReferrerSet expected_referrers;
  expected_referrers.insert(std::make_pair(block2, 0));
  expected_referrers.insert(std::make_pair(block3, 0));
  EXPECT_THAT(expected_referrers, testing::ContainerEq(block1->referrers()));

  BlockGraph::Reference expected_ref(BlockGraph::RELATIVE_REF,
                                     kPtrSize,
                                     block1,
                                     0, 0);
  BlockGraph::Reference actual_ref;
  EXPECT_TRUE(block2->GetReference(0, &actual_ref));
  EXPECT_EQ(expected_ref, actual_ref);

  expected_ref = BlockGraph::Reference(BlockGraph::RELATIVE_REF,
                                       kPtrSize,
                                       block1,
                                       2 * kPtrSize, 2 * kPtrSize);
  EXPECT_TRUE(block3->GetReference(0, &actual_ref));
  EXPECT_EQ(expected_ref, actual_ref);

  // Ensure that the references have been shifted appropriately.
  BlockGraph::Block::ReferenceMap expected_references;
  expected_references.insert(std::make_pair(0, outgoing_ref));
  expected_references.insert(std::make_pair(2 * kPtrSize, outgoing_ref));
  EXPECT_EQ(expected_references, block1->references());
}

TEST_F(BlockTest, InsertDataAtEndOfBlock) {
  // Create a block.
  BlockGraph::Block* block1 = image_.AddBlock(
      BlockGraph::CODE_BLOCK, 4 * kPtrSize, "Block1");
  block1->AllocateData(3 * kPtrSize);
  EXPECT_EQ(4 * kPtrSize, block1->size());

  // Create a block with a pointer to the end of block1.
  BlockGraph::Block* block2 = image_.AddBlock(
      BlockGraph::CODE_BLOCK, kPtrSize, "Block2");
  block2->SetReference(0, BlockGraph::Reference(BlockGraph::RELATIVE_REF,
                                                kPtrSize,
                                                block1,
                                                block1->size(),
                                                block1->size()));

  // Shift block1 in the middle.
  block1->InsertData(kPtrSize, kPtrSize, false);

  // Ensure the data_size and block size are as expected.
  EXPECT_EQ(5 * kPtrSize, block1->size());
  EXPECT_EQ(4 * kPtrSize, block1->data_size());

  // Ensure that the end reference has moved along.
  BlockGraph::Reference expected_ref(BlockGraph::RELATIVE_REF,
                                     kPtrSize,
                                     block1,
                                     block1->size(),
                                     block1->size());

  BlockGraph::Reference actual_ref;
  EXPECT_TRUE(block2->GetReference(0, &actual_ref));
  EXPECT_EQ(expected_ref, actual_ref);

  // Shift block1 at the end.
  block1->InsertData(block1->size(), kPtrSize, false);

  // Ensure the data_size and block size are as expected.
  EXPECT_EQ(6 * kPtrSize, block1->size());
  EXPECT_EQ(4 * kPtrSize, block1->data_size());

  // Ensure that the end reference has moved along.
  expected_ref = BlockGraph::Reference(BlockGraph::RELATIVE_REF,
                                       kPtrSize,
                                       block1,
                                       block1->size(),
                                       block1->size());

  EXPECT_TRUE(block2->GetReference(0, &actual_ref));
  EXPECT_EQ(expected_ref, actual_ref);
}

TEST_F(BlockTest, InsertDataImplicit) {
  BlockGraph::Block* block1 = image_.AddBlock(
      BlockGraph::CODE_BLOCK, 40, "Block1");
  block1->AllocateData(30);

  // Do an insert data in the implicitly initialized portion of the block.
  block1->InsertData(30, 10, false);

  // We expect the block to have grown, but the data size should still be the
  // same.
  EXPECT_EQ(50u, block1->size());
  EXPECT_EQ(30u, block1->data_size());
}

TEST_F(BlockTest, InsertDataImplicitForceAllocation) {
  BlockGraph::Block* block1 = image_.AddBlock(
      BlockGraph::CODE_BLOCK, 40, "Block1");
  block1->AllocateData(30);

  // Do an insert data in the implicitly initialized portion of the block, but
  // force data to be allocated.
  block1->InsertData(30, 10, true);

  // We expect the block to have grown, as well as the data size.
  EXPECT_EQ(50u, block1->size());
  EXPECT_EQ(40u, block1->data_size());
}

TEST_F(BlockTest, InsertDataForceAllocateDoesNotShorten) {
  BlockGraph::Block* block1 = image_.AddBlock(
      BlockGraph::CODE_BLOCK, 40, "Block1");
  block1->AllocateData(30);

  // Insert data in the allocated region, but request allocation to be forced.
  block1->InsertData(0, 10, true);

  EXPECT_EQ(50u, block1->size());
  EXPECT_EQ(40u, block1->data_size());
}

TEST_F(BlockTest, InsertDataWithSelfReference) {
  BlockGraph::Block* block1 = image_.AddBlock(
      BlockGraph::CODE_BLOCK, 40, "Block1");

  BlockGraph::Reference ref(BlockGraph::ABSOLUTE_REF, kPtrSize, block1, 0, 0);
  // Insert a self-reference to the block.
  block1->SetReference(20, ref);

  // Insert some data before the reference.
  block1->InsertData(10, 10, false);

  BlockGraph::Reference moved_ref;
  ASSERT_TRUE(block1->GetReference(30, &moved_ref));
  ASSERT_EQ(ref, moved_ref);

  BlockGraph::Block::ReferrerSet expected;
  expected.insert(std::make_pair(block1, 30));
  ASSERT_EQ(block1->referrers(), expected);
}

TEST_F(BlockTest, RemoveData) {
  // Create a block with a labelled array of pointers. Explicitly initialize
  // the last one with some data and let the block be longer than its
  // explicitly initialized length.
  BlockGraph::Block* block1 = image_.AddBlock(
      BlockGraph::CODE_BLOCK, 6 * kPtrSize, "Block1");
  block1->AllocateData(3 * kPtrSize);
  block1->source_ranges().Push(BlockGraph::Block::DataRange(0, 6 * kPtrSize),
                               BlockGraph::Block::SourceRange(
                                   core::RelativeAddress(0), 6 * kPtrSize));
  BlockGraph::Reference outgoing_ref(BlockGraph::RELATIVE_REF,
                                     kPtrSize,
                                     block_,
                                     0, 0);
  block1->SetReference(0, outgoing_ref);
  block1->SetReference(2 * kPtrSize, outgoing_ref);
  block1->SetReference(5 * kPtrSize, outgoing_ref);
  block1->SetLabel(0, "Pointer1", BlockGraph::DATA_LABEL);
  block1->SetLabel(2 * kPtrSize, "Pointer3", BlockGraph::DATA_LABEL);
  block1->SetLabel(3 * kPtrSize, "EndOfPointers", BlockGraph::DATA_LABEL);
  TypedBlock<uint32> data1;
  ASSERT_TRUE(data1.Init(0, block1));
  data1[0] = 0xAAAAAAAA;
  data1[1] = 0xBBBBBBBB;
  data1[2] = 0xCCCCCCCC;

  // Create a block with a pointer to the first entry of block1.
  BlockGraph::Block* block2 = image_.AddBlock(
      BlockGraph::CODE_BLOCK, kPtrSize, "Block2");
  block2->SetReference(0, BlockGraph::Reference(BlockGraph::RELATIVE_REF,
                                                kPtrSize,
                                                block1,
                                                0, 0));

  // Create a block with a pointer to the third entry of block1.
  BlockGraph::Block* block3 = image_.AddBlock(
      BlockGraph::CODE_BLOCK, kPtrSize, "Block4");
  block3->SetReference(0, BlockGraph::Reference(BlockGraph::RELATIVE_REF,
                                                kPtrSize,
                                                block1,
                                                2 * kPtrSize, 2 * kPtrSize));

  // Create a block with a pointer to the fifth entry of block1.
  BlockGraph::Block* block4 = image_.AddBlock(
      BlockGraph::CODE_BLOCK, kPtrSize, "Block3");
  block4->SetReference(0, BlockGraph::Reference(BlockGraph::RELATIVE_REF,
                                                kPtrSize,
                                                block1,
                                                4 * kPtrSize, 4 * kPtrSize));

  // Trying to remove the fourth entry should fail because it contains a label.
  EXPECT_FALSE(block1->RemoveData(3 * kPtrSize, kPtrSize));

  // Trying to remove the fifth entry should fail because there is a referrer
  // pointing to it.
  EXPECT_FALSE(block1->RemoveData(4 * kPtrSize, kPtrSize));

  // Trying to remove the sixth entry should fail because it contains a
  // reference.
  EXPECT_FALSE(block1->RemoveData(5 * kPtrSize, kPtrSize));

  // Finally, we should be able to delete the second entry.
  EXPECT_TRUE(block1->RemoveData(kPtrSize, kPtrSize));

  // Ensure the data_size and block size are as expected.
  EXPECT_EQ(5 * kPtrSize, block1->size());
  EXPECT_EQ(2 * kPtrSize, block1->data_size());

  // Ensure the source ranges are as expected.
  BlockGraph::Block::SourceRanges expected_src_ranges;
  expected_src_ranges.Push(
      BlockGraph::Block::DataRange(0, kPtrSize),
      BlockGraph::Block::SourceRange(core::RelativeAddress(0), kPtrSize));
  expected_src_ranges.Push(
      BlockGraph::Block::DataRange(kPtrSize, 4 * kPtrSize),
      BlockGraph::Block::SourceRange(core::RelativeAddress(2 * kPtrSize),
                                     4 * kPtrSize));
  EXPECT_THAT(expected_src_ranges.range_pairs(),
              testing::ContainerEq(block1->source_ranges().range_pairs()));

  // Ensure that the contents of the block's data are as expected.
  EXPECT_EQ(0xAAAAAAAAu, data1[0]);
  EXPECT_EQ(0xCCCCCCCCu, data1[1]);

  // Ensure that the labels have been shifted appropriately.
  BlockGraph::Block::LabelMap expected_labels;
  expected_labels.insert(std::make_pair(
      0 * kPtrSize,
      BlockGraph::Label("Pointer1", BlockGraph::DATA_LABEL)));
  expected_labels.insert(std::make_pair(
      1 * kPtrSize,
      BlockGraph::Label("Pointer3", BlockGraph::DATA_LABEL)));
  expected_labels.insert(std::make_pair(
      2 * kPtrSize,
      BlockGraph::Label("EndOfPointers", BlockGraph::DATA_LABEL)));
  EXPECT_THAT(expected_labels, testing::ContainerEq(block1->labels()));

  // Ensure that the referrers are as expected.
  BlockGraph::Block::ReferrerSet expected_referrers;
  expected_referrers.insert(std::make_pair(block2, 0));
  expected_referrers.insert(std::make_pair(block3, 0));
  expected_referrers.insert(std::make_pair(block4, 0));
  EXPECT_THAT(expected_referrers, testing::ContainerEq(block1->referrers()));

  BlockGraph::Reference expected_ref(BlockGraph::RELATIVE_REF,
                                     kPtrSize,
                                     block1,
                                     0, 0);
  BlockGraph::Reference actual_ref;
  EXPECT_TRUE(block2->GetReference(0, &actual_ref));
  EXPECT_EQ(expected_ref, actual_ref);

  expected_ref = BlockGraph::Reference(BlockGraph::RELATIVE_REF,
                                       kPtrSize,
                                       block1,
                                       kPtrSize, kPtrSize);
  EXPECT_TRUE(block3->GetReference(0, &actual_ref));
  EXPECT_EQ(expected_ref, actual_ref);

  expected_ref = BlockGraph::Reference(BlockGraph::RELATIVE_REF,
                                       kPtrSize,
                                       block1,
                                       3 * kPtrSize, 3 * kPtrSize);
  EXPECT_TRUE(block4->GetReference(0, &actual_ref));
  EXPECT_EQ(expected_ref, actual_ref);

  // Ensure that the references have been shifted appropriately.
  BlockGraph::Block::ReferenceMap expected_references;
  expected_references.insert(std::make_pair(0, outgoing_ref));
  expected_references.insert(std::make_pair(kPtrSize, outgoing_ref));
  expected_references.insert(std::make_pair(4 * kPtrSize, outgoing_ref));
  EXPECT_EQ(expected_references, block1->references());
}

TEST_F(BlockTest, RemoveDataPartlyImplicit) {
  BlockGraph::Block* block1 = image_.AddBlock(
      BlockGraph::CODE_BLOCK, 40, "Block1");
  block1->AllocateData(30);

  // Remove data that spans both the initialized and implicit parts of the
  // block.
  EXPECT_TRUE(block1->RemoveData(25, 10));

  // We expect both the block and the data size to have shrunk.
  EXPECT_EQ(30u, block1->size());
  EXPECT_EQ(25u, block1->data_size());
}

TEST_F(BlockTest, RemoveDataImplicit) {
  BlockGraph::Block* block1 = image_.AddBlock(
      BlockGraph::CODE_BLOCK, 40, "Block1");
  block1->AllocateData(30);

  // Do an remove data in the implicitly initialized portion of the block.
  EXPECT_TRUE(block1->RemoveData(30, 5));

  // We expect the block to have shrunk, but the data size should still be the
  // same.
  EXPECT_EQ(35u, block1->size());
  EXPECT_EQ(30u, block1->data_size());
}

TEST_F(BlockTest, RemoveDataWithSelfReference) {
  BlockGraph::Block* block1 = image_.AddBlock(
      BlockGraph::CODE_BLOCK, 50, "Block1");

  BlockGraph::Reference ref(BlockGraph::ABSOLUTE_REF, kPtrSize, block1, 0, 0);
  // Insert a self-reference to the block.
  block1->SetReference(40, ref);

  // Remove some data before the reference.
  block1->RemoveData(10, 10);

  BlockGraph::Reference moved_ref;
  ASSERT_TRUE(block1->GetReference(30, &moved_ref));
  ASSERT_EQ(ref, moved_ref);

  BlockGraph::Block::ReferrerSet expected;
  expected.insert(std::make_pair(block1, 30));
  ASSERT_EQ(block1->referrers(), expected);
}

TEST_F(BlockTest, InsertOrRemoveDataSameSizeNoAllocate) {
  BlockGraph::Block* block1 = image_.AddBlock(
      BlockGraph::DATA_BLOCK, 40, "Block1");

  EXPECT_TRUE(block1->InsertOrRemoveData(0, 20, 20, false));
  EXPECT_EQ(40u, block1->size());
  EXPECT_EQ(0u, block1->data_size());
}

TEST_F(BlockTest, InsertOrRemoveDataSameSizeAllocate) {
  BlockGraph::Block* block1 = image_.AddBlock(
      BlockGraph::DATA_BLOCK, 40, "Block1");

  EXPECT_TRUE(block1->InsertOrRemoveData(0, 20, 20, true));
  EXPECT_EQ(40u, block1->size());
  EXPECT_EQ(20u, block1->data_size());
}

TEST_F(BlockTest, InsertOrRemoveGrowNoAllocate) {
  BlockGraph::Block* block1 = image_.AddBlock(
      BlockGraph::DATA_BLOCK, 40, "Block1");

  EXPECT_TRUE(block1->InsertOrRemoveData(0, 10, 20, false));
  EXPECT_EQ(50u, block1->size());
  EXPECT_EQ(0u, block1->data_size());
}

TEST_F(BlockTest, InsertOrRemoveGrowAllocate) {
  BlockGraph::Block* block1 = image_.AddBlock(
      BlockGraph::DATA_BLOCK, 40, "Block1");

  EXPECT_TRUE(block1->InsertOrRemoveData(0, 10, 20, true));
  EXPECT_EQ(50u, block1->size());
  EXPECT_EQ(20u, block1->data_size());
}

TEST_F(BlockTest, InsertOrRemoveShrinkNoAllocate) {
  BlockGraph::Block* block1 = image_.AddBlock(
      BlockGraph::DATA_BLOCK, 40, "Block1");
  block1->AllocateData(15);

  EXPECT_TRUE(block1->InsertOrRemoveData(0, 20, 10, false));
  EXPECT_EQ(30u, block1->size());
  EXPECT_EQ(10u, block1->data_size());
}

TEST_F(BlockTest, InsertOrRemoveShrinkAllocate) {
  BlockGraph::Block* block1 = image_.AddBlock(
      BlockGraph::DATA_BLOCK, 40, "Block1");

  EXPECT_TRUE(block1->InsertOrRemoveData(0, 20, 10, true));
  EXPECT_EQ(30u, block1->size());
  EXPECT_EQ(10u, block1->data_size());
}

TEST_F(BlockTest, HasExternalReferrers) {
  // Create block1 that refers to itself. It has no external referrers.
  BlockGraph::Block* block1 = image_.AddBlock(
      BlockGraph::DATA_BLOCK, 40, "Block1");
  ASSERT_TRUE(block1 != NULL);
  EXPECT_TRUE(block1->SetReference(
      0, BlockGraph::Reference(BlockGraph::ABSOLUTE_REF, 4, block1, 0, 0)));
  EXPECT_FALSE(block1->HasExternalReferrers());

  // Create a second block that refers to block1.
  BlockGraph::Block* block2 = image_.AddBlock(
      BlockGraph::DATA_BLOCK, 40, "Block2");
  ASSERT_TRUE(block2 != NULL);
  EXPECT_TRUE(block2->SetReference(
      0, BlockGraph::Reference(BlockGraph::ABSOLUTE_REF, 4, block1, 0, 0)));

  // There should now be an external referrer to block1.
  EXPECT_TRUE(block1->HasExternalReferrers());
}

TEST_F(BlockTest, RemoveAllReferences) {
  // Create block1 that refers to itself. It has no external referrers.
  BlockGraph::Block* block1 = image_.AddBlock(
      BlockGraph::DATA_BLOCK, 40, "Block1");
  ASSERT_TRUE(block1 != NULL);
  EXPECT_TRUE(block1->SetReference(
      0, BlockGraph::Reference(BlockGraph::ABSOLUTE_REF, 4, block1, 0, 0)));

  // Create a second block for block1 to refer to.
  BlockGraph::Block* block2 = image_.AddBlock(
      BlockGraph::DATA_BLOCK, 40, "Block2");
  ASSERT_TRUE(block2 != NULL);
  EXPECT_TRUE(block1->SetReference(
      4, BlockGraph::Reference(BlockGraph::ABSOLUTE_REF, 4, block2, 0, 0)));

  // Verify that the references are as expected.
  EXPECT_EQ(2U, block1->references().size());
  EXPECT_EQ(1U, block1->referrers().size());
  EXPECT_EQ(1U, block2->referrers().size());

  // Remove all references from block1.
  EXPECT_TRUE(block1->RemoveAllReferences());

  // Verify that the references are as expected.
  EXPECT_EQ(0U, block1->references().size());
  EXPECT_EQ(0U, block1->referrers().size());
  EXPECT_EQ(0U, block2->referrers().size());
}

TEST(BlockGraphTest, BlockTypeToString) {
  for (int type = 0; type < BlockGraph::BLOCK_TYPE_MAX; ++type) {
    BlockGraph::BlockType block_type =
        static_cast<BlockGraph::BlockType>(type);
    EXPECT_TRUE(BlockGraph::BlockTypeToString(block_type) != NULL);
  }
}

TEST(BlockGraphTest, LabelAttributesToString) {
  BlockGraph::LabelAttributes label_attr = 1;
  for (; label_attr != BlockGraph::LABEL_ATTRIBUTES_MAX; label_attr <<= 1) {
    std::string s = BlockGraph::LabelAttributesToString(label_attr);
    EXPECT_FALSE(s.empty());
  }

  label_attr = BlockGraph::LABEL_ATTRIBUTES_MAX - 1;
  std::string s = BlockGraph::LabelAttributesToString(label_attr);
  EXPECT_FALSE(s.empty());
}

TEST(BlockGraphTest, AddSections) {
  BlockGraph image;
  ASSERT_EQ(0u, image.sections().size());

  BlockGraph::Section* section0 = image.AddSection("foo", 0);
  ASSERT_TRUE(section0 != NULL);
  ASSERT_EQ("foo", section0->name());
  ASSERT_EQ(0u, section0->characteristics());
  ASSERT_EQ(1u, image.sections().size());

  BlockGraph::Section* section1 = image.AddSection("foo", 0);
  ASSERT_TRUE(section1 != NULL);
  ASSERT_EQ("foo", section1->name());
  ASSERT_EQ(0u, section1->characteristics());
  ASSERT_EQ(2u, image.sections().size());

  // This section has the same name and characteristics, but it should not be
  // the same section as section0.
  EXPECT_TRUE(section0 != section1);
  EXPECT_NE(section0->id(), section1->id());

  BlockGraph::Section* section2 = image.FindOrAddSection("foo", 1);
  ASSERT_TRUE(section2 != NULL);
  ASSERT_EQ("foo", section2->name());
  ASSERT_EQ(1u, section2->characteristics());
  ASSERT_EQ(2u, image.sections().size());

  // This should be the same as section0, the first instance of a section
  // with name 'foo'.
  EXPECT_EQ(section0, section2);

  BlockGraph::Section* section3 = image.FindOrAddSection("bar", 1);
  ASSERT_TRUE(section3 != NULL);
  ASSERT_EQ("bar", section3->name());
  ASSERT_EQ(1u, section3->characteristics());
  ASSERT_EQ(3u, image.sections().size());

  // Test out FindSection.
  EXPECT_EQ(section0, image.FindSection("foo"));
  EXPECT_EQ(section3, image.FindSection("bar"));
  EXPECT_TRUE(image.FindSection("baz") == NULL);
}

TEST(BlockGraphTest, RemoveSection) {
  BlockGraph image;
  ASSERT_EQ(0u, image.sections().size());

  BlockGraph::Section* section0 = image.AddSection("foo", 0);
  ASSERT_TRUE(section0 != NULL);
  ASSERT_EQ(1u, image.sections().size());

  BlockGraph::Section* section1 = image.AddSection("bar", 0);
  ASSERT_TRUE(section1 != NULL);
  ASSERT_EQ(2u, image.sections().size());

  // We should not be able to delete a non-existent section.
  EXPECT_FALSE(image.RemoveSectionById(BlockGraph::kInvalidSectionId));
  ASSERT_EQ(2u, image.sections().size());

  // Deleting normal sections should work just fine.

  EXPECT_TRUE(image.RemoveSectionById(section0->id()));
  ASSERT_EQ(1u, image.sections().size());

  EXPECT_TRUE(image.RemoveSection(section1));
  ASSERT_EQ(0u, image.sections().size());
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
  BlockGraph::Reference ref12(BlockGraph::PC_RELATIVE_REF, 1, b2, 9, 9);
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

  BlockGraph::Reference dummy;
  ASSERT_FALSE(dummy.IsValid());

  // Add the first reference, and test that we get a backref.
  BlockGraph::Reference r_pc(BlockGraph::PC_RELATIVE_REF, 1, b2, 9, 9);
  ASSERT_TRUE(r_pc.IsValid());
  ASSERT_EQ(BlockGraph::PC_RELATIVE_REF, r_pc.type());
  ASSERT_EQ(1, r_pc.size());
  ASSERT_EQ(b2, r_pc.referenced());
  ASSERT_EQ(9, r_pc.offset());

  ASSERT_TRUE(b1->SetReference(0, r_pc));
  EXPECT_THAT(b2->referrers(), testing::Contains(std::make_pair(b1, 0)));

  ASSERT_TRUE(b1->SetReference(1, r_pc));
  EXPECT_THAT(b2->referrers(), testing::Contains(std::make_pair(b1, 1)));

  BlockGraph::Reference r_abs(BlockGraph::ABSOLUTE_REF, 4, b2, 13, 13);
  ASSERT_FALSE(b1->SetReference(1, r_abs));
  BlockGraph::Reference r_rel(BlockGraph::RELATIVE_REF, 4, b2, 17, 17);
  ASSERT_TRUE(b1->SetReference(5, r_rel));
  BlockGraph::Reference r_file(BlockGraph::FILE_OFFSET_REF, 4, b2, 23, 23);
  ASSERT_TRUE(b1->SetReference(9, r_file));

  BlockGraph::Reference r_sect(BlockGraph::SECTION_REF, 2, b2, 0, 0);
  ASSERT_TRUE(b1->SetReference(13, r_sect));
  BlockGraph::Reference r_sect_off(BlockGraph::SECTION_OFFSET_REF, 4,
                                   b2, 27, 27);
  ASSERT_TRUE(b1->SetReference(15, r_sect_off));

  // Test that the reference map is as expected.
  BlockGraph::Block::ReferenceMap expected;
  expected.insert(std::make_pair(0, r_pc));
  expected.insert(std::make_pair(1, r_abs));
  expected.insert(std::make_pair(5, r_rel));
  expected.insert(std::make_pair(9, r_file));
  expected.insert(std::make_pair(13, r_sect));
  expected.insert(std::make_pair(15, r_sect_off));
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
  ASSERT_FALSE(b2->TransferReferrers(b3->size(),
      b3, BlockGraph::Block::kTransferInternalReferences));
  logging::SetMinLogLevel(old_level);

  // Now move the references from b2 to b3
  ASSERT_TRUE(b2->TransferReferrers(0,
      b3, BlockGraph::Block::kTransferInternalReferences));
  // Test that b2 no longer has referrers.
  EXPECT_THAT(b2->referrers(), BlockGraph::Block::ReferrerSet());

  // Test that the references transferred as expected.
  expected.clear();
  expected.insert(std::make_pair(0,
      BlockGraph::Reference(BlockGraph::PC_RELATIVE_REF, 1, b3, 9, 9)));
  expected.insert(std::make_pair(1,
      BlockGraph::Reference(BlockGraph::ABSOLUTE_REF, 4, b3, 13, 13)));
  expected.insert(std::make_pair(5,
      BlockGraph::Reference(BlockGraph::RELATIVE_REF, 4, b3, 17, 17)));
  expected.insert(std::make_pair(9,
      BlockGraph::Reference(BlockGraph::FILE_OFFSET_REF, 4, b3, 23, 23)));
  expected.insert(std::make_pair(13,
      BlockGraph::Reference(BlockGraph::SECTION_REF, 2, b3, 0, 0)));
  expected.insert(std::make_pair(15,
      BlockGraph::Reference(BlockGraph::SECTION_OFFSET_REF, 4, b3, 27, 27)));
  EXPECT_THAT(b1->references(), testing::ContainerEq(expected));

  // Remove the references.
  ASSERT_TRUE(b1->RemoveReference(0));
  ASSERT_TRUE(b1->RemoveReference(1));
  ASSERT_TRUE(b1->RemoveReference(5));
  ASSERT_TRUE(b1->RemoveReference(9));
  ASSERT_TRUE(b1->RemoveReference(13));
  ASSERT_TRUE(b1->RemoveReference(15));
  EXPECT_THAT(b1->references(), BlockGraph::Block::ReferenceMap());

  EXPECT_THAT(b2->referrers(), BlockGraph::Block::ReferrerSet());
}

TEST(BlockGraphTest, Labels) {
  BlockGraph image;

  BlockGraph::Block* block =
      image.AddBlock(BlockGraph::CODE_BLOCK, 0x20, "labeled");
  ASSERT_TRUE(block->labels().empty());
  for (int i = 0; i < 0x20; ++i) {
    BlockGraph::Label label;
    ASSERT_FALSE(block->HasLabel(i));
    EXPECT_FALSE(block->GetLabel(i, &label));
    EXPECT_FALSE(block->RemoveLabel(i));
  }

  EXPECT_TRUE(block->SetLabel(13, "foo", BlockGraph::DATA_LABEL));
  EXPECT_FALSE(block->SetLabel(13, "foo2", BlockGraph::DATA_LABEL));

  EXPECT_TRUE(block->SetLabel(17, "bar", BlockGraph::CODE_LABEL));
  EXPECT_FALSE(block->SetLabel(17, "bar2", BlockGraph::CODE_LABEL));

  EXPECT_TRUE(block->SetLabel(15, "baz", BlockGraph::CODE_LABEL));
  EXPECT_TRUE(block->HasLabel(15));
  EXPECT_TRUE(block->RemoveLabel(15));
  EXPECT_FALSE(block->HasLabel(15));

  for (int i = 0; i < 0x20; ++i) {
    BlockGraph::Label label;
    if (i == 13 || i == 17) {
      ASSERT_TRUE(block->HasLabel(i));
      EXPECT_TRUE(block->GetLabel(i, &label));
      EXPECT_EQ(std::string(i == 13 ? "foo" : "bar"), label.name());
      EXPECT_EQ(i == 13 ? BlockGraph::DATA_LABEL :
                    BlockGraph::CODE_LABEL,
                label.attributes());
    } else {
      ASSERT_FALSE(block->HasLabel(i));
      EXPECT_FALSE(block->GetLabel(i, &label));
    }
  }

  BlockGraph::Block::LabelMap expected;
  expected.insert(std::make_pair(
      13, BlockGraph::Label("foo", BlockGraph::DATA_LABEL)));
  expected.insert(std::make_pair(
      17, BlockGraph::Label("bar", BlockGraph::CODE_LABEL)));
  EXPECT_THAT(block->labels(), testing::ContainerEq(expected));
}

TEST(BlockGraphTest, StringTable) {
  std::string str1 = "Dummy";
  std::string str2 = "Foo";
  std::string str3 = "Bar";
  std::string str4 = "Foo";

  // Validate that string are interned correctly.
  BlockGraph block_graph;
  core::StringTable& strtab = block_graph.string_table();
  const std::string& interned_str1 = strtab.InternString(str1);
  const std::string& interned_str2 = strtab.InternString(str2);
  const std::string& interned_str3 = strtab.InternString(str3);
  const std::string& interned_str4 = strtab.InternString(str4);

  EXPECT_NE(&interned_str1, &interned_str2);
  EXPECT_NE(&interned_str1, &interned_str3);
  EXPECT_NE(&interned_str1, &interned_str4);
  EXPECT_NE(&interned_str2, &interned_str3);
  EXPECT_EQ(&interned_str2, &interned_str4);
  EXPECT_NE(&interned_str3, &interned_str4);
}

namespace {

class BlockGraphSerializationTest : public testing::Test {
 public:
  virtual void SetUp() {
    ASSERT_TRUE(testing::GenerateTestBlockGraph(&image_));
  }

 protected:
  BlockGraph image_;
};

}  // namespace

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

  // We should be able to add arbitrary many zero-sized blocks at any address.
  EXPECT_TRUE(address_space.AddBlock(BlockGraph::CODE_BLOCK,
                                     RelativeAddress(0x1020),
                                     0,
                                     "zerocode1") != NULL);
  EXPECT_EQ(address_space.address_space_impl().size() + 1,
            address_space.block_addresses().size());
  EXPECT_TRUE(address_space.AddBlock(BlockGraph::CODE_BLOCK,
                                     RelativeAddress(0x1020),
                                     0,
                                     "zerocode2") != NULL);
  EXPECT_EQ(address_space.address_space_impl().size() + 2,
            address_space.block_addresses().size());
}

TEST(BlockGraphAddressSpaceTest, ResizeBlock) {
  BlockGraph image;
  BlockGraph::AddressSpace address_space(&image);
  EXPECT_EQ(0u, address_space.size());

  BlockGraph::Block* b1 = address_space.AddBlock(BlockGraph::CODE_BLOCK,
                                                 RelativeAddress(0x1000),
                                                 0x20,
                                                 "code");
  BlockGraph::Block* b2 = address_space.AddBlock(BlockGraph::CODE_BLOCK,
                                                 RelativeAddress(0x1030),
                                                 0x20,
                                                 "code");
  EXPECT_EQ(2u, address_space.size());

  const size_t kNewSizes[] = { 0x28, 0x32, 0x20, 0x20 };
  const size_t kExpectedSizes[] = { 0x28, 0x28, 0x20, 0x20 };
  COMPILE_ASSERT(sizeof(kNewSizes) == sizeof(kExpectedSizes),
                 size_arrays_must_match);

  // Grow successfully first. Then grow, but expect failure. Then shrink.
  // Finally, stay the same size.
  for (size_t i = 0; i < arraysize(kNewSizes); ++i) {
    bool expected_result = kNewSizes[i] == kExpectedSizes[i];
    EXPECT_EQ(expected_result, address_space.ResizeBlock(b1, kNewSizes[i]));

    EXPECT_EQ(2u, address_space.size());
    EXPECT_TRUE(address_space.ContainsBlock(b1));
    EXPECT_TRUE(address_space.ContainsBlock(b2));
    EXPECT_EQ(kExpectedSizes[i], b1->size());
    BlockGraph::AddressSpace::RangeMapConstIter block_it =
        address_space.address_space_impl().FindContaining(
            BlockGraph::AddressSpace::Range(RelativeAddress(0x1000), 1));
    EXPECT_TRUE(block_it != address_space.address_space_impl().end());
    EXPECT_EQ(RelativeAddress(0x1000), block_it->first.start());
    EXPECT_EQ(kExpectedSizes[i], block_it->first.size());
    EXPECT_EQ(b1, block_it->second);
  }

  // Shrink to size zero. The block should be in the list of blocks by address,
  // but not in the actual address space itself.
  EXPECT_TRUE(address_space.ResizeBlock(b1, 0));
  EXPECT_EQ(2u, address_space.size());
  EXPECT_EQ(1u, address_space.address_space_impl().size());
  EXPECT_TRUE(address_space.ContainsBlock(b1));
  EXPECT_TRUE(address_space.ContainsBlock(b2));
  EXPECT_EQ(0u, b1->size());
  BlockGraph::AddressSpace::RangeMapConstIter block_it =
      address_space.address_space_impl().FindContaining(
          BlockGraph::AddressSpace::Range(RelativeAddress(0x1000), 1));
  EXPECT_TRUE(block_it == address_space.address_space_impl().end());
  BlockGraph::AddressSpace::BlockAddressMap::const_iterator addr_it =
      address_space.block_addresses().find(b1);
  EXPECT_TRUE(addr_it != address_space.block_addresses().end());
  EXPECT_EQ(RelativeAddress(0x1000), addr_it->second);

  // Finally, trying to resize a block that's not in the address space
  // should fail.
  BlockGraph::Block* b3 = image.AddBlock(BlockGraph::CODE_BLOCK, 1, "c");
  EXPECT_FALSE(address_space.ResizeBlock(b3, 1));
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
  BlockGraph::Block* block4 =
      image.AddBlock(BlockGraph::CODE_BLOCK, 0, "code");

  ASSERT_TRUE(address_space.InsertBlock(RelativeAddress(0x1000), block1));
  ASSERT_FALSE(address_space.InsertBlock(RelativeAddress(0x1000), block2));
  ASSERT_TRUE(address_space.InsertBlock(RelativeAddress(0x1010), block2));
  ASSERT_FALSE(address_space.InsertBlock(RelativeAddress(0x1018), block3));
  ASSERT_TRUE(address_space.InsertBlock(RelativeAddress(0x1030), block3));
  ASSERT_TRUE(address_space.InsertBlock(RelativeAddress(0x1030), block4));
  EXPECT_EQ(4u, address_space.size());
  EXPECT_EQ(3u, address_space.address_space_impl().size());

  RelativeAddress addr;
  EXPECT_TRUE(address_space.GetAddressOf(block1, &addr));
  EXPECT_EQ(0x1000, addr.value());
  EXPECT_EQ(0x1000, block1->addr().value());

  EXPECT_TRUE(address_space.GetAddressOf(block2, &addr));
  EXPECT_EQ(0x1010, addr.value());
  EXPECT_EQ(0x1010, block2->addr().value());

  EXPECT_TRUE(address_space.GetAddressOf(block3, &addr));
  EXPECT_EQ(0x1030, addr.value());
  EXPECT_EQ(0x1030, block3->addr().value());

  EXPECT_TRUE(address_space.GetAddressOf(block4, &addr));
  EXPECT_EQ(0x1030, addr.value());
  EXPECT_EQ(0x1030, block4->addr().value());

  // Insert a block into a second address space.
  BlockGraph::AddressSpace address_space2(&image);
  EXPECT_TRUE(address_space2.InsertBlock(RelativeAddress(0x2000), block1));
  EXPECT_TRUE(address_space.GetAddressOf(block1, &addr));
  EXPECT_EQ(0x1000, addr.value());

  EXPECT_TRUE(address_space2.GetAddressOf(block1, &addr));
  EXPECT_EQ(0x2000, addr.value());

  EXPECT_EQ(0x2000, block1->addr().value());
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

TEST(BlockGraphAddressSpaceTest, GetContainingBlock) {
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

  // Fully contained in block1
  EXPECT_EQ(block1,
            address_space.GetContainingBlock(RelativeAddress(0x1004), 8));

  // Fully contained in block2
  EXPECT_EQ(block2,
            address_space.GetContainingBlock(RelativeAddress(0x1014), 8));

  // Starts before but intersects with block1.
  EXPECT_EQ(NULL, address_space.GetContainingBlock(RelativeAddress(0x099E), 8));

  // Starts in the middle of block1 and overlaps into block2.
  EXPECT_EQ(NULL, address_space.GetContainingBlock(RelativeAddress(0x100a), 8));
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
  RelativeAddress addr1(0x1000);
  RelativeAddress addr2(0x1010);
  RelativeAddress addr3(0x1030);
  BlockGraph::Block* block1 = address_space.AddBlock(BlockGraph::CODE_BLOCK,
                                                     addr1,
                                                     0x10,
                                                     "block1");
  BlockGraph::Block* block2 = address_space.AddBlock(BlockGraph::CODE_BLOCK,
                                                     addr2,
                                                     0x10,
                                                     "block2");
  BlockGraph::Block* block3 = address_space.AddBlock(BlockGraph::CODE_BLOCK,
                                                     addr3,
                                                     0x10,
                                                     "block3");
  ASSERT_TRUE(block2->SetLabel(0, "0x1010", BlockGraph::CODE_LABEL));
  ASSERT_TRUE(block2->SetLabel(4, "0x1014", BlockGraph::CODE_LABEL));
  ASSERT_TRUE(block3->SetLabel(0, "0x1030", BlockGraph::CODE_LABEL));
  ASSERT_TRUE(block3->SetLabel(4, "0x1034", BlockGraph::CODE_LABEL));

  block1->source_ranges().Push(BlockGraph::Block::DataRange(0, 0x10),
                               BlockGraph::Block::SourceRange(addr1, 0x10));
  block2->source_ranges().Push(BlockGraph::Block::DataRange(0, 0x10),
                               BlockGraph::Block::SourceRange(addr2, 0x10));
  block3->source_ranges().Push(BlockGraph::Block::DataRange(0, 0x10),
                               BlockGraph::Block::SourceRange(addr3, 0x10));

  ASSERT_TRUE(block1->SetReference(0x1,
      BlockGraph::Reference(BlockGraph::ABSOLUTE_REF, 4, block2, 0x0, 0x0)));
  ASSERT_TRUE(block1->SetReference(0x6,
      BlockGraph::Reference(BlockGraph::ABSOLUTE_REF, 4, block3, 0x0, 0x0)));
  ASSERT_TRUE(block2->SetReference(0x1,
      BlockGraph::Reference(BlockGraph::PC_RELATIVE_REF, 1, block1, 0x4, 0x4)));
  ASSERT_TRUE(block2->SetReference(0x6,
      BlockGraph::Reference(BlockGraph::PC_RELATIVE_REF, 4, block3, 0x4, 0x4)));
  ASSERT_TRUE(block3->SetReference(0x1,
      BlockGraph::Reference(BlockGraph::PC_RELATIVE_REF, 4, block2, 0x4, 0x4)));

  // Set some attributes that should trivially propagate to the merged block.
  block2->set_attribute(BlockGraph::PE_PARSED);

  // Set an attribute that only propagates because it is present in both blocks.
  block2->set_attribute(BlockGraph::GAP_BLOCK);
  block3->set_attribute(BlockGraph::GAP_BLOCK);

  // Set an attribute that doesn't propagate because it is not present in both
  // blocks.
  block2->set_attribute(BlockGraph::PADDING_BLOCK);

  // Blocks 2 and 3 will be merged.
  BlockGraph::Block* merged = address_space.MergeIntersectingBlocks(
      BlockGraph::AddressSpace::Range(RelativeAddress(0x1014), 0x30));

  ASSERT_TRUE(merged != NULL);
  ASSERT_EQ(RelativeAddress(0x1010), merged->addr());
  ASSERT_EQ(0x34, merged->size());

  // Expect the merged block to have meaningful source ranges.
  BlockGraph::Block::SourceRanges::RangePairs expected_source_ranges;
  expected_source_ranges.push_back(
      std::make_pair(BlockGraph::Block::DataRange(0, 0x10),
                     BlockGraph::Block::SourceRange(addr2, 0x10)));
  expected_source_ranges.push_back(
      std::make_pair(BlockGraph::Block::DataRange(0x20, 0x10),
                     BlockGraph::Block::SourceRange(addr3, 0x10)));
  EXPECT_THAT(merged->source_ranges().range_pairs(),
              testing::ContainerEq(expected_source_ranges));

  BlockGraph::Block::LabelMap expected_labels;
  expected_labels.insert(std::make_pair(
      0x00, BlockGraph::Label("0x1010", BlockGraph::CODE_LABEL)));
  expected_labels.insert(std::make_pair(
      0x04, BlockGraph::Label("0x1014", BlockGraph::CODE_LABEL)));
  expected_labels.insert(std::make_pair(
      0x20, BlockGraph::Label("0x1030", BlockGraph::CODE_LABEL)));
  expected_labels.insert(std::make_pair(
      0x24, BlockGraph::Label("0x1034", BlockGraph::CODE_LABEL)));
  EXPECT_THAT(merged->labels(), testing::ContainerEq(expected_labels));

  BlockGraph::Block::ReferenceMap expected_refs;
  expected_refs.insert(std::make_pair(0x1,
      BlockGraph::Reference(BlockGraph::PC_RELATIVE_REF, 1, block1, 0x4, 0x4)));
  expected_refs.insert(std::make_pair(0x6,
      BlockGraph::Reference(BlockGraph::PC_RELATIVE_REF, 4, merged, 0x24,
                            0x24)));
  expected_refs.insert(std::make_pair(0x21,
      BlockGraph::Reference(BlockGraph::PC_RELATIVE_REF, 4, merged, 0x4, 0x4)));
  EXPECT_THAT(merged->references(), testing::ContainerEq(expected_refs));

  expected_refs.clear();
  expected_refs.insert(std::make_pair(0x1,
      BlockGraph::Reference(BlockGraph::ABSOLUTE_REF, 4, merged, 0x0, 0x0)));
  expected_refs.insert(std::make_pair(0x6,
      BlockGraph::Reference(BlockGraph::ABSOLUTE_REF, 4, merged, 0x20, 0x20)));
  EXPECT_THAT(block1->references(), testing::ContainerEq(expected_refs));

  // Expect the attributes to have been propagated properly.
  EXPECT_EQ(BlockGraph::PE_PARSED | BlockGraph::GAP_BLOCK,
            merged->attributes());

  // We expect that the block graph and the address space have the same size,
  // as MergeIntersectingBlocks deletes the old blocks from the BlockGraph.
  EXPECT_EQ(image.blocks().size(), address_space.address_space_impl().size());
}

TEST(BlockGraphAddressSpaceTest, ContainsBlock) {
  BlockGraph image;
  BlockGraph::AddressSpace address_space(&image);
  BlockGraph::Block* block =
      image.AddBlock(BlockGraph::CODE_BLOCK, 0x10, "code");

  ASSERT_FALSE(address_space.ContainsBlock(block));
  EXPECT_TRUE(address_space.InsertBlock(RelativeAddress(0x1000), block));
  ASSERT_TRUE(address_space.ContainsBlock(block));
}

}  // namespace block_graph
