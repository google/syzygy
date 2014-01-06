// Copyright 2014 Google Inc. All Rights Reserved.
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

#include "syzygy/block_graph/block_hash.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace block_graph {

TEST(BlockHash, HashAndCompare) {
  BlockGraph block_graph;
  const size_t kBlockSize = 0x20;
  const uint8 kMagicValue = 0xAB;

  BlockGraph::Block* code_block_1 = block_graph.AddBlock(BlockGraph::CODE_BLOCK,
                                                         kBlockSize,
                                                         "code block");

  EXPECT_NE(reinterpret_cast<uint8*>(NULL),
            code_block_1->ResizeData(kBlockSize));

  ::memset(code_block_1->GetMutableData(), kMagicValue, kBlockSize);
  BlockHash code_block_1_hash(code_block_1);

  BlockGraph::Block* test_block = block_graph.AddBlock(BlockGraph::DATA_BLOCK,
                                                       kBlockSize,
                                                       "test block");
  EXPECT_NE(reinterpret_cast<uint8*>(NULL), test_block->ResizeData(kBlockSize));
  ::memset(test_block->GetMutableData(), kMagicValue, kBlockSize);

  // The blocks don't have the same type, they should have a different hash.
  EXPECT_NE(0, code_block_1_hash.Compare(BlockHash(test_block)));
  test_block->set_type(BlockGraph::CODE_BLOCK);
  EXPECT_EQ(0, code_block_1_hash.Compare(BlockHash(test_block)));

  // Change the data size and make sure that this results in a different hash
  // value.
  test_block->ResizeData(kBlockSize + 1);
  EXPECT_NE(0, code_block_1_hash.Compare(BlockHash(test_block)));
  test_block->ResizeData(kBlockSize);
  ::memset(test_block->GetMutableData(), kMagicValue, kBlockSize);
  EXPECT_EQ(0, code_block_1_hash.Compare(BlockHash(test_block)));

  BlockGraph::Block* code_block_2 = block_graph.AddBlock(BlockGraph::CODE_BLOCK,
                                                         kBlockSize,
                                                         "code block 2");
  BlockGraph::Reference block_reference_abs(BlockGraph::ABSOLUTE_REF,
      4, code_block_2, 0, 0);
  BlockGraph::Reference block_reference_pc(BlockGraph::PC_RELATIVE_REF,
      4, code_block_2, 0, 0);
  const size_t kReferenceOffset = 4;

  // |test_block| has a reference but not |code_block_1|, their hashes should
  // be different.
  EXPECT_TRUE(test_block->SetReference(kReferenceOffset, block_reference_abs));
  EXPECT_NE(0, code_block_1_hash.Compare(BlockHash(test_block)));

  EXPECT_TRUE(code_block_1->SetReference(kReferenceOffset,
                                         block_reference_abs));
  code_block_1_hash.Hash(code_block_1);
  // |test_block| and |code_block_1| have the same reference, they should have
  // the same hash.
  EXPECT_EQ(0, code_block_1_hash.Compare(BlockHash(test_block)));

  // Alter the data in |test_block| (outside of the reference) and make sure
  // that this results in a different hash.
  test_block->GetMutableData()[0] = ~kMagicValue;
  EXPECT_NE(0, code_block_1_hash.Compare(BlockHash(test_block)));
  test_block->GetMutableData()[0] = kMagicValue;
  EXPECT_EQ(0, code_block_1_hash.Compare(BlockHash(test_block)));

  // Alter the data in |test_block| in the reference and make sure that this
  // doesn't alter the hash.
  test_block->GetMutableData()[kReferenceOffset] = ~kMagicValue;
  EXPECT_EQ(0, code_block_1_hash.Compare(BlockHash(test_block)));
  test_block->GetMutableData()[kReferenceOffset] = kMagicValue;

  // Modify the reference of |test_block| and make sure that this results in a
  // different hash.
  EXPECT_TRUE(test_block->RemoveReference(kReferenceOffset));
  test_block->SetReference(kReferenceOffset + 1, block_reference_abs);
  EXPECT_NE(0, code_block_1_hash.Compare(BlockHash(test_block)));
  EXPECT_TRUE(test_block->RemoveReference(kReferenceOffset + 1));

  test_block->SetReference(kReferenceOffset, block_reference_pc);
  EXPECT_NE(0, code_block_1_hash.Compare(BlockHash(test_block)));
}

}  // namespace block_graph
