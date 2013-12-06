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
//
// Unittests for BlockGraph transform wrapper.

#include "syzygy/block_graph/transform.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/block_graph/unittest_util.h"

namespace block_graph {
namespace {

using testing::_;
using testing::DummyTransformPolicy;
using testing::Invoke;
using testing::Return;

// A constant data structure/buffer from which to initialize a data block.
// The structure contains a core reference (function pointer) and an integer
// data element.
struct MyData {
  void (*code)(int);
  int data;
};
const BlockGraph::Offset kOffsetOfReferenceToCode = offsetof(MyData, code);
const BlockGraph::Offset kOffsetOfData = offsetof(MyData, data);
const MyData kDataBytes = { reinterpret_cast<void(*)(int)>(0xCAFEBABE),
                            0xDEADBEEF };

// A byte buffer from which to initialize a code block. The original C source
// code for this function is:
//
//     static int y = 1;
//     void add(int x) {
//       y += x;
//     }
//
// Note the reference to
// y starts 5 bytes from the end.
const uint8 kCodeBytes[] = {
  0x8B, 0x44, 0x24, 0x04,              // mov eax,dword ptr [esp+4]
  0x01, 0x05, 0x00, 0x00, 0x00, 0x00,  // add dword ptr [_y],eax
  0xC3                                 // ret
};
const BlockGraph::Offset kOffsetOfCode = 0;
const BlockGraph::Offset kOffsetOfReferenceToData = sizeof(kCodeBytes) - 5;

class ApplyBlockGraphTransformTest : public testing::Test {
 public:
  virtual void SetUp() {
    header_block_ = block_graph_.AddBlock(BlockGraph::DATA_BLOCK, 10, "Header");
  }

 protected:
  DummyTransformPolicy policy_;
  BlockGraph block_graph_;
  BlockGraph::Block* header_block_;
};

class LenientMockBlockGraphTransform : public BlockGraphTransformInterface {
 public:
  virtual ~LenientMockBlockGraphTransform() { }

  virtual const char* name() const { return "MockBlockGraphTransform"; }

  MOCK_METHOD3(TransformBlockGraph,
               bool(const TransformPolicyInterface*,
                    BlockGraph*,
                    BlockGraph::Block*));

  bool DeleteHeader(const TransformPolicyInterface* policy,
                    BlockGraph* block_graph,
                    BlockGraph::Block* header_block) {
    CHECK(block_graph->RemoveBlock(header_block));
    return true;
  }
};
typedef testing::StrictMock<LenientMockBlockGraphTransform>
    MockBlockGraphTransform;

class ApplyBasicBlockSubGraphTransformTest : public testing::Test {
 public:
  ApplyBasicBlockSubGraphTransformTest()
      : data_block_(NULL), code_block_(NULL) {
  }

  virtual void SetUp() {
    // Create some blocks to test with.
    data_block_ = block_graph_.AddBlock(
        BlockGraph::DATA_BLOCK, sizeof(kDataBytes), "Data");
    ASSERT_TRUE(data_block_ != NULL);
    code_block_ = block_graph_.AddBlock(
        BlockGraph::CODE_BLOCK, sizeof(kCodeBytes), "Code");
    ASSERT_TRUE(code_block_ != NULL);

    // Set up the data block.
    data_block_->SetData(reinterpret_cast<const uint8*>(&kDataBytes),
                         sizeof(kDataBytes));

    // Set up the code block.
    ASSERT_TRUE(code_block_->SetLabel(
        kOffsetOfCode,
        BlockGraph::Label("Code", BlockGraph::CODE_LABEL)));
    code_block_->SetData(kCodeBytes, sizeof(kCodeBytes));

    // Set up the references
    ASSERT_TRUE(
        data_block_->SetReference(kOffsetOfReferenceToCode,
                                  MakeReference(code_block_, kOffsetOfCode)));
    ASSERT_TRUE(
        code_block_->SetReference(kOffsetOfReferenceToData,
                                  MakeReference(data_block_, kOffsetOfData)));
  }

  static BlockGraph::Reference MakeReference(BlockGraph::Block* target,
                                             BlockGraph::Offset offset) {
    EXPECT_TRUE(target != NULL);
    return BlockGraph::Reference(BlockGraph::RELATIVE_REF,
                                 BlockGraph::Reference::kMaximumSize,
                                 target, offset, offset);
  }

 protected:
  DummyTransformPolicy policy_;
  BlockGraph block_graph_;
  BlockGraph::Block* data_block_;
  BlockGraph::Block* code_block_;
};

class MockBasicBlockSubGraphTransform :
    public BasicBlockSubGraphTransformInterface {
 public:
  virtual ~MockBasicBlockSubGraphTransform() { }

  virtual const char* name() const { return "MockBasicBlockSubGraphTransform"; }

  MOCK_METHOD3(TransformBasicBlockSubGraph,
               bool(const TransformPolicyInterface*,
                    BlockGraph*,
                    BasicBlockSubGraph*));
};

}  // namespace

TEST_F(ApplyBlockGraphTransformTest, NormalTransformSucceeds) {
  MockBlockGraphTransform transform;
  EXPECT_CALL(transform, TransformBlockGraph(_, _, _)).Times(1).
      WillOnce(Return(true));
  EXPECT_TRUE(ApplyBlockGraphTransform(&transform,
                                       &policy_,
                                       &block_graph_,
                                       header_block_));
}

TEST_F(ApplyBlockGraphTransformTest, DeletingHeaderFails) {
  MockBlockGraphTransform transform;
  EXPECT_CALL(transform, TransformBlockGraph(_, _, _)).Times(1).WillOnce(
      Invoke(&transform, &MockBlockGraphTransform::DeleteHeader));
  EXPECT_FALSE(ApplyBlockGraphTransform(&transform,
                                        &policy_,
                                        &block_graph_,
                                        header_block_));
}

TEST_F(ApplyBlockGraphTransformTest, VectorTransformSucceeds) {
  MockBlockGraphTransform tx1, tx2, tx3;
  std::vector<BlockGraphTransformInterface*> txs;
  txs.push_back(&tx1);
  txs.push_back(&tx2);
  txs.push_back(&tx3);

  EXPECT_CALL(tx1, TransformBlockGraph(&policy_, &block_graph_, header_block_))
      .WillOnce(Return(true));
  EXPECT_CALL(tx2, TransformBlockGraph(&policy_, &block_graph_, header_block_))
      .WillOnce(Return(true));
  EXPECT_CALL(tx3, TransformBlockGraph(&policy_, &block_graph_, header_block_))
      .WillOnce(Return(true));

  EXPECT_TRUE(ApplyBlockGraphTransforms(
      txs, &policy_, &block_graph_, header_block_));
}

TEST_F(ApplyBlockGraphTransformTest, VectorTransformFails) {
  MockBlockGraphTransform tx1, tx2, tx3;
  std::vector<BlockGraphTransformInterface*> txs;
  txs.push_back(&tx1);
  txs.push_back(&tx2);
  txs.push_back(&tx3);

  EXPECT_CALL(tx1, TransformBlockGraph(&policy_, &block_graph_, header_block_))
      .WillOnce(Return(true));
  EXPECT_CALL(tx2, TransformBlockGraph(&policy_, &block_graph_, header_block_))
      .WillOnce(Return(false));

  EXPECT_FALSE(ApplyBlockGraphTransforms(
      txs, &policy_, &block_graph_, header_block_));
}

TEST_F(ApplyBasicBlockSubGraphTransformTest, TransformFails) {
  // Remember the block ids of the original blocks.
  BlockGraph::BlockId data_block_id = data_block_->id();
  BlockGraph::BlockId code_block_id = code_block_->id();

  // Apply an empty transform that reports failure.
  MockBasicBlockSubGraphTransform transform;
  EXPECT_CALL(transform, TransformBasicBlockSubGraph(_, _, _)).Times(1).
      WillOnce(Return(false));
  EXPECT_FALSE(ApplyBasicBlockSubGraphTransform(&transform,
                                                &policy_,
                                                &block_graph_,
                                                code_block_,
                                                NULL));

  // The original block graph should be unchanged.
  EXPECT_EQ(2U, block_graph_.blocks().size());
  EXPECT_EQ(data_block_, block_graph_.GetBlockById(data_block_id));
  EXPECT_EQ(code_block_, block_graph_.GetBlockById(code_block_id));
}

TEST_F(ApplyBasicBlockSubGraphTransformTest, EmptyTransformSucceeds) {
  // Remember the block ids of the original blocks.
  BlockGraph::BlockId data_block_id = data_block_->id();
  BlockGraph::BlockId code_block_id = code_block_->id();

  // Apply an empty transform that reports success.
  MockBasicBlockSubGraphTransform transform;
  BlockVector new_blocks;
  EXPECT_CALL(transform, TransformBasicBlockSubGraph(_, _, _)).Times(1).
      WillOnce(Return(true));
  EXPECT_TRUE(ApplyBasicBlockSubGraphTransform(&transform,
                                               &policy_,
                                               &block_graph_,
                                               code_block_,
                                               &new_blocks));

  // The code block should have been replaced with an equivalent one. We'll
  // have the same number of blocks, but the code block should no longer
  // be in the graph.
  EXPECT_EQ(2U, block_graph_.blocks().size());
  EXPECT_EQ(data_block_, block_graph_.GetBlockById(data_block_id));
  EXPECT_EQ(NULL, block_graph_.GetBlockById(code_block_id));

  // Clean up our dangling pointer.
  code_block_ = NULL;

  // Find the new block.
  ASSERT_EQ(1U, new_blocks.size());
  const BlockGraph::Block* new_block = new_blocks[0];

  // Validate the references.
  EXPECT_EQ(1U, new_block->references().size());
  BlockGraph::Reference ref;
  EXPECT_TRUE(new_block->GetReference(kOffsetOfReferenceToData, &ref));
  EXPECT_EQ(kOffsetOfData, ref.offset());
  EXPECT_EQ(data_block_, ref.referenced());

  // Validate the referrers.
  EXPECT_EQ(1U, new_block->referrers().size());
  EXPECT_EQ(data_block_, new_block->referrers().begin()->first);
  EXPECT_EQ(kOffsetOfReferenceToCode, new_block->referrers().begin()->second);
  EXPECT_TRUE(new_block->referrers().begin()->first->GetReference(
      kOffsetOfReferenceToCode, &ref));
  EXPECT_EQ(new_block, ref.referenced());
}

TEST_F(ApplyBasicBlockSubGraphTransformTest, VectorTransformSucceeds) {
  // Validate applying a vector of transforms.
  MockBasicBlockSubGraphTransform transform1;
  MockBasicBlockSubGraphTransform transform2;
  BlockVector new_blocks;
  EXPECT_CALL(transform1, TransformBasicBlockSubGraph(_, _, _)).Times(1).
      WillOnce(Return(true));
  EXPECT_CALL(transform2, TransformBasicBlockSubGraph(_, _, _)).Times(1).
      WillOnce(Return(true));

  std::vector<BasicBlockSubGraphTransformInterface*> transforms;
  transforms.push_back(&transform1);
  transforms.push_back(&transform2);
  EXPECT_TRUE(ApplyBasicBlockSubGraphTransforms(transforms,
                                                &policy_,
                                                &block_graph_,
                                                code_block_,
                                                &new_blocks));
}

}  // namespace block_graph
