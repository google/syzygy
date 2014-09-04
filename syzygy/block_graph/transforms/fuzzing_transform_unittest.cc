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
//
// Unittests for FuzzingTransform.

#include "syzygy/block_graph/transforms/fuzzing_transform.h"

#include "gtest/gtest.h"
#include "syzygy/block_graph/basic_block.h"
#include "syzygy/block_graph/basic_block_assembler.h"
#include "syzygy/block_graph/basic_block_decomposer.h"
#include "syzygy/block_graph/basic_block_subgraph.h"
#include "syzygy/block_graph/block_graph.h"
#include "syzygy/block_graph/transform.h"
#include "syzygy/block_graph/unittest_util.h"

#include "mnemonics.h"  // NOLINT

namespace block_graph {
namespace transforms {
namespace {

using block_graph::BasicBlock;
using block_graph::BasicBlockAssembler;
using block_graph::BasicCodeBlock;
using block_graph::BasicBlockDecomposer;
using block_graph::Instruction;
using block_graph::Immediate;
using testing::DummyTransformPolicy;

class TestLivenessFuzzingBasicBlockTransform :
    public LivenessFuzzingBasicBlockTransform {
 public:
  using LivenessFuzzingBasicBlockTransform::TransformBasicBlockSubGraph;
};

}  // namespace

TEST(LivenessFuzzingBasicBlockTransformTest, SingleBasicBlock) {
  BlockGraph bg;
  BasicBlockSubGraph subgraph;
  BasicCodeBlock* bb = subgraph.AddBasicCodeBlock("bb");
  ASSERT_TRUE(bb != NULL);

  // Insert instructions into basic block.
  BasicBlockAssembler assembly(bb->instructions().end(), &bb->instructions());
  assembly.cmp(assm::eax, Immediate(42, assm::kSize32Bit));
  assembly.mov(assm::eax, Immediate(0, assm::kSize32Bit));

  // Transforms the basic block.
  DummyTransformPolicy policy;
  TestLivenessFuzzingBasicBlockTransform tx;
  size_t previous_size = bb->instructions().size();
  ASSERT_TRUE(tx.TransformBasicBlockSubGraph(&policy, &bg, &subgraph));

  // Expecting two new instructions.
  size_t expected_size = previous_size + 2;
  size_t current_size = bb->instructions().size();
  EXPECT_EQ(expected_size, current_size);
}

}  // namespace transforms
}  // namespace block_graph
