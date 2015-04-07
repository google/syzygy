// Copyright 2015 Google Inc. All Rights Reserved.
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

#include "syzygy/pe/transforms/pe_hot_patching_basic_block_transform.h"

#include "syzygy/block_graph/basic_block_assembler.h"

namespace pe {
namespace transforms {

const char PEHotPatchingBasicBlockTransform::kTransformName[] =
    "PEHotPatchingBasicBlockTransform";

// This is the size of an x86 jump instruction: 0xEA [32-bit absolute address]
// The padding inserted at the beginning of the blocks must be big enough to
// contain this instruction.
const size_t PEHotPatchingBasicBlockTransform::kLongJumpInstructionLength = 5U;

namespace {

using block_graph::BlockGraph;
using block_graph::BasicBlockAssembler;
using block_graph::BasicBlockSubGraph;
typedef BasicBlockSubGraph::BasicBlock BasicBlock;
typedef BasicBlockSubGraph::BasicCodeBlock BasicCodeBlock;

}  // namespace

bool PEHotPatchingBasicBlockTransform::TransformBasicBlockSubGraph(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BasicBlockSubGraph* basic_block_subgraph) {
  EnsureAtomicallyReplaceableFirstInstruction(basic_block_subgraph);
  EnsurePaddingForJumpBeforeBlock(basic_block_subgraph);
  return true;
}

void PEHotPatchingBasicBlockTransform::InsertTwoByteNopAtBlockBeginning(
    BasicCodeBlock* bb) {
  // Insert a two-byte NOP at the beginning.
  BasicBlockAssembler assm(bb->instructions().begin(), &bb->instructions());
  assm.nop(2U);
}

bool PEHotPatchingBasicBlockTransform::IsAtomicallyReplaceableFirstInstruction(
    BasicCodeBlock* bb) {
  // If there are no instructions in the first basic code block it means that
  // the block begins with a jump which is either 2 or 5 bytes so therefore
  // atomically replaceable.
  if (bb->instructions().size() == 0)
    return true;

  // An at least two-byte aligned and at least two-byte long instruction is
  // atomically replaceable.
  return bb->instructions().front().size() >= 2;
}

void PEHotPatchingBasicBlockTransform::
    EnsureAtomicallyReplaceableFirstInstruction(
    BasicBlockSubGraph* bbsg) {
  DCHECK_NE(static_cast<BasicBlockSubGraph*>(nullptr), bbsg);
  CHECK_EQ(1U, bbsg->block_descriptions().size());

  // Ensure proper alignment for the first instruction. An alignment of 2
  // allows to atomically replace the first 2 bytes of a 2-byte or longer
  // instruction.
  if (bbsg->block_descriptions().front().alignment < 2)
    bbsg->block_descriptions().front().alignment = 2;

  BasicCodeBlock* first_bb = GetFirstBasicCodeBlock(bbsg);

  if (!IsAtomicallyReplaceableFirstInstruction(first_bb))
    InsertTwoByteNopAtBlockBeginning(first_bb);
}

void PEHotPatchingBasicBlockTransform::EnsurePaddingForJumpBeforeBlock(
    BasicBlockSubGraph* bbsg) {
  DCHECK_NE(static_cast<BasicBlockSubGraph*>(nullptr), bbsg);

  CHECK_EQ(1U, bbsg->block_descriptions().size());
  BasicBlockSubGraph::BlockDescription& block_description =
      bbsg->block_descriptions().front();

  // If padding_before is not 0, it means that some other task wants to use
  // that place for some other purpose.
  CHECK_EQ(0U, block_description.padding_before);

  block_description.padding_before = kLongJumpInstructionLength;
}

BasicCodeBlock* PEHotPatchingBasicBlockTransform::GetFirstBasicCodeBlock(
    BasicBlockSubGraph* bbsg) {
  DCHECK_NE(static_cast<BasicBlockSubGraph*>(nullptr), bbsg);

  // Get the description of the block.
  CHECK_EQ(1U, bbsg->block_descriptions().size());
  BasicBlockSubGraph::BlockDescription& block_description =
      bbsg->block_descriptions().front();

  // Get the first basic block.
  CHECK_EQ(false, block_description.basic_block_order.empty());
  BasicBlock* first_block = block_description.basic_block_order.front();

  // Convert to a basic code block.
  BasicCodeBlock* first_code_block = BasicCodeBlock::Cast(first_block);
  CHECK_NE(static_cast<BasicCodeBlock*>(nullptr), first_code_block);
  return first_code_block;
}

}  // namespace transforms
}  // namespace pe
