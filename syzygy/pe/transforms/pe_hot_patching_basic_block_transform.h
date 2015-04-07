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
//
// A basic block subgraph transform that prepares a block for hot patching.
//
// To make a block hot patchable, we insert five bytes of padding before the
// block to accommodate a long jump instruction and make the first instruction
// of the block atomically replaceable with a two-byte jump that jumps
// to the long jump in the padding. An instruction is atomically replaceable
// if it is at least two bytes long and its first two bytes do not cross
// a 4-byte boundary. Therefore the alignment of the block will be increased
// to at least two and if the block begins with a one-byte instruction, a
// two-byte NOP will be prepended and the references referring after the NOP
// will refer to the beginning of the block.

#ifndef SYZYGY_PE_TRANSFORMS_PE_HOT_PATCHING_BASIC_BLOCK_TRANSFORM_H_
#define SYZYGY_PE_TRANSFORMS_PE_HOT_PATCHING_BASIC_BLOCK_TRANSFORM_H_

#include <vector>

#include "syzygy/block_graph/transforms/iterative_transform.h"

namespace pe {
namespace transforms {

class PEHotPatchingBasicBlockTransform
    : public block_graph::transforms::NamedBasicBlockSubGraphTransformImpl<
          PEHotPatchingBasicBlockTransform> {
 public:
  typedef block_graph::BlockGraph BlockGraph;
  typedef block_graph::BasicBlockSubGraph BasicBlockSubGraph;
  typedef block_graph::TransformPolicyInterface TransformPolicyInterface;
  typedef BasicBlockSubGraph::BasicCodeBlock BasicCodeBlock;

  // The transform name.
  static const char kTransformName[];

  PEHotPatchingBasicBlockTransform() {}

  // BasicBlockSubGraphTransformInterface implementation.
  // @pre The subgraph must contain a single block that must begin with
  //     a basic code block.
  virtual bool TransformBasicBlockSubGraph(
      const TransformPolicyInterface* policy,
      BlockGraph* block_graph,
      BasicBlockSubGraph* bbsg) override;

 protected:
  // The length of a long jump instruction. This is the amount of padding that
  // will be inserted before each block that needs hot patching.
  static const size_t kLongJumpInstructionLength;

  // Insert a NOP at the beginning of the code block.
  // @param code_block The basic code block to insert into.
  void InsertTwoByteNopAtBlockBeginning(BasicCodeBlock* code_block);

  // Checks if the first instruction of a basic code block is atomically
  // replaceable.
  // @param code_block The basic code block to examine.
  // @returns true iff the first instruction of the basic code block is
  //     atomically replaceable.
  bool IsAtomicallyReplaceableFirstInstruction(BasicCodeBlock* code_block);

  // Ensures that the first instruction of a block is atomically replaceable.
  // This function increases the alignment to 2 (if it was lower), checks
  // the first instruction, and if it is not atomically replaceable
  // (only one byte long) then prepends a two-byte NOP to the first basic code
  // block.
  // @param bbsg The basic block subgraph to change.
  // @pre The subgraph must contain a single block that must begin with
  //     a basic code block.
  void EnsureAtomicallyReplaceableFirstInstruction(BasicBlockSubGraph* bbsg);

  // Ensures that there is at least kLongJumpInstructionLength padding before
  // the block represented by the basic block subgraph.
  // @param block The target block.
  // @pre The subgraph must contain a single block.
  void EnsurePaddingForJumpBeforeBlock(BasicBlockSubGraph* bbsg);

  // Gets the first basic code block of a block in a subgraph according to
  // the basic block ordering in the block description.
  // @param bbsg The basic block subgraph to query.
  // @returns The first code block
  // @pre The subgraph must contain a single block that must begin with
  //     a basic code block.
  BasicCodeBlock* GetFirstBasicCodeBlock(BasicBlockSubGraph* bbsg);

 private:
  DISALLOW_COPY_AND_ASSIGN(PEHotPatchingBasicBlockTransform);
};

}  // namespace transforms
}  // namespace pe

#endif  // SYZYGY_PE_TRANSFORMS_PE_HOT_PATCHING_BASIC_BLOCK_TRANSFORM_H_
