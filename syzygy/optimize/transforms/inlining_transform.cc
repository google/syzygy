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
// This class implements the functions inlining transformation.
//
// Performing inline expansion on assembly is not an easy task. As the transform
// runs after the standard compiler WPO, it may face custom calling convention
// and strange stack manipulations. Thus, every expansion must be safe.
//
// The trivial body inlining is able to inline any trivial accessors.
//  Assumptions:
//     - No stack manipulations.
//     - No branching instructions (except the last return).
//     - No basic blocks reference, data block, jump-table, etc...
//  Example:
//     - XOR EAX, EAX
//       RET

#include "syzygy/optimize/transforms/inlining_transform.h"

#include "syzygy/block_graph/basic_block.h"
#include "syzygy/block_graph/basic_block_decomposer.h"
#include "syzygy/block_graph/block_graph.h"
// TODO(etienneb): liveness analysis internal should be hoisted to an
//     instructions helper namespace, and shared between analysis. It is quite
//     common to get the information on registers defined or used by an
//     instruction, or the memory operand read and written.
#include "syzygy/block_graph/analysis/liveness_analysis_internal.h"

namespace optimize {
namespace transforms {

namespace {

using block_graph::BasicBlock;
using block_graph::BasicBlockDecomposer;
using block_graph::BasicBlockReference;
using block_graph::BasicCodeBlock;
using block_graph::Instruction;
using block_graph::Successor;
using block_graph::analysis::LivenessAnalysis;

typedef Instruction::BasicBlockReferenceMap BasicBlockReferenceMap;

// Match a call instruction to a direct callee (i.e. no indirect calls).
bool MatchDirectCall(const Instruction& instr, BlockGraph::Block** callee) {
  DCHECK_NE(reinterpret_cast<BlockGraph::Block**>(NULL), callee);

  // Match a call instruction with one reference.
  const _DInst& repr = instr.representation();
  if (!instr.IsCall() ||
      repr.ops[0].type != O_PC ||
      instr.references().size() != 1) {
    return false;
  }

  // The callee must be a code block.
  const BasicBlockReference& ref = instr.references().begin()->second;
  BlockGraph::Block* block = ref.block();
  if (block == NULL || block->type() != BlockGraph::CODE_BLOCK)
    return false;

  // Returns the matched callee.
  *callee = block;
  return true;
}

// Match trivial body in a subgraph. A trivial body is a single basic block
// without control flow, stack manipulation or other unsupported constructs.
bool MatchTrivialBody(const BasicBlockSubGraph& subgraph,
                      BasicCodeBlock** body) {
  DCHECK_NE(reinterpret_cast<BasicCodeBlock**>(NULL), body);

  // Trivial body only has one basic block.
  if (subgraph.basic_blocks().size() != 1)
    return false;
  BasicCodeBlock* bb = BasicCodeBlock::Cast(*subgraph.basic_blocks().begin());
  if (bb == NULL)
    return false;

  bool has_return = false;

  // Iterates through each instruction.
  BasicBlock::Instructions::iterator inst_iter = bb->instructions().begin();
  for (; inst_iter != bb->instructions().end(); ++inst_iter) {
    const Instruction& instr = *inst_iter;

    // Return instruction is valid.
    if (instr.IsReturn()) {
      has_return = true;
      continue;
    }

    // Avoid control flow instructions.
    if (instr.IsControlFlow())
      return false;

    // Do not allow any references to a basic block.
    const BasicBlockReferenceMap& references = instr.references();
    BasicBlockReferenceMap::const_iterator ref = references.begin();
    for (; ref != references.end(); ++ref) {
      if (ref->second.referred_type() ==
          BasicBlockReference::REFERRED_TYPE_BASIC_BLOCK) {
        return false;
      }
    }

    // Avoid stack manipulation
    LivenessAnalysis::State defs;
    LivenessAnalysis::StateHelper::GetDefsOf(instr, &defs);

    LivenessAnalysis::State uses;
    LivenessAnalysis::StateHelper::GetUsesOf(instr, &uses);

    if (defs.IsLive(core::esp) ||
        defs.IsLive(core::ebp) ||
        uses.IsLive(core::esp) ||
        uses.IsLive(core::ebp)) {
      return false;
    }
  }

  // The basic block must have a return (to remove the caller address on stack)
  // and must not have successors.
  if (!bb->successors().empty() || !has_return)
    return false;

  // Returns the matched body.
  *body = bb;
  return true;
}

// Decompose a block to a subgraph.
bool DecomposeToBasicBlock(const BlockGraph::Block* block,
                           BasicBlockSubGraph* subgraph) {
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), block);
  DCHECK_NE(reinterpret_cast<BasicBlockSubGraph*>(NULL), subgraph);

  // Decompose block to basic blocks.
  BasicBlockDecomposer decomposer(block, subgraph);
  if (!decomposer.Decompose())
    return false;

  return true;
}

// Copy the body of the callee at a call-site in the caller.
bool InlineTrivialBody(const BasicCodeBlock* body,
                       BasicBlock::Instructions::iterator target,
                       BasicBlock::Instructions* instructions) {
  DCHECK_NE(reinterpret_cast<BasicBlock::Instructions*>(NULL), instructions);

  BasicBlock::Instructions new_body;

  // Iterates through each instruction.
  BasicBlock::Instructions::const_iterator inst_iter =
      body->instructions().begin();
  for (; inst_iter != body->instructions().end(); ++inst_iter) {
    const Instruction& instr = *inst_iter;
    const _DInst& repr = instr.representation();

    if (instr.IsReturn()) {
      if (repr.ops[0].type != O_NONE) {
        // TODO(etienneb): 'ret 8' must be converted to a 'add %esp, 8'.
        return false;
      }
    } else {
      new_body.push_back(instr);
    }
  }

  // Insert the inlined instructions at the call-site.
  instructions->splice(target, new_body);
  return true;
}

}  // namespace

const char InliningTransform::kTransformName[] = "InlineBasicBlockTransform";

bool InliningTransform::TransformBasicBlockSubGraph(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BasicBlockSubGraph* subgraph) {
  DCHECK_NE(reinterpret_cast<TransformPolicyInterface*>(NULL), policy);
  DCHECK_NE(reinterpret_cast<BlockGraph*>(NULL), block_graph);
  DCHECK_NE(reinterpret_cast<BasicBlockSubGraph*>(NULL), subgraph);

  const BlockGraph::Block* caller = subgraph->original_block();
  DCHECK_NE(reinterpret_cast<const BlockGraph::Block*>(NULL), caller);

  // Apply the decomposition policy to the caller.
  if (!policy->CodeBlockIsSafeToBasicBlockDecompose(caller))
    return true;

  // Iterates through each basic block.
  BasicBlockSubGraph::BBCollection::iterator bb_iter =
      subgraph->basic_blocks().begin();
  for (; bb_iter != subgraph->basic_blocks().end(); ++bb_iter) {
    BasicCodeBlock* bb = BasicCodeBlock::Cast(*bb_iter);
    if (bb == NULL)
      continue;

    // Iterates through each instruction.
    BasicBlock::Instructions::iterator inst_iter = bb->instructions().begin();
    while (inst_iter != bb->instructions().end()) {
      const Instruction& instr = *inst_iter;
      BasicBlock::Instructions::iterator call_iter = inst_iter;
      ++inst_iter;

      // Match a direct call-site.
      BlockGraph::Block* callee = NULL;
      if (!MatchDirectCall(instr, &callee))
        continue;

      // Avoid self recursion inlining.
      // Apply the decomposition policy to the callee.
      if (caller == callee ||
          !policy->CodeBlockIsSafeToBasicBlockDecompose(callee)) {
        continue;
      }

      // For a small callee, try to replace callee instructions in-place.
      // Add one byte to take into account the return instruction.
      if (callee->size() <= instr.size() + 1) {
        BasicBlockSubGraph callee_subgraph;
        BasicCodeBlock* body;

        if (DecomposeToBasicBlock(callee, &callee_subgraph) &&
            MatchTrivialBody(callee_subgraph, &body) &&
            InlineTrivialBody(body, call_iter, &bb->instructions())) {
          // Inlining successful, remove call-site.
          bb->instructions().erase(call_iter);
          continue;
        }
      }
    }
  }

  return true;
}

}  // namespace transforms
}  // namespace optimize
