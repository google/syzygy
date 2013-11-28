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
// The pattern based inlining is able to inline many common cases encounter with
// common compilers. This inlining transformation avoids decomposing the block
// which is much more efficient.
//   Example:
//     - push ebp
//       mov ebp, esp
//       pop ebp
//       ret
//
// The trivial body inlining is able to inline any trivial accessors.
//   Assumptions:
//     - No stack manipulations (except local push/pop).
//     - No branching instructions (except the last return or jump).
//     - No basic blocks reference, data block, jump-table, etc...
//   Example:
//     - xor eax, eax
//       ret

#include "syzygy/optimize/transforms/inlining_transform.h"

#include "syzygy/block_graph/basic_block.h"
#include "syzygy/block_graph/basic_block_assembler.h"
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
using block_graph::BasicBlockAssembler;
using block_graph::BasicBlockDecomposer;
using block_graph::BasicBlockReference;
using block_graph::BasicBlockSubGraph;
using block_graph::BasicCodeBlock;
using block_graph::BlockGraph;
using block_graph::Displacement;
using block_graph::Immediate;
using block_graph::Instruction;
using block_graph::Operand;
using block_graph::Successor;
using block_graph::analysis::LivenessAnalysis;

typedef ApplicationProfile::BlockProfile BlockProfile;
typedef Instruction::BasicBlockReferenceMap BasicBlockReferenceMap;

enum MatchKind {
  kInvalidMatch,
  kReturnMatch,
  kReturnConstantMatch,
  kDirectTrampolineMatch,
  kIndirectTrampolineMatch,
};

// These patterns are often produced by the MSVC compiler. They're common enough
// that the inlining transformation matches them by pattern rather than
// disassembling them.

// ret
const uint8 kEmptyBody1[] = { 0xC3 };

// push %ebp
// mov %ebp, %esp
// pop %ebp
// ret
const uint8 kEmptyBody2[] = { 0x55, 0x8B, 0xEC, 0x5D, 0xC3 };

// push %ebp
// mov %ebp, %esp
// mov %eax, [%ebp + 0x4]
// pop %ebp
// ret
const uint8 kGetProgramCounter[] = {
    0x55, 0x8B, 0xEC, 0x8B, 0x45, 0x04, 0x5D, 0xC3 };

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

  // The callee must be the beginning of a code block.
  const BasicBlockReference& ref = instr.references().begin()->second;
  BlockGraph::Block* block = ref.block();
  if (block == NULL ||
      ref.base() != 0 ||
      ref.offset() != 0 ||
      block->type() != BlockGraph::CODE_BLOCK) {
    return false;
  }

  // Returns the matched callee.
  *callee = block;
  return true;
}

bool MatchRawBytes(BlockGraph::Block* callee,
                   const uint8* bytes,
                   size_t length) {
  if (callee->size() != length ||
      ::memcmp(callee->data(), bytes, length) != 0) {
    return false;
  }

  return true;
}

bool MatchGetProgramCounter(BlockGraph::Block* callee) {
  size_t length = sizeof(kGetProgramCounter);
  if (MatchRawBytes(callee, kGetProgramCounter, length))
    return true;

  return false;
}

bool MatchEmptyBody(BlockGraph::Block* callee) {
  size_t length1 = sizeof(kEmptyBody1);
  if (MatchRawBytes(callee, kEmptyBody1, length1))
    return true;

  size_t length2 = sizeof(kEmptyBody2);
  if (MatchRawBytes(callee, kEmptyBody2, length2))
    return true;

  return false;
}

// Match trivial body in a subgraph. A trivial body is a single basic block
// without control flow, stack manipulation or other unsupported constructs.
// @param subgraph The subgraph to try matching a trivial body.
// @param kind On a match, receives the kind of match was found.
// @param return_constant Receives the number of bytes to pop from the stack
//     after the body (when kind is kReturnConstantMatch).
// @param reference Receives a reference to a target continuation (when kind is
//     kDirectTrampolineMatch or kIndirectTrampolineMatch).
// @param body On success, receives the trivial body.
// @returns true on success, false otherwise.
bool MatchTrivialBody(const BasicBlockSubGraph& subgraph,
                      MatchKind* kind,
                      size_t* return_constant,
                      BasicBlockReference* reference,
                      BasicCodeBlock** body) {
  DCHECK_NE(reinterpret_cast<MatchKind*>(NULL), kind);
  DCHECK_NE(reinterpret_cast<size_t*>(NULL), return_constant);
  DCHECK_NE(reinterpret_cast<BasicBlockReference*>(NULL), reference);
  DCHECK_NE(reinterpret_cast<BasicCodeBlock**>(NULL), body);

  // Assume no match.
  *kind = kInvalidMatch;

  // Trivial body only has one basic block.
  if (subgraph.basic_blocks().size() != 1)
    return false;
  BasicCodeBlock* bb = BasicCodeBlock::Cast(*subgraph.basic_blocks().begin());
  if (bb == NULL)
    return false;

  // Current local stack depth.
  size_t stack_depth = 0;

  // Iterates through each instruction.
  BasicBlock::Instructions::iterator inst_iter = bb->instructions().begin();
  for (; inst_iter != bb->instructions().end(); ++inst_iter) {
    const Instruction& instr = *inst_iter;
    const _DInst& repr = instr.representation();

    // Do not allow any references to a basic block.
    const BasicBlockReferenceMap& references = instr.references();
    BasicBlockReferenceMap::const_iterator ref = references.begin();
    for (; ref != references.end(); ++ref) {
      if (ref->second.referred_type() ==
          BasicBlockReference::REFERRED_TYPE_BASIC_BLOCK) {
        return false;
      }
    }

    // Return instruction is valid.
    if (instr.IsReturn()) {
      // Match return with or without a constant.
      if (repr.ops[0].type == O_NONE) {
        *kind = kReturnMatch;
      } else if (repr.ops[0].type == O_IMM) {
        *kind = kReturnConstantMatch;
        *return_constant = repr.imm.dword;
      } else {
        return false;
      }

      // Move to the next instruction and leave loop. This instruction must be
      // the last one in the basic block.
      ++inst_iter;
      break;
    }

    // Match an indirect jump from a global variable.
    BasicBlockReference target_ref;
    if (instr.IsBranch() &&
        instr.references().size() == 1 &&
        instr.FindOperandReference(0, &target_ref) &&
        target_ref.block() != NULL &&
        repr.opcode == I_JMP &&
        repr.ops[0].type  == O_DISP &&
        repr.ops[0].size == 32 &&
        repr.ops[0].index == 0) {
      // Match displacement to a block.
      *kind = kIndirectTrampolineMatch;
      *reference = target_ref;

      // Move to the next instruction and leave loop. This instruction must be
      // the last one in the basic block.
      ++inst_iter;
      break;
    }

    // Avoid control flow instructions.
    if (instr.IsControlFlow())
      return false;

    // Avoid unsafe stack manipulation.
    if (repr.opcode == I_PUSH &&
        (repr.ops[0].type == O_IMM ||
         repr.ops[0].type == O_IMM1 ||
         repr.ops[0].type == O_IMM2)) {
      // Pushing a constant is valid.
      stack_depth += 4;
    } else if (repr.opcode == I_PUSH &&
               repr.ops[0].type == O_REG &&
               repr.ops[0].index != R_EBP &&
               repr.ops[0].index != R_ESP) {
      // Pushing a register is valid.
      stack_depth += 4;
    } else if (repr.opcode == I_POP &&
               repr.ops[0].type == O_REG &&
               repr.ops[0].index != R_EBP &&
               repr.ops[0].index != R_ESP &&
               stack_depth >= 4) {
      // Popping a register is valid.
      stack_depth -= 4;
    } else {
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
  }

  // All instructions must have been checked.
  if (inst_iter != bb->instructions().end())
    return false;

  if (*kind == kInvalidMatch) {
    // Try to match a tail-call to an other block.
    if (bb->successors().size() != 1 ||
        bb->successors().front().condition() != Successor::kConditionTrue) {
      return false;
    }

    // Must match a valid reference to a block.
    const Successor& succ = bb->successors().front();
    const BasicBlockReference& ref = succ.reference();
    if (ref.block() == NULL)
      return false;

    // Matched a direct trampoline.
    *kind = kDirectTrampolineMatch;
    *reference = ref;
  } else {
    // The basic block must have a return (to remove the caller address on
    // stack) or be an indirect tail-call to an other block and must not have
    // successors.
    if (!bb->successors().empty())
      return false;
  }

  // Returns the matched body.
  DCHECK_NE(kInvalidMatch, *kind);
  *body = bb;
  return true;
}

// Copy the body of the callee at a call-site in the caller.
// @param kind The kind of inlining to perform.
// @param return_constant The number of bytes to pop from the stack.
// @param reference The reference to the continuation.
// @param body The trivial body to be inlined.
// @param target The place where to insert the callee body into the caller.
// @param instructions The caller body that receives a copy of the callee body.
// @returns true on success, false otherwise.
bool InlineTrivialBody(MatchKind kind,
                       size_t return_constant,
                       const BasicBlockReference& reference,
                       const BasicCodeBlock* body,
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

    if (instr.IsBranch()) {
      // Skip the indirect branch instruction.
      DCHECK_EQ(kind, kIndirectTrampolineMatch);
    } else if (instr.IsReturn()) {
      // Nothing to do here with return instruction (see below).
    } else {
      new_body.push_back(instr);
    }
  }

  // Replacing the return or the tail-call instruction.
  BasicBlockAssembler assembler(target, instructions);
  switch (kind) {
    case kReturnMatch:
      break;
    case kReturnConstantMatch:
      // Replace a 'ret 4' instruction by a 'lea %esp, [%esp + 0x4]'.
      // Instruction add cannot be used because flags must be preserved,
      assembler.lea(core::esp,
                    Operand(core::esp, Displacement(return_constant)));
      break;
    case kDirectTrampolineMatch:
      DCHECK(reference.IsValid());
      assembler.call(
          Immediate(reference.block(), reference.offset(), reference.base()));
      break;
    case kIndirectTrampolineMatch:
      DCHECK(reference.IsValid());
      assembler.call(Operand(Displacement(reference.block(),
                                          reference.offset(),
                                          reference.base())));
      break;
    default:
      NOTREACHED();
  }

  // Insert the inlined instructions at the call-site.
  instructions->splice(target, new_body);
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

}  // namespace

const char InliningTransform::kTransformName[] = "InlineBasicBlockTransform";

InliningTransform::InliningTransform(ApplicationProfile* profile)
    : profile_(profile) {
  DCHECK_NE(reinterpret_cast<ApplicationProfile*>(NULL), profile);
}

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
  if (!policy->BlockIsSafeToBasicBlockDecompose(caller))
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
          !policy->BlockIsSafeToBasicBlockDecompose(callee)) {
        continue;
      }

      if (MatchEmptyBody(callee)) {
        // Body is empty, remove call-site.
        bb->instructions().erase(call_iter);
        continue;
      }

      if (MatchGetProgramCounter(callee)) {
        // TODO(etienneb): Implement Get Program Counter with a fixup.
        continue;
      }

      // For a small callee, try to replace callee instructions in-place.
      // Add one byte to take into account the return instruction.
      if (callee->size() <= instr.size() + 1) {
        BasicBlockSubGraph* callee_subgraph;
        size_t return_constant = 0;
        BasicCodeBlock* body = NULL;
        BasicBlockReference target;
        MatchKind match_kind = kInvalidMatch;

        // Look in the subgraph cache for an already decomposed subgraph.
        SubGraphCache::iterator look = subgraph_cache_.find(callee);
        if (look != subgraph_cache_.end()) {
          callee_subgraph = &look->second;
        } else {
          // Not in cache, decompose it.
          callee_subgraph = &subgraph_cache_[callee];
          if (!DecomposeToBasicBlock(callee, callee_subgraph)) {
            subgraph_cache_.erase(callee);
            continue;
          }
        }

        if (MatchTrivialBody(*callee_subgraph, &match_kind, &return_constant,
                             &target, &body) &&
            InlineTrivialBody(match_kind, return_constant, target, body,
                              call_iter, &bb->instructions())) {
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
