// Copyright 2012 Google Inc.
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
// Implements the Basic-Block Graph representation and APIs.
//
// Some notes on inverting the instructions that don't have a complement
// in the instruction set.
//
// JCXZ/JECXZ:
//     The simplest might be to punt and not actually invert,
//     but trampoline. Otherwise, a truly inverted instruction sequence
//     would be something like.
//
//         pushfd
//         cmp ecx, 0  ; Change to ecx as appropriate.
//         jnz fall-through
//       original-branch-target
//         popfd
//         ...
//
//       fall-through;
//         popfd
//         ...
//
//     Note that popfd is prepended to the instruction sequences of both
//     fall-through and original-branch-target. To represent this we
//     should introduce JCXNZ and JECXNZ pseudo-instructions to represent
//     this transformation, to allow the inversion to be reversible.
//
// LOOP/LOOPE/LOOPZ/LOOPNE/LOOPNZ:
//     The simplest would be to punt and not actually invert, but trampoline.
//     Otherwise, a truly inverted instruction sequence would be something
//     like (taking LOOPNZ/LOOPNE as an example)...
//
//         pushfd
//         jnz pre-fall-through  ; Switch to jz for LOOPZ, omit for LOOP.
//         dec cx
//         jnz fall-through
//       original-branch-target:
//         popfd
//         ...
//
//       pre-fall-through:
//         dec cx  ; Omit for LOOP.
//       fall-through:
//         popfd
//         ...
//
//     Note that popfd is prepended onto the instruction sequences of both
//     fall-through and original-branch-target. To represent this we
//     should introduce pesudo instructions to represent each inversion,
//     which would allow the inversion to be reversible.

#include "syzygy/block_graph/basic_block.h"

#include <algorithm>
#include <ostream>

#include "base/stringprintf.h"
#include "mnemonics.h"  // NOLINT

namespace block_graph {

namespace {

bool IsUnconditionalBranch(const Instruction& inst) {
  return META_GET_FC(inst.representation().meta) == FC_UNC_BRANCH;
}

bool IsConditionalBranch(const Instruction& inst) {
  return META_GET_FC(inst.representation().meta) == FC_CND_BRANCH;
}

}  // namespace

BasicBlockReference::BasicBlockReference()
    : referred_type_(REFERRED_TYPE_UNKNOWN),
      reference_type_(BlockGraph::RELATIVE_REF),
      size_(0),
      referred_(NULL),
      offset_(-1) {
}

BasicBlockReference::BasicBlockReference(ReferenceType type,
                                         Size size,
                                         Block* block,
                                         Offset offset)
    : referred_type_(REFERRED_TYPE_BLOCK),
      reference_type_(type),
      size_(size),
      referred_(block),
      offset_(offset) {
  DCHECK(type > REFERRED_TYPE_UNKNOWN && type < MAX_REFERRED_TYPE);
  DCHECK(size == 1 || size == 2 || size == 4);
  DCHECK(block != NULL);
  DCHECK(offset >= 0);
}

BasicBlockReference::BasicBlockReference(ReferenceType type,
                                         Size size,
                                         BasicBlock* basic_block,
                                         Offset offset)
    : referred_type_(REFERRED_TYPE_BASIC_BLOCK),
      reference_type_(type),
      size_(size),
      referred_(basic_block),
      offset_(offset) {
  DCHECK(type > REFERRED_TYPE_UNKNOWN && type < MAX_REFERRED_TYPE);
  DCHECK(size == 1 || size == 2 || size == 4);
  DCHECK(basic_block != NULL);
  DCHECK(offset >= 0);
}

BasicBlockReference::BasicBlockReference(const BasicBlockReference& other)
    : referred_type_(other.referred_type_),
      reference_type_(other.reference_type_),
      size_(other.size_),
      referred_(other.referred_),
      offset_(other.offset_) {
}

BasicBlockReferrer::BasicBlockReferrer()
    : referrer_type_(REFERRER_TYPE_UNKNOWN),
      referrer_(NULL),
      offset_(-1) {
}

BasicBlockReferrer::BasicBlockReferrer(BasicBlock* basic_block, Offset offset)
    : referrer_type_(REFERRER_TYPE_BASIC_BLOCK),
      referrer_(basic_block),
      offset_(offset) {
  DCHECK(basic_block != NULL);
  DCHECK(offset >= 0);
}

BasicBlockReferrer::BasicBlockReferrer(Block* block, Offset offset)
    : referrer_type_(REFERRER_TYPE_BLOCK),
      referrer_(block),
      offset_(offset) {
  DCHECK(block != NULL);
  DCHECK(offset >= 0);
}

BasicBlockReferrer::BasicBlockReferrer(const BasicBlockReferrer& other)
    : referrer_type_(other.referrer_type_),
      referrer_(other.referrer_),
      offset_(other.offset_) {
}


Instruction::Instruction(const Instruction::Representation& value,
                         Offset offset,
                         Size size)
    : representation_(value), offset_(offset), size_(size) {
}

bool Instruction::InvertConditionalBranchOpcode(uint16* opcode) {
  DCHECK(opcode != NULL);

  switch (*opcode) {
    default:
      LOG(ERROR) << GET_MNEMONIC_NAME(*opcode) << " is not invertible.";
      return false;

    case I_JA:  // Equivalent to JNBE.
      *opcode = I_JBE;
      return true;

    case I_JAE:  // Equivalent to JNB and JNC.
      *opcode = I_JB;
      return true;

    case I_JB:  // Equivalent to JNAE and JC.
      *opcode = I_JAE;
      return true;

    case I_JBE:  // Equivalent to JNA.
      *opcode = I_JA;
      return true;

    case I_JCXZ:
    case I_JECXZ:
      // TODO(rogerm): Inverting these is not quite as simple as inverting
      //     the others. The simplest might be to punt and not actually invert,
      //     but trampoline. Otherwise, a truly inverted instruction sequence
      //     would be something like.
      //
      //         pushfd
      //         cmp ecx, 0  ; Change to ecx as appropriate.
      //         jnz fall-through
      //       original-branch-target
      //         popfd
      //         ...
      //
      //       fall-through;
      //         popfd
      //         ...
      //
      //     Note that popfd is prepended to the instruction sequences of both
      //     fall-through and original-branch-target. To represent this we
      //     should introduce JCXNZ and JECXNZ pseudo-instructions to represent
      //     this transformation, to allow the inversion to be reversible.
      LOG(ERROR) << "Inversion of " << GET_MNEMONIC_NAME(*opcode)
                 << " is not supported.";
      return false;

    case I_JG:  // Equivalent to JNLE.
      *opcode = I_JLE;
      return true;

    case I_JGE:  // Equivalent to JNL.
      *opcode = I_JL;
      return true;

    case I_JL:  // Equivalent to I_JNGE.
      *opcode = I_JGE;
      return true;

    case I_JLE:  // Equivalent to JNG.
      *opcode = I_JG;
      return true;

    case I_JNO:
      *opcode = I_JO;
      return true;

    case I_JNP:  // Equivalent to JPO.
      *opcode = I_JP;
      return true;

    case I_JNS:
      *opcode = I_JS;
      return true;

    case I_JNZ:  // Equivalent to JNE.
      *opcode = I_JZ;
      return true;

    case I_JO:
      *opcode = I_JNO;
      return true;

    case I_JP:  // Equivalent to JPE.
      *opcode = I_JNP;
      return true;

    case I_JS:
      *opcode = I_JNS;
      return true;

    case I_JZ:  // Equivalent to JE.
      *opcode = I_JNZ;
      return true;

    case I_LOOP:
    case I_LOOPNZ:  // Equivalent to LOOPNE.
    case I_LOOPZ:  // Equivalent to LOOPE
      // TODO(rogerm): Inverting these is not quite as simple as inverting
      //     the others. The simplest would be to punt and not actually invert,
      //     but trampoline. Otherwise, a truly inverted instruction sequence
      //     would be something like, for Inverse(LOOPNZ), ...
      //
      //         pushfd
      //         jnz pre-fall-through  ; Switch to jz for LOOPZ, omit for LOOP.
      //         dec cx
      //         jnz fall-through
      //       original-branch-target:
      //         popfd
      //         ...
      //
      //       pre-fall-through:
      //         dec cx  ; Omit for LOOP.
      //       fall-through:
      //         popfd
      //         ...
      //
      //     Note that popfd is prepended onto the instruction sequences of both
      //     fall-through and original-branch-target. To represent this we
      //     should introduce pesudo instructions to represent each inversion,
      //     which would allow the inversion to be reversible.
      LOG(ERROR) << "Inversion of " << GET_MNEMONIC_NAME(*opcode)
                 << " is not supported.";
      return false;
  }
}

Successor::Condition Successor::OpCodeToCondition(Successor::OpCode op_code) {
  switch (op_code) {
    default:
      LOG(ERROR) << GET_MNEMONIC_NAME(op_code) << " is not a branch.";
      return kInvalidCondition;

    case I_JA:  // Equivalent to JNBE.
      return kConditionAbove;

    case I_JAE:  // Equivalent to JNB and JNC.
      return kConditionAboveOrEqual;

    case I_JB:  // Equivalent to JNAE and JC.
      return kConditionBelow;

    case I_JBE:  // Equivalent to JNA.
      return kConditionBelowOrEqual;

    case I_JCXZ:
    case I_JECXZ:
      return kCounterIsZero;

    case I_JG:  // Equivalent to JNLE.
      return kConditionGreater;

    case I_JGE:  // Equivalent to JNL.
      return kConditionGreaterOrEqual;

    case I_JL:  // Equivalent to I_JNGE.
      return kConditionLess;

    case I_JLE:  // Equivalent to JNG.
      return kConditionLessOrEqual;

    case I_JMP:
      return kConditionTrue;

    case I_JNO:
      return kConditionNotOverflow;

    case I_JNP:  // Equivalent to JPO.
      return kConditionNotParity;

    case I_JNS:
      return kConditionNotSigned;

    case I_JNZ:  // Equivalent to JNE.
      return kConditionNotEqual;

    case I_JO:
      return kConditionOverflow;

    case I_JP:  // Equivalent to JPE.
      return kConditionParity;

    case I_JS:
      return kConditionSigned;

    case I_JZ:  // Equivalent to JE.
      return kConditionEqual;

    case I_LOOP:
      return kLoopTrue;

    case I_LOOPNZ:  // Equivalent to LOOPNE.
      return kLoopIfNotEqual;

    case I_LOOPZ:  // Equivalent to LOOPE.
      return kLoopIfEqual;
  }
}

Successor::Successor() : condition_(kInvalidCondition), offset_(-1), size_(0) {
}

Successor::Successor(Successor::Condition type,
                     Successor::AbsoluteAddress target,
                     Offset offset,
                     Size size)
    : condition_(type),
      original_target_address_(target),
      offset_(offset),
      size_(size) {
  DCHECK(condition_ != kInvalidCondition);
}

Successor::Successor(Successor::Condition type,
                     const BasicBlockReference& target,
                     Offset offset,
                     Size size)
    : condition_(type),
      branch_target_(target),
      offset_(offset),
      size_(size) {
  DCHECK(condition_ != kInvalidCondition);
  DCHECK(branch_target_.IsValid());
}

Successor::Condition Successor::InvertCondition(
    Successor::Condition condition) {
  static const Condition kConditionInversionTable[] = {
      // Note that these must match the order specified in the Condition
      // enumeration (see basic_block.h).
      /* kInvalidBranchType */  kInvalidCondition,
      /* kConditionTrue */  kInvalidCondition,
      /* kConditionAbove */  kConditionBelowOrEqual,
      /* kConditionAboveOrEqual */ kConditionBelow,
      /* kConditionBelow */  kConditionAboveOrEqual,
      /* kConditionBelowOrEqual */  kConditionAbove,
      /* kConditionEqual */  kConditionNotEqual,
      /* kConditionGreater */  kConditionLessOrEqual,
      /* kConditionGreaterOrEqual */  kConditionLess,
      /* kConditionLess */  kConditionGreaterOrEqual,
      /* kConditionLessOrEqual */  kConditionGreater,
      /* kConditionNotEqual */  kConditionEqual,
      /* kConditionNotOverflow */  kConditionOverflow,
      /* kConditionNotParity */  kConditionParity,
      /* kConditionNotSigned */  kConditionSigned,
      /* kConditionOverflow */  kConditionNotOverflow,
      /* kConditionParity */  kConditionNotParity,
      /* kConditionSigned */  kConditionNotSigned,
      /* kCounterIsZero */  kInverseCounterIsZero,
      /* kLoopTrue */  kInverseLoopTrue,
      /* kLoopIfEqual */  kInverseLoopIfEqual,
      /* kLoopIfNotEqual */  kInverseLoopIfNotEqual,
      /* kInverseCounterIsZero */ kCounterIsZero,
      /* kInverseLoop */  kLoopTrue,
      /* kInverseLoopIfEqual */  kLoopIfEqual,
      /* kInverseLoopIfNotEqual */ kLoopIfNotEqual,
  };

  COMPILE_ASSERT(arraysize(kConditionInversionTable) == kMaxCondition,
                 unexpected_number_of_inversion_table_entries);

  if (condition < 0 || condition >= kMaxCondition)
    return kInvalidCondition;

  return kConditionInversionTable[condition];
}

BasicBlock::BasicBlock(BasicBlock::BlockId id,
                       const base::StringPiece& name,
                       BasicBlock::BlockType type,
                       BasicBlock::Offset offset,
                       BasicBlock::Size size,
                       const uint8* data )
    : id_(id),
      name_(name.begin(), name.end()),
      type_(type),
      offset_(offset),
      size_(size),
      data_(data) {
  DCHECK((offset < 0 && size == 0) || (offset >= 0 && size > 0));
  DCHECK(data != NULL);
}

bool BasicBlock::IsValid() const {
  if (type() == BlockGraph::BASIC_DATA_BLOCK)
    return true;

  if (type() != BlockGraph::BASIC_CODE_BLOCK)
    return false;

#ifndef NDEBUG
  Instructions::const_iterator it = instructions().begin();
  for (; it != instructions().end(); ++it) {
    if (IsConditionalBranch(*it) || IsUnconditionalBranch(*it))
      return false;
  }
#endif

  switch (successors_.size()) {
    case 0:
      // If the basic code block has no successors, we expect that it would
      // have instructions; otherwise, it doesn't need to exist. We would
      // also expect that it ends in control-flow change that we can't
      // necessarily trace statically (ie., RET or computed jump).
      // TODO(rogerm): Validate that this is really true?
      return instructions().size() != 0 &&
          (instructions().back().representation().opcode == I_RET ||
           instructions().back().representation().opcode == I_JMP);

    case 1:
      // A basic code block having exactly one successor implies that the
      // successor is unconditional.
      return successors().front().condition() == Successor::kConditionTrue;

    case 2:
      // A basic code block having exactly two successors implies that each
      // successor is the inverse of the other.
      return successors().front().condition() ==
          Successor::InvertCondition(successors().back().condition());

    default:
      // Any other number of successors implies that the data is borked.
      NOTREACHED();
      return false;
  }
}

}  // namespace block_graph
