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
#include "syzygy/core/assembler.h"
#include "syzygy/core/disassembler_util.h"

#include "mnemonics.h"  // NOLINT

namespace block_graph {

namespace {

 // A list of printable names corresponding to basic block types. This needs to
// be kept in sync with the BasicBlock::BasicBlockType enum!
const char* kBasicBlockType[] = {
  "BASIC_CODE_BLOCK",
  "BASIC_DATA_BLOCK",
  "BASIC_PADDING_BLOCK",
};

COMPILE_ASSERT(arraysize(kBasicBlockType) == BasicBlock::BASIC_BLOCK_TYPE_MAX,
               kBasicBlockType_not_in_sync);

bool IsUnconditionalBranch(const Instruction& inst) {
  return META_GET_FC(inst.representation().meta) == FC_UNC_BRANCH;
}

bool IsConditionalBranch(const Instruction& inst) {
  return META_GET_FC(inst.representation().meta) == FC_CND_BRANCH;
}

template<typename T>
bool UpdateBasicBlockReferenceMap(T* object,
                                  BasicBlock::BasicBlockReferenceMap* ref_map,
                                  BasicBlock::Offset offset,
                                  const BasicBlockReference& ref) {
  DCHECK(object != NULL);
  DCHECK(ref_map != NULL);
  DCHECK(ref.IsValid());
  DCHECK_LE(BasicBlock::kNoOffset, offset);
  DCHECK_LE(offset + ref.size(), object->GetMaxSize());

  typedef BasicBlock::BasicBlockReferenceMap::iterator Iterator;

  // Attempt to perform the insertion, returning the insert location and
  // whether or not the value at the insert location has been set to ref.
  std::pair<Iterator, bool> result =
      ref_map->insert(std::make_pair(offset, ref));

#ifndef NDEBUG
  // Validate no overlap with the previous reference, if any.
  if (result.first != ref_map->begin()) {
   Iterator prev(result.first);
    --prev;
    DCHECK_GE(static_cast<BasicBlock::Size>(offset),
              prev->first + prev->second.size());
  }

  // Validate no overlap with the next reference, if any.
  Iterator next(result.first);
  ++next;
  DCHECK(next == ref_map->end() ||
         static_cast<BasicBlock::Size>(next->first) >= offset + ref.size());
#endif

  // If the value wasn't actually inserted, then update it.
  if (!result.second) {
    BasicBlockReference& old = result.first->second;
    DCHECK_EQ(old.size(), ref.size());
    DCHECK_EQ(old.reference_type(), ref.reference_type());
    old = ref;
  }

  return result.second;
}

}  // namespace

BasicBlockReference::BasicBlockReference()
    : referred_type_(REFERRED_TYPE_UNKNOWN),
      reference_type_(BlockGraph::RELATIVE_REF),
      size_(0),
      referred_block_(NULL),
      offset_(BasicBlock::kNoOffset),
      base_(BasicBlock::kNoOffset) {
}


BasicBlockReference::BasicBlockReference(ReferenceType type,
                                         Size size,
                                         Block* block,
                                         Offset offset,
                                         Offset base)
    : referred_type_(REFERRED_TYPE_BLOCK),
      reference_type_(type),
      size_(size),
      referred_block_(block),
      offset_(offset),
      base_(base) {
  DCHECK(size == 1 || size == 2 || size == 4);
  DCHECK(block != NULL);
  DCHECK_LE(0, base);
  DCHECK_LT(static_cast<size_t>(base), block->size());
}

BasicBlockReference::BasicBlockReference(ReferenceType type,
                                         Size size,
                                         BasicBlock* basic_block)
    : referred_type_(REFERRED_TYPE_BASIC_BLOCK),
      reference_type_(type),
      size_(size),
      referred_basic_block_(basic_block),
      offset_(0),
      base_(0) {
  DCHECK(size == 1 || size == 4);
  DCHECK(basic_block != NULL);
}

BasicBlockReference::BasicBlockReference(ReferenceType type,
                                         Size size,
                                         const BasicBlockReference& ref)
    : referred_type_(ref.referred_type_),
      reference_type_(type),
      size_(size),
      referred_block_(ref.referred_block_),
      offset_(ref.offset_),
      base_(ref.base_) {
  DCHECK(size == 1 || size == 4);
}

BasicBlockReference::BasicBlockReference(const BasicBlockReference& other)
    : referred_type_(other.referred_type_),
      reference_type_(other.reference_type_),
      size_(other.size_),
      referred_block_(other.referred_block_),
      offset_(other.offset_),
      base_(other.base_) {
}

BasicBlockReferrer::BasicBlockReferrer()
    : referrer_(NULL),
      offset_(BasicBlock::kNoOffset) {
}

BasicBlockReferrer::BasicBlockReferrer(const Block* block, Offset offset)
    : referrer_(block),
      offset_(offset) {
  DCHECK(block != NULL);
  DCHECK_GE(offset, 0);
}

BasicBlockReferrer::BasicBlockReferrer(const BasicBlockReferrer& other)
    : referrer_(other.referrer_),
      offset_(other.offset_) {
}

bool BasicBlockReferrer::IsValid() const {
  if (referrer_ == NULL)
    return false;

  return offset_ >= 0;
}

Instruction::Instruction(const Instruction::Representation& value,
                         SourceRange source_range,
                         Size size,
                         const uint8* data)
    : representation_(value),
      source_range_(source_range),
      size_(size),
      data_(data),
      owns_data_(false),
      offset_(BasicBlock::kNoOffset) {
  DCHECK(data != NULL);
  DCHECK_LT(0U, size);
  DCHECK_GE(core::AssemblerImpl::kMaxInstructionLength, size);
}

Instruction::Instruction(Size size, const uint8* data)
    : size_(0), data_(NULL), owns_data_(false), offset_(BasicBlock::kNoOffset) {
  DCHECK(data != NULL);
  DCHECK_LT(0U, size);
  DCHECK_GE(core::AssemblerImpl::kMaxInstructionLength, size);

  CHECK(core::DecodeOneInstruction(data, size, &representation_));

  uint8* new_data = new uint8[size];
  memcpy(new_data, data, size);
  data_ = new_data;
  size_ = size;
  owns_data_ = true;
}

Instruction::Instruction(const Instruction& other)
    : representation_(other.representation_),
      references_(other.references_),
      source_range_(other.source_range_),
      size_(other.size_),
      data_(other.data_),
      owns_data_(other.owns_data_),
      label_(other.label_),
      offset_(BasicBlock::kNoOffset) {
  if (owns_data_) {
    uint8* new_data = new uint8[size_];
    memcpy(new_data, data_, size_);
    data_ = new_data;
  }
}

Instruction::~Instruction() {
  if (owns_data_)
    delete [] data_;
}

bool Instruction::CallsNonReturningFunction() const {
  // Is this a call instruction?
  if (META_GET_FC(representation_.meta) != FC_CALL)
    return false;

  // Is the target something we can follow?
  uint8 operand_type = representation_.ops[0].type;
  if (operand_type != O_PC && operand_type != O_DISP)
    return false;

  // Get the reference.
  DCHECK_EQ(1U, references_.size());
  const BasicBlockReference& ref = references_.begin()->second;

  // This can happen if  the call is recursive to the currently decomposed
  // function calling ourselves. In this case the reference will be to another
  // basic-block that is a part of the same parent block.
  if (ref.block() == NULL) {
    DCHECK(ref.basic_block() != NULL);
    return false;
  }

  // Check whether the referenced block is a non-returning function.
  DCHECK_EQ(ref.offset(), ref.base());
  DCHECK_EQ(BlockGraph::Reference::kMaximumSize, ref.size());
  if (!CallsNonReturningFunction(representation_, ref.block(), ref.offset()))
    return false;

  // If we got here, then this is a non-returning call.
  return true;
}

bool Instruction::SetReference(Offset offset, const BasicBlockReference& ref) {
  return UpdateBasicBlockReferenceMap(this, &references_, offset, ref);
}

bool Instruction::FindOperandReference(size_t operand_index,
                                       BasicBlockReference* reference) const {
  DCHECK(reference != NULL);

  // We walk backwards through the operands, and back up the operand
  // location by the size of each operand, until we're at ours.
  size_t operand_location = representation_.size;
  size_t i = 0;
  for (i = arraysize(representation_.ops); i != operand_index; --i) {
    switch (representation_.ops[i - 1].type) {
      case O_NONE:
      case O_REG:
        break;

      case O_IMM:
      case O_IMM1:
      case O_IMM2:
      case O_PTR:
      case O_PC:
        operand_location -= representation_.ops[i - 1].size / 8;
        break;

      case O_SMEM:
      case O_MEM:
      case O_DISP:
        operand_location -= representation_.dispSize / 8;
        break;
    }
  }
  DCHECK_EQ(i, operand_index);

  Instruction::BasicBlockReferenceMap::const_iterator
      it(references_.find(operand_location));

  if (it != references_.end()) {
    *reference = it->second;
    return true;
  }

  return false;
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

bool Instruction::CallsNonReturningFunction(const Representation& inst,
                                            const BlockGraph::Block* target,
                                            Offset offset) {
  DCHECK_EQ(FC_CALL, META_GET_FC(inst.meta));
  DCHECK(inst.ops[0].type == O_PC || inst.ops[0].type == O_DISP);
  DCHECK(target != NULL);
  if (inst.ops[0].type == O_DISP) {
    DCHECK(target->type() == BlockGraph::DATA_BLOCK);

    // There need not always be a reference here. This could be to a data
    // block whose contents will be filled in at runtime.
    BlockGraph::Reference ref;
    if (!target->GetReference(offset, &ref))
      return false;

    target = ref.referenced();

    // If this is a relative reference it must be to a data block (it's a PE
    // parsed structure pointing to an import name thunk). If it's absolute
    // then it must be pointing to a code block.
    DCHECK((ref.type() == BlockGraph::RELATIVE_REF &&
                target->type() == BlockGraph::DATA_BLOCK) ||
           (ref.type() == BlockGraph::ABSOLUTE_REF &&
                target->type() == BlockGraph::CODE_BLOCK));
  }

  if ((target->attributes() & BlockGraph::NON_RETURN_FUNCTION) == 0)
    return false;

  return true;
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

Successor::Successor()
    : condition_(kInvalidCondition),
      bb_target_offset_(BasicBlock::kNoOffset),
      instruction_offset_(BasicBlock::kNoOffset),
      instruction_size_(0) {
}

Successor::Successor(Successor::Condition type,
                     Offset bb_target_offset,
                     Offset instruction_offset,
                     Size instruction_size)
    : condition_(type),
      bb_target_offset_(bb_target_offset),
      instruction_offset_(instruction_offset),
      instruction_size_(instruction_size) {
  DCHECK(condition_ != kInvalidCondition);
}

Successor::Successor(Successor::Condition condition,
                     const BasicBlockReference& target,
                     Offset instruction_offset,
                     Size instruction_size)
    : condition_(condition),
      bb_target_offset_(BasicBlock::kNoOffset),
      instruction_offset_(instruction_offset),
      instruction_size_(instruction_size) {
  DCHECK(condition != kInvalidCondition);
  bool inserted = SetReference(target);
  DCHECK(inserted);
}

Successor::Successor(const Successor& other)
    : condition_(other.condition_),
      bb_target_offset_(other.bb_target_offset_),
      reference_(other.reference_),
      instruction_offset_(other.instruction_offset_),
      source_range_(other.source_range_),
      instruction_size_(other.instruction_size_),
      label_(other.label_) {
}

BasicBlockReference Successor::reference() const {
  return reference_;
}

Successor::Condition Successor::InvertCondition(Condition cond) {
  DCHECK_LT(kInvalidCondition, cond);
  DCHECK_LE(kMinConditionalBranch, cond);
  DCHECK_GT(kMaxCondition, cond);

  // The conditional branches correspond exactly to those from core::Assembler.
  if (cond <= kMaxConditionalBranch) {
    return static_cast<Condition>(
        core::NegateConditionCode(static_cast<core::ConditionCode>(cond)));
  }

  // The extra ones we have to map ourselves.
  static const size_t kTableSize = kMaxCondition - kMaxConditionalBranch;
  static const Condition kConditionInversionTable[kTableSize] = {
      /* kConditionTrue */  kInvalidCondition,
      /* kCounterIsZero */  kInverseCounterIsZero,
      /* kLoopTrue */  kInverseLoopTrue,
      /* kLoopIfEqual */  kInverseLoopIfEqual,
      /* kLoopIfNotEqual */  kInverseLoopIfNotEqual,
      /* kInverseCounterIsZero */ kCounterIsZero,
      /* kInverseLoop */  kLoopTrue,
      /* kInverseLoopIfEqual */  kLoopIfEqual,
      /* kInverseLoopIfNotEqual */ kLoopIfNotEqual,
  };

  return kConditionInversionTable[cond - kMaxConditionalBranch - 1];
}

Successor::Size Successor::GetMaxSize() const {
  // TODO(rogerm): Update this to return the actual number of bytes needed to
  //     synthesize condition_. In particular, take care of multi-instruction
  //     inverse cases: kInverseCounterIsZero and kInverseLoop*.
  return core::AssemblerImpl::kMaxInstructionLength;
}

bool Successor::SetReference(const BasicBlockReference& ref) {
  bool inserted = !reference_.IsValid();
  reference_ = ref;
  return inserted;
}

const BasicBlock::Offset BasicBlock::kNoOffset = -1;

BasicBlock::BasicBlock(BasicBlock::BlockId id,
                       const base::StringPiece& name,
                       BasicBlock::BasicBlockType type,
                       BasicBlock::Size size,
                       const uint8* data)
    : id_(id),
      name_(name.begin(), name.end()),
      type_(type),
      size_(size),
      data_(data) {
  DCHECK(data != NULL || size == 0);
  DCHECK(type == BASIC_CODE_BLOCK || size > 0);
}

const char* BasicBlock::BasicBlockTypeToString(
    BasicBlock::BasicBlockType type) {
  DCHECK_LE(BasicBlock::BASIC_CODE_BLOCK, type);
  DCHECK_GT(BasicBlock::BASIC_BLOCK_TYPE_MAX, type);
  return kBasicBlockType[type];
}

bool BasicBlock::IsValid() const {
  if (type() == BasicBlock::BASIC_DATA_BLOCK ||
      type() == BasicBlock::BASIC_PADDING_BLOCK) {
    return true;
  }

  if (type() != BasicBlock::BASIC_CODE_BLOCK)
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

BasicBlock::Size BasicBlock::GetDataSize() const {
  // If it's a data or padding basic-block, then we have the size on hand.
  if (type_ != BASIC_CODE_BLOCK)
    return size_;

  // Otherwise, we must tally the size of the instructions.
  Size data_size = 0;
  Instructions::const_iterator instr_iter = instructions_.begin();
  for (; instr_iter != instructions_.end(); ++instr_iter)
    data_size += instr_iter->size();

  return data_size;
}

BasicBlock::Size BasicBlock::GetMaxSize() const {
  // If it's a data or padding basic-block, then we have its exact size.
  if (type_ != BASIC_CODE_BLOCK)
    return size_;

  // Otherwise, we must account for the instructions and successors.
  size_t max_size = 0;

  Instructions::const_iterator instr_iter = instructions_.begin();
  for (; instr_iter != instructions_.end(); ++instr_iter)
    max_size += instr_iter->GetMaxSize();

  Successors::const_iterator succ_iter = successors_.begin();
  for (; succ_iter != successors_.end(); ++succ_iter)
    max_size += succ_iter->GetMaxSize();

  return max_size;
}

bool BasicBlock::SetReference(Offset offset, const BasicBlockReference& ref) {
  DCHECK_NE(BasicBlock::BASIC_CODE_BLOCK, type_);
  return UpdateBasicBlockReferenceMap(this, &references_, offset, ref);
}

}  // namespace block_graph
