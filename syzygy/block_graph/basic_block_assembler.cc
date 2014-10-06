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
#include "syzygy/block_graph/basic_block_assembler.h"

namespace block_graph {

namespace {

typedef assm::DisplacementImpl DisplacementImpl;
typedef assm::OperandImpl OperandImpl;
typedef assm::ValueImpl ValueImpl;
typedef assm::ValueSize ValueSize;

ValueSize ValueSizeFromConstant(uint32 input_value) {
  // IA32 assembly may/will sign-extend 8-bit literals, so we attempt to encode
  // in 8 bits only those literals whose value will be unchanged by that
  // treatment.
  input_value |= 0x7F;

  if (input_value == 0xFFFFFFFF || input_value == 0x7F)
    return assm::kSize8Bit;

  return assm::kSize32Bit;
}

ValueImpl CopyValue(const UntypedReference* ref,
                    const assm::ValueImpl& value) {
  return ValueImpl(value.value(),
                   value.size(),
                   value.reference() ? ref : NULL);
}

size_t ToBytes(assm::ValueSize size) {
  switch (size) {
    case assm::kSize8Bit: return 1;
    case assm::kSize32Bit: return 4;
  }
  NOTREACHED();
  return 0;
}

// Completes a UntypedReference, converting it to a BasicBlockReference
// using the provided type and size information.
// @param ref_info The type and size information to use.
// @param untyped_ref The untyped reference to be completed.
// @returns the equivalent BasicBlockReference.
BasicBlockReference CompleteUntypedReference(
    BlockGraph::ReferenceType type,
    size_t size,
    const UntypedReference& untyped_ref) {
  DCHECK(untyped_ref.IsValid());

  if (untyped_ref.referred_type() ==
          BasicBlockReference::REFERRED_TYPE_BLOCK) {
    DCHECK(untyped_ref.block() != NULL);
    return BasicBlockReference(type, size, untyped_ref.block(),
                               untyped_ref.offset(), untyped_ref.base());
  }

  DCHECK_EQ(BasicBlockReference::REFERRED_TYPE_BASIC_BLOCK,
            untyped_ref.referred_type());
  DCHECK(untyped_ref.basic_block() != NULL);
  return BasicBlockReference(type, size, untyped_ref.basic_block());
}

}  // namespace

Value::Value() {
}

Value::Value(uint32 value) : Super(value, ValueSizeFromConstant(value)) {
}

Value::Value(uint32 value, ValueSize size) : Super(value, size) {
}

Value::Value(BasicBlock* bb)
    : Super(0, assm::kSize32Bit, UntypedReference(bb)) {
}

Value::Value(Block* block, Offset offset)
    : Super(0, assm::kSize32Bit, UntypedReference(block, offset, offset)) {
}

Value::Value(Block* block, Offset offset, Offset base)
    : Super(0, assm::kSize32Bit, UntypedReference(block, offset, base)) {
}

Value::Value(uint32 value, ValueSize size, const UntypedReference& ref)
    : Super(value, size, ref) {
  DCHECK(ref.IsValid());
}

Value::Value(const Value& other) : Super(other) {
}

Operand::Operand(const assm::Register32& base) : Super(base) {
}

Operand::Operand(const assm::Register32& base, const Displacement& displ)
    : Super(base, displ) {
}

Operand::Operand(const Displacement& displ) : Super(displ) {
}

Operand::Operand(const assm::Register32& base,
                 const assm::Register32& index,
                 assm::ScaleFactor scale,
                 const Displacement& displ)
    : Super(base, index, scale, displ) {
}

Operand::Operand(const assm::Register32& base,
                 const assm::Register32& index,
                 assm::ScaleFactor scale)
    : Super(base, index, scale) {
}

Operand::Operand(const assm::Register32& index,
                 assm::ScaleFactor scale,
                 const Displacement& displ)
    : Super(index, scale, displ) {
}

Operand::Operand(const Operand& o)
    : Super(o.base(), o.index(), o.scale(), o.displacement()) {
}

BasicBlockAssembler::BasicBlockSerializer::BasicBlockSerializer(
    const Instructions::iterator& where, Instructions* list)
        : where_(where), list_(list), num_ref_infos_(0) {
  DCHECK(list != NULL);
}

void BasicBlockAssembler::BasicBlockSerializer::AppendInstruction(
    uint32 location, const uint8* bytes, size_t num_bytes,
    const size_t *ref_locations,
    const UntypedReference* refs,
    size_t num_refs) {
  // The number of reference infos we've been provided must match the number of
  // references we have been given.
  DCHECK_EQ(num_ref_infos_, num_refs);

  Instruction instruction;
  CHECK(Instruction::FromBuffer(bytes, num_bytes, &instruction));
  instruction.set_source_range(source_range_);

  Instructions::iterator it = list_->insert(where_, instruction);

  for (size_t i = 0; i < num_refs; ++i) {
    const UntypedReference* tref = &refs[i];
    DCHECK(tref != NULL);

    BasicBlockReference bbref = CompleteUntypedReference(
        ref_infos_[i].type, ref_infos_[i].size, *tref);
    DCHECK(bbref.IsValid());
    it->SetReference(ref_locations[i], bbref);
  }

  // Clear the reference info for the next instruction.
  num_ref_infos_ = 0;
}

void BasicBlockAssembler::BasicBlockSerializer::PushReferenceInfo(
    BlockGraph::ReferenceType type, assm::ValueSize size) {
  DCHECK_GT(2u, num_ref_infos_);
  ref_infos_[num_ref_infos_].type = type;
  ref_infos_[num_ref_infos_].size = ToBytes(size);
  ++num_ref_infos_;
}

BasicBlockAssembler::BasicBlockAssembler(const Instructions::iterator& where,
                                         Instructions* list)
    : serializer_(where, list), asm_(0, &serializer_) {
}

BasicBlockAssembler::BasicBlockAssembler(uint32 location,
                                         const Instructions::iterator& where,
                                         Instructions* list)
    : serializer_(where, list), asm_(location, &serializer_) {
}

void BasicBlockAssembler::nop(size_t size) {
  asm_.nop(size);
}

void BasicBlockAssembler::call(const Immediate& dst) {
  // In the context of BasicBlockAssembler it only makes sense for calls with
  // immediate parameters to be backed by a 32-bit reference.
  PushMandatoryReferenceInfo(BlockGraph::PC_RELATIVE_REF, dst);
  CheckReferenceSize(assm::kSize32Bit, dst);
  asm_.call(dst);
}

void BasicBlockAssembler::call(const Operand& dst) {
  // If a call is backed by a reference it must be 32-bit.
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, dst);
  CheckReferenceSize(assm::kSize32Bit, dst);
  asm_.call(dst);
}

void BasicBlockAssembler::jmp(const Immediate& dst) {
  // In the context of BasicBlockAssembler it only makes sense for jumps with
  // immediate parameters to be backed by a reference.
  PushMandatoryReferenceInfo(BlockGraph::PC_RELATIVE_REF, dst);
  asm_.jmp(dst);
}

void BasicBlockAssembler::jmp(const Operand& dst) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, dst);
  asm_.jmp(dst);
}

void BasicBlockAssembler::j(ConditionCode code, const Immediate& dst) {
  // In the context of BasicBlockAssembler it only makes sense for jumps with
  // immediate parameters to be backed by a reference.
  PushMandatoryReferenceInfo(BlockGraph::PC_RELATIVE_REF, dst);
  asm_.j(code, dst);
}

void BasicBlockAssembler::set(ConditionCode code, const Register32& dst) {
  asm_.set(code, dst);
}

void BasicBlockAssembler::pushfd() {
  asm_.pushfd();
}

void BasicBlockAssembler::popfd() {
  asm_.popfd();
}

void BasicBlockAssembler::lahf() {
  asm_.lahf();
}

void BasicBlockAssembler::sahf() {
  asm_.sahf();
}

void BasicBlockAssembler::test(const Register8& dst, const Register8& src) {
  asm_.test(dst, src);
}

void BasicBlockAssembler::test(const Register8& dst, const Immediate& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, src);
  asm_.test(dst, src);
}

void BasicBlockAssembler::test(const Register32& dst, const Register32& src) {
  asm_.test(dst, src);
}

void BasicBlockAssembler::test(const Register32& dst, const Operand& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, src);
  asm_.test(dst, src);
}

void BasicBlockAssembler::test(const Operand& dst, const Register32& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, dst);
  asm_.test(dst, src);
}

void BasicBlockAssembler::test(const Register32& dst, const Immediate& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, src);
  asm_.test(dst, src);
}

void BasicBlockAssembler::test(const Operand&  dst, const Immediate& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, dst);
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, src);
  asm_.test(dst, src);
}

void BasicBlockAssembler::cmp(const Register8& dst, const Register8& src) {
  asm_.cmp(dst, src);
}

void BasicBlockAssembler::cmp(const Register8& dst, const Immediate& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, src);
  asm_.cmp(dst, src);
}

void BasicBlockAssembler::cmp(const Register32& dst, const Register32& src) {
  asm_.cmp(dst, src);
}

void BasicBlockAssembler::cmp(const Register32& dst, const Operand& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, src);
  asm_.cmp(dst, src);
}

void BasicBlockAssembler::cmp(const Operand& dst, const Register32& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, dst);
  asm_.cmp(dst, src);
}

void BasicBlockAssembler::cmp(const Register32& dst, const Immediate& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, src);
  asm_.cmp(dst, src);
}

void BasicBlockAssembler::cmp(const Operand&  dst, const Immediate& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, dst);
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, src);
  asm_.cmp(dst, src);
}

void BasicBlockAssembler::add(const Register8& dst, const Register8& src) {
  asm_.add(dst, src);
}

void BasicBlockAssembler::add(const Register8& dst, const Immediate& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, src);
  asm_.add(dst, src);
}

void BasicBlockAssembler::add(const Register32& dst, const Register32& src) {
  asm_.add(dst, src);
}

void BasicBlockAssembler::add(const Register32& dst, const Operand& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, src);
  asm_.add(dst, src);
}

void BasicBlockAssembler::add(const Operand& dst, const Register32& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, dst);
  asm_.add(dst, src);
}

void BasicBlockAssembler::add(const Register32& dst, const Immediate& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, src);
  asm_.add(dst, src);
}

void BasicBlockAssembler::add(const Operand& dst, const Immediate& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, dst);
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, src);
  asm_.add(dst, src);
}

void BasicBlockAssembler::sub(const Register8& dst, const Register8& src) {
  asm_.sub(dst, src);
}

void BasicBlockAssembler::sub(const Register8& dst, const Immediate& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, src);
  asm_.sub(dst, src);
}

void BasicBlockAssembler::sub(const Register32& dst, const Register32& src) {
  asm_.sub(dst, src);
}

void BasicBlockAssembler::sub(const Register32& dst, const Operand& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, src);
  asm_.sub(dst, src);
}

void BasicBlockAssembler::sub(const Operand& dst, const Register32& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, dst);
  asm_.sub(dst, src);
}

void BasicBlockAssembler::sub(const Register32& dst, const Immediate& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, src);
  asm_.sub(dst, src);
}

void BasicBlockAssembler::sub(const Operand& dst, const Immediate& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, dst);
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, src);
  asm_.sub(dst, src);
}

void BasicBlockAssembler::shl(const Register32& dst, const Immediate& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, src);
  asm_.shl(dst, src);
}

void BasicBlockAssembler::shr(const Register32& dst, const Immediate& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, src);
  asm_.shr(dst, src);
}

void BasicBlockAssembler::mov_b(const Operand& dst, const Immediate& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, dst);
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, src);
  CheckReferenceSize(assm::kSize32Bit, dst);
  CheckReferenceSize(assm::kSize32Bit, src);
  asm_.mov_b(dst, src);
}

void BasicBlockAssembler::movzx_b(const Register32& dst, const Operand& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, src);
  CheckReferenceSize(assm::kSize32Bit, src);
  asm_.movzx_b(dst, src);
}

void BasicBlockAssembler::mov(const Register32& dst, const Register32& src) {
  asm_.mov(dst, src);
}

void BasicBlockAssembler::mov(const Register32& dst, const Operand& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, src);
  CheckReferenceSize(assm::kSize32Bit, src);
  asm_.mov(dst, src);
}

void BasicBlockAssembler::mov(const Operand& dst, const Register32& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, dst);
  CheckReferenceSize(assm::kSize32Bit, dst);
  asm_.mov(dst, src);
}

void BasicBlockAssembler::mov(const Register32& dst, const Immediate& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, src);
  CheckReferenceSize(assm::kSize32Bit, src);
  asm_.mov(dst, src);
}

void BasicBlockAssembler::mov(const Operand& dst, const Immediate& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, dst);
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, src);
  CheckReferenceSize(assm::kSize32Bit, dst);
  CheckReferenceSize(assm::kSize32Bit, src);
  asm_.mov(dst, src);
}

void BasicBlockAssembler::mov_fs(const Register32& dst, const Operand& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, src);
  CheckReferenceSize(assm::kSize32Bit, src);
  asm_.mov_fs(dst, src);
}

void BasicBlockAssembler::mov_fs(const Operand& dst, const Register32& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, dst);
  CheckReferenceSize(assm::kSize32Bit, dst);
  asm_.mov_fs(dst, src);
}

void BasicBlockAssembler::lea(const Register32& dst, const Operand& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, src);
  CheckReferenceSize(assm::kSize32Bit, src);
  asm_.lea(dst, src);
}

void BasicBlockAssembler::push(const Register32& src) {
  asm_.push(src);
}

void BasicBlockAssembler::push(const Immediate& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, src);
  CheckReferenceSize(assm::kSize32Bit, src);
  asm_.push(src);
}

void BasicBlockAssembler::push(const Operand& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, src);
  CheckReferenceSize(assm::kSize32Bit, src);
  asm_.push(src);
}

void BasicBlockAssembler::pop(const Register32& dst) {
  asm_.pop(dst);
}

void BasicBlockAssembler::pop(const Operand& dst) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, dst);
  CheckReferenceSize(assm::kSize32Bit, dst);
  asm_.pop(dst);
}

void BasicBlockAssembler::ret() {
  asm_.ret();
}

void BasicBlockAssembler::ret(uint16 n) {
  asm_.ret(n);
}

void BasicBlockAssembler::xchg(const Register32& dst, const Register32& src) {
  asm_.xchg(dst, src);
}

void BasicBlockAssembler::xchg(const Register16& dst, const Register16& src) {
  asm_.xchg(dst, src);
}

void BasicBlockAssembler::xchg(const Register8& dst, const Register8& src) {
  asm_.xchg(dst, src);
}

void BasicBlockAssembler::PushMandatoryReferenceInfo(
    ReferenceType type, const Immediate& imm) {
  DCHECK(imm.reference().IsValid());
  serializer_.PushReferenceInfo(type, imm.size());
}

void BasicBlockAssembler::PushOptionalReferenceInfo(
    ReferenceType type, const Immediate& imm) {
  if (!imm.reference().IsValid())
    return;
  serializer_.PushReferenceInfo(type, imm.size());
}

void BasicBlockAssembler::PushOptionalReferenceInfo(
    ReferenceType type, const Operand& op) {
  if (!op.displacement().reference().IsValid())
    return;
  serializer_.PushReferenceInfo(type, op.displacement().size());
}

void BasicBlockAssembler::CheckReferenceSize(
    assm::ValueSize size, const Immediate& imm) const {
  DCHECK(!imm.reference().IsValid() || imm.size() == size);
}

void BasicBlockAssembler::CheckReferenceSize(
    assm::ValueSize size, const Operand& op) const {
  DCHECK(!op.displacement().reference().IsValid() ||
         op.displacement().size() == size);
}

}  // namespace block_graph
