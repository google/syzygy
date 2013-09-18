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

typedef core::DisplacementImpl DisplacementImpl;
typedef core::OperandImpl OperandImpl;
typedef core::ValueImpl ValueImpl;
typedef core::ValueSize ValueSize;

ValueSize ValueSizeFromConstant(uint32 input_value) {
  // IA32 assembly may/will sign-extend 8-bit literals, so we attempt to encode
  // in 8 bits only those literals whose value will be unchanged by that
  // treatment.
  input_value |= 0x7F;

  if (input_value == 0xFFFFFFFF || input_value == 0x7F)
    return core::kSize8Bit;

  return core::kSize32Bit;
}

ValueImpl CopyValue(const UntypedReference* ref,
                    const core::ValueImpl& value) {
  return ValueImpl(value.value(),
                   value.size(),
                   value.reference() ? ref : NULL);
}

size_t ToBytes(core::ValueSize size) {
  switch (size) {
    case core::kSize8Bit: return 1;
    case core::kSize32Bit: return 4;
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

Value::Value(uint32 value) : value_(value, ValueSizeFromConstant(value)) {
}

Value::Value(uint32 value, ValueSize size) : value_(value, size) {
}

Value::Value(BasicBlock* bb)
    : reference_(bb),
      value_(0, core::kSize32Bit, &reference_) {
}

Value::Value(Block* block, Offset offset)
    : reference_(block, offset, offset),
      value_(0, core::kSize32Bit, &reference_) {
}

Value::Value(Block* block, Offset offset, Offset base)
    : reference_(block, offset, base),
      value_(0, core::kSize32Bit, &reference_) {
}

Value::Value(uint32 value, ValueSize size, const UntypedReference& ref)
    : reference_(ref), value_(value, size, &reference_) {
  DCHECK(ref.IsValid());
}

Value::Value(const Value& other)
    : reference_(other.reference()),
      value_(CopyValue(&reference_, other.value_)) {
}

Value::Value(const UntypedReference& ref, const ValueImpl& value)
    : reference_(ref), value_(CopyValue(&reference_, value)) {
}

Value::~Value() {
#ifndef NDEBUG
  if (reference_.IsValid()) {
    DCHECK(value_.reference() == &reference_);
  } else {
    DCHECK(value_.reference() == NULL);
  }
#endif
}

const Value& Value::operator=(const Value& other) {
  reference_ = other.reference_;
  value_ = CopyValue(&reference_, other.value_);
  return *this;
}

bool Value::operator==(const Value& rhs) const {
  if (reference_.IsValid())
    return reference_ == rhs.reference();
  return value_ == rhs.value_;
}

Operand::Operand(const core::Register32& base) : operand_(base) {
}

Operand::Operand(const core::Register32& base, const Displacement& displ)
    : reference_(displ.reference()),
      operand_(base, CopyValue(&reference_, displ.value_)) {
}

Operand::Operand(const Displacement& displ)
    : reference_(displ.reference()),
      operand_(CopyValue(&reference_, displ.value_)) {
}

Operand::Operand(const core::Register32& base,
                 const core::Register32& index,
                 core::ScaleFactor scale,
                 const Displacement& displ)
    : reference_(displ.reference_),
      operand_(base, index, scale, CopyValue(&reference_, displ.value_)) {
}

Operand::Operand(const core::Register32& base,
                 const core::Register32& index,
                 core::ScaleFactor scale)
    : operand_(base, index, scale) {
}

Operand::Operand(const core::Register32& index,
                 core::ScaleFactor scale,
                 const Displacement& displ)
    : reference_(displ.reference_),
      operand_(index, scale, CopyValue(&reference_, displ.value_)) {
}

Operand::Operand(const Operand& o)
    : reference_(o.reference_),
      operand_(o.base(), o.index(), o.scale(),
               CopyValue(&reference_, o.operand_.displacement())) {
}

Operand::~Operand() {
#ifndef NDEBUG
  if (reference_.IsValid()) {
    DCHECK(operand_.displacement().reference() == &reference_);
  } else {
    DCHECK(operand_.displacement().reference() == NULL);
  }
#endif
}

const Operand& Operand::operator=(const Operand& other) {
  reference_ = other.reference_;
  operand_ =
      core::OperandImpl(other.base(), other.index(), other.scale(),
                        CopyValue(&reference_, other.operand_.displacement()));
  return *this;
}

BasicBlockAssembler::BasicBlockSerializer::BasicBlockSerializer(
    const Instructions::iterator& where, Instructions* list)
        : where_(where), list_(list), num_ref_infos_(0) {
  DCHECK(list != NULL);
}

void BasicBlockAssembler::BasicBlockSerializer::AppendInstruction(
    uint32 location, const uint8* bytes, size_t num_bytes,
    const size_t *ref_locations, const void* const* refs, size_t num_refs) {
  // The number of reference infos we've been provided must match the number of
  // references we have been given.
  DCHECK_EQ(num_ref_infos_, num_refs);

  Instruction instruction;
  CHECK(Instruction::FromBuffer(bytes, num_bytes, &instruction));
  instruction.set_source_range(source_range_);

  Instructions::iterator it = list_->insert(where_, instruction);

  for (size_t i = 0; i < num_refs; ++i) {
    const UntypedReference* tref =
        reinterpret_cast<const UntypedReference*>(refs[i]);
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
    BlockGraph::ReferenceType type, core::ValueSize size) {
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
  CheckReferenceSize(core::kSize32Bit, dst);
  asm_.call(dst.value_);
}

void BasicBlockAssembler::call(const Operand& dst) {
  // If a call is backed by a reference it must be 32-bit.
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, dst);
  CheckReferenceSize(core::kSize32Bit, dst);
  asm_.call(dst.operand_);
}

void BasicBlockAssembler::jmp(const Immediate& dst) {
  // In the context of BasicBlockAssembler it only makes sense for jumps with
  // immediate parameters to be backed by a reference.
  PushMandatoryReferenceInfo(BlockGraph::PC_RELATIVE_REF, dst);
  asm_.jmp(dst.value_);
}

void BasicBlockAssembler::jmp(const Operand& dst) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, dst);
  asm_.jmp(dst.operand_);
}

void BasicBlockAssembler::j(ConditionCode code, const Immediate& dst) {
  // In the context of BasicBlockAssembler it only makes sense for jumps with
  // immediate parameters to be backed by a reference.
  PushMandatoryReferenceInfo(BlockGraph::PC_RELATIVE_REF, dst);
  asm_.j(code, dst.value_);
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
  asm_.test(dst, src.value_);
}

void BasicBlockAssembler::test(const Register32& dst, const Register32& src) {
  asm_.test(dst, src);
}

void BasicBlockAssembler::test(const Register32& dst, const Operand& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, src);
  asm_.test(dst, src.operand_);
}

void BasicBlockAssembler::test(const Operand& dst, const Register32& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, dst);
  asm_.test(dst.operand_, src);
}

void BasicBlockAssembler::test(const Register32& dst, const Immediate& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, src);
  asm_.test(dst, src.value_);
}

void BasicBlockAssembler::test(const Operand&  dst, const Immediate& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, dst);
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, src);
  asm_.test(dst.operand_, src.value_);
}

void BasicBlockAssembler::cmp(const Register8& dst, const Register8& src) {
  asm_.cmp(dst, src);
}

void BasicBlockAssembler::cmp(const Register8& dst, const Immediate& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, src);
  asm_.cmp(dst, src.value_);
}

void BasicBlockAssembler::cmp(const Register32& dst, const Register32& src) {
  asm_.cmp(dst, src);
}

void BasicBlockAssembler::cmp(const Register32& dst, const Operand& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, src);
  asm_.cmp(dst, src.operand_);
}

void BasicBlockAssembler::cmp(const Operand& dst, const Register32& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, dst);
  asm_.cmp(dst.operand_, src);
}

void BasicBlockAssembler::cmp(const Register32& dst, const Immediate& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, src);
  asm_.cmp(dst, src.value_);
}

void BasicBlockAssembler::cmp(const Operand&  dst, const Immediate& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, dst);
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, src);
  asm_.cmp(dst.operand_, src.value_);
}

void BasicBlockAssembler::add(const Register8& dst, const Register8& src) {
  asm_.add(dst, src);
}

void BasicBlockAssembler::add(const Register8& dst, const Immediate& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, src);
  asm_.add(dst, src.value_);
}

void BasicBlockAssembler::add(const Register32& dst, const Register32& src) {
  asm_.add(dst, src);
}

void BasicBlockAssembler::add(const Register32& dst, const Operand& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, src);
  asm_.add(dst, src.operand_);
}

void BasicBlockAssembler::add(const Operand& dst, const Register32& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, dst);
  asm_.add(dst.operand_, src);
}

void BasicBlockAssembler::add(const Register32& dst, const Immediate& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, src);
  asm_.add(dst, src.value_);
}

void BasicBlockAssembler::add(const Operand& dst, const Immediate& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, dst);
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, src);
  asm_.add(dst.operand_, src.value_);
}

void BasicBlockAssembler::sub(const Register8& dst, const Register8& src) {
  asm_.sub(dst, src);
}

void BasicBlockAssembler::sub(const Register8& dst, const Immediate& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, src);
  asm_.sub(dst, src.value_);
}

void BasicBlockAssembler::sub(const Register32& dst, const Register32& src) {
  asm_.sub(dst, src);
}

void BasicBlockAssembler::sub(const Register32& dst, const Operand& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, src);
  asm_.sub(dst, src.operand_);
}

void BasicBlockAssembler::sub(const Operand& dst, const Register32& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, dst);
  asm_.sub(dst.operand_, src);
}

void BasicBlockAssembler::sub(const Register32& dst, const Immediate& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, src);
  asm_.sub(dst, src.value_);
}

void BasicBlockAssembler::sub(const Operand& dst, const Immediate& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, dst);
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, src);
  asm_.sub(dst.operand_, src.value_);
}

void BasicBlockAssembler::shl(const Register32& dst, const Immediate& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, src);
  asm_.shl(dst, src.value_);
}

void BasicBlockAssembler::shr(const Register32& dst, const Immediate& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, src);
  asm_.shr(dst, src.value_);
}

void BasicBlockAssembler::mov_b(const Operand& dst, const Immediate& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, dst);
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, src);
  CheckReferenceSize(core::kSize32Bit, dst);
  CheckReferenceSize(core::kSize32Bit, src);
  asm_.mov_b(dst.operand_, src.value_);
}

void BasicBlockAssembler::movzx_b(const Register32& dst, const Operand& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, src);
  CheckReferenceSize(core::kSize32Bit, src);
  asm_.movzx_b(dst, src.operand_);
}

void BasicBlockAssembler::mov(const Register32& dst, const Register32& src) {
  asm_.mov(dst, src);
}

void BasicBlockAssembler::mov(const Register32& dst, const Operand& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, src);
  CheckReferenceSize(core::kSize32Bit, src);
  asm_.mov(dst, src.operand_);
}

void BasicBlockAssembler::mov(const Operand& dst, const Register32& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, dst);
  CheckReferenceSize(core::kSize32Bit, dst);
  asm_.mov(dst.operand_, src);
}

void BasicBlockAssembler::mov(const Register32& dst, const Immediate& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, src);
  CheckReferenceSize(core::kSize32Bit, src);
  asm_.mov(dst, src.value_);
}

void BasicBlockAssembler::mov(const Operand& dst, const Immediate& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, dst);
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, src);
  CheckReferenceSize(core::kSize32Bit, dst);
  CheckReferenceSize(core::kSize32Bit, src);
  asm_.mov(dst.operand_, src.value_);
}

void BasicBlockAssembler::mov_fs(const Register32& dst, const Operand& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, src);
  CheckReferenceSize(core::kSize32Bit, src);
  asm_.mov_fs(dst, src.operand_);
}

void BasicBlockAssembler::mov_fs(const Operand& dst, const Register32& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, dst);
  CheckReferenceSize(core::kSize32Bit, dst);
  asm_.mov_fs(dst.operand_, src);
}

void BasicBlockAssembler::lea(const Register32& dst, const Operand& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, src);
  CheckReferenceSize(core::kSize32Bit, src);
  asm_.lea(dst, src.operand_);
}

void BasicBlockAssembler::push(const Register32& src) {
  asm_.push(src);
}

void BasicBlockAssembler::push(const Immediate& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, src);
  CheckReferenceSize(core::kSize32Bit, src);
  asm_.push(src.value_);
}

void BasicBlockAssembler::push(const Operand& src) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, src);
  CheckReferenceSize(core::kSize32Bit, src);
  asm_.push(src.operand_);
}

void BasicBlockAssembler::pop(const Register32& dst) {
  asm_.pop(dst);
}

void BasicBlockAssembler::pop(const Operand& dst) {
  PushOptionalReferenceInfo(BlockGraph::ABSOLUTE_REF, dst);
  CheckReferenceSize(core::kSize32Bit, dst);
  asm_.pop(dst.operand_);
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
  DCHECK(imm.value_.reference() != NULL);
  serializer_.PushReferenceInfo(type, imm.value_.size());
}

void BasicBlockAssembler::PushOptionalReferenceInfo(
    ReferenceType type, const Immediate& imm) {
  if (imm.value_.reference() == NULL)
    return;
  serializer_.PushReferenceInfo(type, imm.value_.size());
}

void BasicBlockAssembler::PushOptionalReferenceInfo(
    ReferenceType type, const Operand& op) {
  if (op.operand_.displacement().reference() == NULL)
    return;
  serializer_.PushReferenceInfo(type, op.operand_.displacement().size());
}

void BasicBlockAssembler::CheckReferenceSize(
    core::ValueSize size, const Immediate& imm) const {
  DCHECK(imm.value_.reference() == NULL || imm.value_.size() == size);
}

void BasicBlockAssembler::CheckReferenceSize(
    core::ValueSize size, const Operand& op) const {
  DCHECK(op.operand_.displacement().reference() == NULL ||
         op.operand_.displacement().size() == size);
}

}  // namespace block_graph
