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

core::ValueSize ValueSizeFromConstant(uint32 input_value) {
  // IA32 assembly may/will sign-extend 8-bit literals, so we attempt to encode
  // in 8 bits only those literals whose value will be unchanged by that
  // treatment.
  input_value |= 0x7F;

  if (input_value == 0xFFFFFFFF || input_value == 0x7F)
    return core::kSize8Bit;

  return core::kSize32Bit;
}

core::ValueImpl CopyValue(const BasicBlockReference* ref,
                          const core::ValueImpl& value) {
  return core::ValueImpl(value.value(),
                         value.size(),
                         value.reference() ? ref : NULL);
}

}  // namespace

Value::Value() {
}

Value::Value(uint32 value) : value_(value, ValueSizeFromConstant(value)) {
}

Value::Value(uint32 value, core::ValueSize size) : value_(value, size) {
}

Value::Value(BasicBlock* bb)
    : reference_(BlockGraph::ABSOLUTE_REF, sizeof(core::AbsoluteAddress), bb),
      value_(0, core::kSize32Bit, &reference_) {
}

Value::Value(BlockGraph::Block* block, BlockGraph::Offset offset)
    : reference_(BlockGraph::ABSOLUTE_REF, sizeof(core::AbsoluteAddress),
                 block, offset, 0),
      value_(0, core::kSize32Bit, &reference_) {
}

Value::Value(uint32 value, ValueSize size, const BasicBlockReference& ref)
    : reference_(ref), value_(value, size, &reference_) {
}

Value::Value(const Value& o)
    : reference_(o.reference()), value_(CopyValue(&reference_, o.value_)) {
}

Value::Value(const BasicBlockReference& ref, const core::ValueImpl& value)
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

Operand::Operand(core::Register base) : operand_(base) {
}

Operand::Operand(core::Register base, const Displacement& displ)
    : reference_(displ.reference()),
      operand_(base, CopyValue(&reference_, displ.value_)) {
}

Operand::Operand(const Displacement& displ)
    : reference_(displ.reference()),
      operand_(CopyValue(&reference_, displ.value_)) {
}

Operand::Operand(core::Register base,
                 core::Register index,
                 core::ScaleFactor scale,
                 const Displacement& displ)
    : reference_(displ.reference_),
      operand_(base, index, scale, CopyValue(&reference_, displ.value_)) {
}

Operand::Operand(core::Register base,
                 core::Register index,
                 core::ScaleFactor scale)
    : operand_(base, index, scale) {
}

Operand::Operand(core::Register index,
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
        : where_(where), list_(list) {
  DCHECK(list != NULL);
}

void BasicBlockAssembler::BasicBlockSerializer::AppendInstruction(
    uint32 location, const uint8* bytes, size_t num_bytes,
    const size_t *ref_locations, const void* const* refs, size_t num_refs) {
  Instructions::iterator it =
      list_->insert(where_, Instruction(num_bytes, bytes));

  for (size_t i = 0; i < num_refs; ++i) {
    const BasicBlockReference* ref =
        reinterpret_cast<const BasicBlockReference*>(refs[i]);
    DCHECK(ref != NULL);

    it->SetReference(ref_locations[i], *ref);
  }
}

BasicBlockAssembler::BasicBlockAssembler(const Instructions::iterator& where,
                                         Instructions* list)
    : serializer_(where, list), asm_(0, &serializer_) {
}

void BasicBlockAssembler::call(const Immediate& dst) {
  asm_.call(dst.value_);
}

void BasicBlockAssembler::call(const Operand& dst) {
  asm_.call(dst.operand_);
}

void BasicBlockAssembler::jmp(const Immediate& dst) {
  asm_.jmp(dst.value_);
}

void BasicBlockAssembler::jmp(const Operand& dst) {
  asm_.jmp(dst.operand_);
}

void BasicBlockAssembler::j(ConditionCode code, const Immediate& dst) {
  asm_.j(code, dst.value_);
}

void BasicBlockAssembler::mov_b(const Operand& dst, const Immediate& src) {
  asm_.mov_b(dst.operand_, src.value_);
}

void BasicBlockAssembler::mov(Register dst, Register src) {
  asm_.mov(dst, src);
}

void BasicBlockAssembler::mov(Register dst, const Operand& src) {
  asm_.mov(dst, src.operand_);
}

void BasicBlockAssembler::mov(const Operand& dst, Register src) {
  asm_.mov(dst.operand_, src);
}

void BasicBlockAssembler::mov(Register dst, const Immediate& src) {
  asm_.mov(dst, src.value_);
}

void BasicBlockAssembler::mov(const Operand& dst, const Immediate& src) {
  asm_.mov(dst.operand_, src.value_);
}

void BasicBlockAssembler::lea(Register dst, const Operand& src) {
  asm_.lea(dst, src.operand_);
}

void BasicBlockAssembler::push(Register src) {
  asm_.push(src);
}

void BasicBlockAssembler::push(const Immediate& src) {
  asm_.push(src.value_);
}

void BasicBlockAssembler::push(const Operand& src) {
  asm_.push(src.operand_);
}

void BasicBlockAssembler::pop(Register src) {
  asm_.pop(src);
}

void BasicBlockAssembler::pop(const Operand& src) {
  asm_.pop(src.operand_);
}

}  // namespace block_graph
