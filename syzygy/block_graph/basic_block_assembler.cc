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

ValueSize ValueSizeFromConstant(uint32_t input_value) {
  // IA32 assembly may/will sign-extend 8-bit literals, so we attempt to encode
  // in 8 bits only those literals whose value will be unchanged by that
  // treatment.
  input_value |= 0x7F;

  if (input_value == 0xFFFFFFFF || input_value == 0x7F)
    return assm::kSize8Bit;

  return assm::kSize32Bit;
}

size_t ToBytes(assm::ReferenceSize size) {
  switch (size) {
    case assm::kSize8Bit: return 1;
    case assm::kSize32Bit: return 4;
  }
  NOTREACHED();
  return 0;
}

// Completes a UntypedReference, converting it to a BasicBlockReference
// using the associated type and size information.
BasicBlockReference CompleteUntypedReference(
    const BasicBlockAssembler::ReferenceInfo& info) {
  DCHECK(info.reference.IsValid());

  size_t size = ToBytes(info.size);
  BlockGraph::ReferenceType type = BlockGraph::ABSOLUTE_REF;
  if (info.pc_relative)
    type = BlockGraph::PC_RELATIVE_REF;

  if (info.reference.referred_type() ==
          BasicBlockReference::REFERRED_TYPE_BLOCK) {
    DCHECK(info.reference.block() != NULL);
    return BasicBlockReference(type, size, info.reference.block(),
                               info.reference.offset(), info.reference.base());
  }

  DCHECK_EQ(BasicBlockReference::REFERRED_TYPE_BASIC_BLOCK,
            info.reference.referred_type());
  DCHECK(info.reference.basic_block() != NULL);
  return BasicBlockReference(type, size, info.reference.basic_block());
}

}  // namespace

BasicBlockAssembler::Immediate Immediate() {
  return BasicBlockAssembler::Immediate();
}

BasicBlockAssembler::Immediate Immediate(uint32_t value) {
  return BasicBlockAssembler::Immediate(value, ValueSizeFromConstant(value));
}

BasicBlockAssembler::Immediate Immediate(uint32_t value, ValueSize size) {
  return BasicBlockAssembler::Immediate(value, size);
}

BasicBlockAssembler::Immediate Immediate(BasicBlock* bb) {
  return BasicBlockAssembler::Immediate(
      0, assm::kSize32Bit, UntypedReference(bb));
}

BasicBlockAssembler::Immediate Immediate(
    BlockGraph::Block* block, BlockGraph::Offset offset) {
  return BasicBlockAssembler::Immediate(
      0, assm::kSize32Bit, UntypedReference(block, offset, offset));
}

BasicBlockAssembler::Immediate Immediate(BlockGraph::Block* block,
                                         BlockGraph::Offset offset,
                                         BlockGraph::Offset base) {
  return BasicBlockAssembler::Immediate(
      0, assm::kSize32Bit, UntypedReference(block, offset, base));
}

BasicBlockAssembler::Immediate Immediate(uint32_t value,
                                         ValueSize size,
                                         const UntypedReference& ref) {
  DCHECK(ref.IsValid());
  return BasicBlockAssembler::Immediate(value, size, ref);
}

BasicBlockAssembler::Displacement Displacement() {
  return BasicBlockAssembler::Displacement();
}

BasicBlockAssembler::Displacement Displacement(uint32_t value) {
  return BasicBlockAssembler::Displacement(value,
                                           ValueSizeFromConstant(value));
}

BasicBlockAssembler::Displacement Displacement(uint32_t value, ValueSize size) {
  return BasicBlockAssembler::Displacement(value, size);
}

BasicBlockAssembler::Displacement Displacement(BasicBlock* bb) {
  return BasicBlockAssembler::Displacement(
      0, assm::kSize32Bit, UntypedReference(bb));
}

BasicBlockAssembler::Displacement Displacement(
    BlockGraph::Block* block, BlockGraph::Offset offset) {
  return BasicBlockAssembler::Displacement(
      0, assm::kSize32Bit, UntypedReference(block, offset, offset));
}

BasicBlockAssembler::Displacement Displacement(
    BlockGraph::Block* block, BlockGraph::Offset offset,
    BlockGraph::Offset base) {
  return BasicBlockAssembler::Displacement(
      0, assm::kSize32Bit, UntypedReference(block, offset, base));
}

BasicBlockAssembler::Displacement Displacement(uint32_t value,
                                               ValueSize size,
                                               const UntypedReference& ref) {
  DCHECK(ref.IsValid());
  return BasicBlockAssembler::Displacement(value, size, ref);
}

BasicBlockAssembler::Operand Operand(const assm::Register32& base) {
  return BasicBlockAssembler::Operand(base);
}

BasicBlockAssembler::Operand Operand(
    const assm::Register32& base,
    const BasicBlockAssembler::Displacement& displ) {
  return BasicBlockAssembler::Operand(base, displ);
}

BasicBlockAssembler::Operand Operand(
    const BasicBlockAssembler::Displacement& displ) {
  return BasicBlockAssembler::Operand(displ);
}

BasicBlockAssembler::Operand Operand(
    const assm::Register32& base, const assm::Register32& index,
    assm::ScaleFactor scale, const BasicBlockAssembler::Displacement& displ) {
  return BasicBlockAssembler::Operand(base, index, scale, displ);
}

BasicBlockAssembler::Operand Operand(const assm::Register32& base,
                                     const assm::Register32& index,
                                     assm::ScaleFactor scale) {
  return BasicBlockAssembler::Operand(base, index, scale);
}

BasicBlockAssembler::Operand Operand(
    const assm::Register32& index, assm::ScaleFactor scale,
    const BasicBlockAssembler::Displacement& displ) {
  return BasicBlockAssembler::Operand(index, scale, displ);
}

BasicBlockAssembler::BasicBlockSerializer::BasicBlockSerializer(
    const Instructions::iterator& where, Instructions* list)
        : where_(where), list_(list) {
  DCHECK(list != NULL);
}

void BasicBlockAssembler::BasicBlockSerializer::AppendInstruction(
    uint32_t location,
    const uint8_t* bytes,
    uint32_t num_bytes,
    const ReferenceInfo* refs,
    size_t num_refs) {
  Instruction instruction;
  CHECK(Instruction::FromBuffer(bytes, num_bytes, &instruction));
  instruction.set_source_range(source_range_);

  Instructions::iterator it = list_->insert(where_, instruction);

  for (size_t i = 0; i < num_refs; ++i) {
    BasicBlockReference bbref = CompleteUntypedReference(refs[i]);
    DCHECK(bbref.IsValid());
    it->SetReference(refs[i].offset, bbref);
  }
}

bool BasicBlockAssembler::BasicBlockSerializer::FinalizeLabel(
    uint32_t location,
    const uint8_t* bytes,
    size_t num_bytes) {
  // No support for labels.
  return false;
}

BasicBlockAssembler::BasicBlockAssembler(const Instructions::iterator& where,
                                         Instructions* list)
    : Super(0, &serializer_), serializer_(where, list) {
}

BasicBlockAssembler::BasicBlockAssembler(uint32_t location,
                                         const Instructions::iterator& where,
                                         Instructions* list)
    : Super(location, &serializer_), serializer_(where, list) {
}

void BasicBlockAssembler::call(const Immediate& dst) {
  // In the context of BasicBlockAssembler it only makes sense for calls with
  // immediate parameters to be backed by a 32-bit reference.
  DCHECK(dst.reference().IsValid());
  DCHECK_EQ(assm::kSize32Bit, dst.size());
  Super::call(dst);
}

void BasicBlockAssembler::call(const Operand& dst) {
  const UntypedReference& ref = dst.displacement().reference();
  DCHECK(!ref.IsValid() || dst.displacement().size() == assm::kSize32Bit);
  Super::call(dst);
}

void BasicBlockAssembler::jmp(const Immediate& dst) {
  DCHECK(dst.reference().IsValid());
  Super::jmp(dst);
}

void BasicBlockAssembler::jmp(const Operand& dst) {
  const UntypedReference& ref = dst.displacement().reference();
  DCHECK(!ref.IsValid() || dst.displacement().size() == assm::kSize32Bit);
  Super::jmp(dst);
}

void BasicBlockAssembler::j(ConditionCode code, const Immediate& dst) {
  DCHECK(dst.reference().IsValid());
  Super::j(code, dst);
}

}  // namespace block_graph
