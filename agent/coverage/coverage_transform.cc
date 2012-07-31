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

#include "syzygy/agent/coverage/coverage_transform.h"

#include "syzygy/agent/coverage/coverage_constants.h"
#include "syzygy/agent/coverage/coverage_data.h"
#include "syzygy/block_graph/typed_block.h"
#include "syzygy/core/disassembler_util.h"
#include "syzygy/pe/block_util.h"
#include "syzygy/pe/pe_utils.h"

namespace agent {
namespace coverage {

namespace {

typedef block_graph::BasicBlock BasicBlock;
typedef block_graph::BasicBlockReference BasicBlockReference;
typedef block_graph::BlockGraph BlockGraph;
typedef block_graph::Instruction Instruction;
typedef block_graph::TypedBlock<CoverageData> CoverageDataBlock;

bool AddCoverageDataSection(BlockGraph* block_graph,
                            BlockGraph::Block** coverage_data_block) {
  DCHECK(block_graph != NULL);
  DCHECK(coverage_data_block != NULL);

  BlockGraph::Section* coverage_section = block_graph->FindSection(
      kCoverageClientDataSectionName);
  if (coverage_section != NULL) {
    LOG(ERROR) << "Block-graph already contains a code coverage data section ("
               << kCoverageClientDataSectionName << ").";
    return false;
  }

  coverage_section = block_graph->AddSection(
      kCoverageClientDataSectionName,
      kCoverageClientDataSectionCharacteristics);
  DCHECK(coverage_section != NULL);

  BlockGraph::Block* block =
      block_graph->AddBlock(BlockGraph::DATA_BLOCK,
                            sizeof(CoverageData),
                            "Coverage data");
  DCHECK(block != NULL);
  block->set_section(coverage_section->id());

  CoverageData coverage_data = {};
  coverage_data.magic = kCoverageClientMagic;
  coverage_data.version = kCoverageClientVersion;

  block->CopyData(sizeof(coverage_data), &coverage_data);
  *coverage_data_block = block;

  return true;
}

// 0x50 : push eax
// 0xA1 [4 bytes ptr] : mov eax, dword ptr[byte_array_pointer]
// 0xC6 0x80 [4 bytes ptr] [1 byte value] : mov byte ptr[eax + 200], 1
// 0x58 : pop eax
#pragma pack(push, 1)
struct CoverageInstrumentationCode {
  CoverageInstrumentationCode()
      : byte_0_0(0x50),
        byte_1_0(0xA1), basic_block_seen_array(0),
        byte_2_0(0xC6), byte_2_1(0x80), basic_block_index(0), byte_2_6(0x01),
        byte_3_0(0x58) {
  };

  // 0x50 : push eax
  union {
    uint8 inst0[1];
    uint8 byte_0_0;
  };

  union {
    // 0xA1 [4 bytes ptr] : mov eax, dword ptr[byte_array_pointer]
    uint8 inst1[5];
    struct {
      uint8 byte_1_0;
      uint32 basic_block_seen_array;
    };
  };

  // 0xC6 0x80 [4 bytes ptr] 0x01 : mov byte ptr[eax + basic_block_index], 1
  union {
    uint8 inst2[7];
    struct {
      uint8 byte_2_0;
      uint8 byte_2_1;
      uint32 basic_block_index;
      uint8 byte_2_6;
    };
  };

  // 0x58: pop eax
  union {
    uint8 inst3[1];
    uint8 byte_3_0;
  };
};
#pragma pack(pop)
COMPILE_ASSERT(sizeof(CoverageInstrumentationCode) == 14,
               coverage_instrumention_code_must_be_14_bytes);

BasicBlock::Instructions::iterator PrependInstruction(
    const uint8* bytes,
    size_t length,
    BasicBlock::Instructions* instructions) {
  DCHECK(bytes != NULL);
  DCHECK(instructions != NULL);

  _DInst rep;
  CHECK(core::DecodeOneInstruction(0x10000000, bytes, length, &rep));

  return instructions->insert(
      instructions->begin(),
      Instruction(rep, BasicBlock::kNoOffset, length, bytes));
}

}  // namespace

const char CoverageInstrumentationTransform::kTransformName[] =
    "CoverageInstrumentationTransform";

CoverageInstrumentationTransform::CoverageInstrumentationTransform()
    : coverage_data_block_(NULL), basic_block_count_(0) {
}

bool CoverageInstrumentationTransform::TransformBasicBlockSubGraph(
    BlockGraph* block_graph,
    BasicBlockSubGraph* basic_block_subgraph) {
  DCHECK(block_graph != NULL);
  DCHECK(basic_block_subgraph != NULL);

  instruction_byte_map_.clear();

  // Iterate over the basic blocks.
  BasicBlockSubGraph::BBCollection::iterator it =
      basic_block_subgraph->basic_blocks().begin();
  for (; it != basic_block_subgraph->basic_blocks().end(); ++it) {
    // We're only interested in code blocks.
    if (it->second.type() != BasicBlock::BASIC_CODE_BLOCK)
      continue;

    // We prepend each basic code block with the following instructions:
    //   0. push eax
    //   1. mov eax, dword ptr[basic_block_seen_array]
    //   2. mov byte ptr[eax + basic_block_index], 1
    //   3. pop eax
    // TODO(chrisha): Get around to using the assembler.
    static const CoverageInstrumentationCode kCode;
    static const uint8* kCodeBegin = reinterpret_cast<const uint8*>(&kCode);
    static const uint8* kCodeEnd = kCodeBegin + sizeof(kCode);
    ByteVector& byte_vector =
        instruction_byte_map_[instruction_byte_map_.size()];
    byte_vector.assign(kCodeBegin, kCodeEnd);
    CoverageInstrumentationCode* code =
        reinterpret_cast<CoverageInstrumentationCode*>(&byte_vector.at(0));

    // Set the basic block index. This is an immediate operand.
    code->basic_block_index = basic_block_count_;

    // TODO(chrisha): Remove representation from the instruction.
    const uint8* pinst0 = reinterpret_cast<const uint8*>(&code->inst0);
    const uint8* pinst1 = reinterpret_cast<const uint8*>(&code->inst1);
    const uint8* pinst2 = reinterpret_cast<const uint8*>(&code->inst2);
    const uint8* pinst3 = reinterpret_cast<const uint8*>(&code->inst3);
    const uint8* pinst4 = pinst0 + sizeof(kCode);

    // Prepend the instrumentation instructions.
    BasicBlock::Instructions* insts = &it->second.instructions();
    PrependInstruction(pinst3, pinst4 - pinst3, insts);
    PrependInstruction(pinst2, pinst3 - pinst2, insts);
    BasicBlock::Instructions::iterator inst1_it =
        PrependInstruction(pinst1, pinst2 - pinst1, insts);
    PrependInstruction(pinst0, pinst1 - pinst0, insts);

    // Hook up the reference to the basic_block_seen_array.
    static const BlockGraph::Offset kSrcOffset =
        offsetof(CoverageInstrumentationCode, basic_block_seen_array) -
        offsetof(CoverageInstrumentationCode, inst1);
    static const BlockGraph::Offset kDstOffset =
        offsetof(CoverageData, basic_block_seen_array);
    inst1_it->SetReference(
        kSrcOffset,
        BasicBlockReference(BlockGraph::ABSOLUTE_REF,
                            sizeof(code->basic_block_seen_array),
                            coverage_data_block_,
                            kDstOffset,
                            kDstOffset));

    ++basic_block_count_;
  }

  return true;
}

bool CoverageInstrumentationTransform::PreBlockGraphIteration(
    BlockGraph* block_graph, BlockGraph::Block* header_block) {
  DCHECK(block_graph != NULL);
  DCHECK(header_block != NULL);

  if (!AddCoverageDataSection(block_graph, &coverage_data_block_))
    return false;
  DCHECK(coverage_data_block_ != NULL);

  return true;
}

bool CoverageInstrumentationTransform::OnBlock(
    BlockGraph* block_graph, BlockGraph::Block* block) {
  DCHECK(block_graph != NULL);
  DCHECK(block != NULL);

  // We only care about code blocks.
  if (block->type() != BlockGraph::CODE_BLOCK)
    return true;

  // We only care about blocks that are safe for basic block decomposition.
  if (!pe::CodeBlockIsBasicBlockDecomposable(block))
    return true;

  // Apply our basic block transform.
  if (!block_graph::ApplyBasicBlockSubGraphTransform(
      this, block_graph, block, NULL)) {
    return false;
  }

  return true;
}

bool CoverageInstrumentationTransform::PostBlockGraphIteration(
    BlockGraph* block_graph, BlockGraph::Block* header_block) {
  DCHECK(block_graph != NULL);
  DCHECK(header_block != NULL);

  if (basic_block_count_ == 0) {
    LOG(WARNING) << "Encounted no basic code blocks during instrumentation.";
    return true;
  }

  // Set the final basic block count. This is used by the runtime library to
  // know how big an array to allocate for the statistics.
  CoverageDataBlock coverage_data;
  DCHECK(coverage_data_block_ != NULL);
  CHECK(coverage_data.Init(0, coverage_data_block_));
  coverage_data->basic_block_count = basic_block_count_;

  // Get/create a read/write .rdata section.
  BlockGraph::Section* rdata_section = block_graph->FindOrAddSection(
      pe::kReadWriteDataSectionName, pe::kReadWriteDataCharacteristics);
  if (rdata_section == NULL) {
    LOG(ERROR) << "Unable to find or create section \""
               << pe::kReadWriteDataSectionName << "\".";
    return false;
  }

  // Create an empty block that is sufficient to hold all of the coverage
  // results. We will initially point basic_block_seen_array at this so that
  // even if the call-trace service is down the program can run without
  // crashing. We put this in .rdata so that .cover contains only a single
  // block.
  BlockGraph::Block* bb_seen_array_block =
      block_graph->AddBlock(BlockGraph::DATA_BLOCK,
                            basic_block_count_,
                            "Basic Blocks Seen Array");
  DCHECK(bb_seen_array_block != NULL);
  bb_seen_array_block->set_section(rdata_section->id());

  // Hook it up to the coverage_data array pointer.
  coverage_data_block_->SetReference(
      coverage_data.OffsetOf(coverage_data->basic_block_seen_array),
      BlockGraph::Reference(
          BlockGraph::ABSOLUTE_REF,
          sizeof(coverage_data->basic_block_seen_array),
          bb_seen_array_block,
          0,
          0));

  return true;
}

}  // namespace coverage
}  // namespace agent
