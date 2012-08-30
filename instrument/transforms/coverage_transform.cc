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

#include "syzygy/instrument/transforms/coverage_transform.h"

#include "syzygy/block_graph/basic_block_assembler.h"
#include "syzygy/block_graph/typed_block.h"
#include "syzygy/common/coverage.h"
#include "syzygy/core/disassembler_util.h"
#include "syzygy/pe/block_util.h"
#include "syzygy/pe/pe_utils.h"

namespace instrument {
namespace transforms {

namespace {

using common::CoverageData;
using core::eax;
using block_graph::BasicBlock;
using block_graph::BasicBlockAssembler;
using block_graph::BasicBlockReference;
using block_graph::BlockGraph;
using block_graph::Displacement;
using block_graph::Immediate;
using block_graph::Operand;

typedef block_graph::TypedBlock<CoverageData> CoverageDataBlock;

bool AddCoverageDataSection(BlockGraph* block_graph,
                            BlockGraph::Block** coverage_data_block) {
  DCHECK(block_graph != NULL);
  DCHECK(coverage_data_block != NULL);

  BlockGraph::Section* coverage_section = block_graph->FindSection(
      common::kCoverageClientDataSectionName);
  if (coverage_section != NULL) {
    LOG(ERROR) << "Block-graph already contains a code coverage data section ("
               << common::kCoverageClientDataSectionName << ").";
    return false;
  }

  coverage_section = block_graph->AddSection(
      common::kCoverageClientDataSectionName,
      common::kCoverageClientDataSectionCharacteristics);
  DCHECK(coverage_section != NULL);

  BlockGraph::Block* block =
      block_graph->AddBlock(BlockGraph::DATA_BLOCK,
                            sizeof(CoverageData),
                            "Coverage data");
  DCHECK(block != NULL);
  block->set_section(coverage_section->id());

  CoverageData coverage_data = {};
  coverage_data.magic = common::kCoverageClientMagic;
  coverage_data.version = common::kCoverageClientVersion;

  block->CopyData(sizeof(coverage_data), &coverage_data);
  *coverage_data_block = block;

  return true;
}

}  // namespace

const char CoverageInstrumentationTransform::kTransformName[] =
    "CoverageInstrumentationTransform";

CoverageInstrumentationTransform::CoverageInstrumentationTransform()
    : coverage_data_block_(NULL) {
}

bool CoverageInstrumentationTransform::TransformBasicBlockSubGraph(
    BlockGraph* block_graph,
    BasicBlockSubGraph* basic_block_subgraph) {
  DCHECK(block_graph != NULL);
  DCHECK(basic_block_subgraph != NULL);

  // Iterate over the basic blocks.
  BasicBlockSubGraph::BBCollection::iterator it =
      basic_block_subgraph->basic_blocks().begin();
  for (; it != basic_block_subgraph->basic_blocks().end(); ++it) {
    BasicBlockSubGraph::BasicBlock& bb = it->second;

    // We're only interested in code blocks.
    if (bb.type() != BasicBlock::BASIC_CODE_BLOCK)
      continue;

    // Find the source range associated with this basic-block.
    // TODO(chrisha): Make this a utility function on BasicBlock and eventually
    //     move all of the data into instructions and successors.
    const BlockGraph::Block::SourceRanges::RangePair* range_pair =
        basic_block_subgraph->original_block()->source_ranges().FindRangePair(
            BlockGraph::Block::SourceRanges::SourceRange(bb.offset(), 1));

    // If there's no source data, something has gone terribly wrong. In fact, it
    // likely means that we've stacked transforms and new instructions have
    // been prepended to this BB. We don't support this yet.
    DCHECK(range_pair != NULL);

    // We prepend each basic code block with the following instructions:
    //   0. push eax
    //   1. mov eax, dword ptr[basic_block_seen_array]
    //   2. mov byte ptr[eax + basic_block_index], 1
    //   3. pop eax
    BasicBlockAssembler assm(bb.instructions().begin(),
                             &bb.instructions());
    // Prepend the instrumentation instructions.
    assm.push(eax);
    static const BlockGraph::Offset kDstOffset =
        offsetof(CoverageData, basic_block_seen_array);
    assm.mov(eax, Operand(Displacement(coverage_data_block_, kDstOffset)));
    assm.mov_b(Operand(eax, Displacement(bb_ranges_.size())), Immediate(1));
    assm.pop(eax);

    // Get the RVA of the BB by translating its offset. We also get its size
    // from the source range. This assumes that the BB is an original
    // untransformed BB.
    const BlockGraph::Block::DataRange& data_range = range_pair->first;
    const BlockGraph::Block::SourceRange& src_range = range_pair->second;
    core::RelativeAddress bb_addr = src_range.start() +
        (bb.offset() - data_range.start());
    size_t bb_size = src_range.size();
    bb_ranges_.push_back(RelativeAddressRange(bb_addr, bb_size));
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

  if (bb_ranges_.size() == 0) {
    LOG(WARNING) << "Encountered no basic code blocks during instrumentation.";
    return true;
  }

  // Set the final basic block count. This is used by the runtime library to
  // know how big an array to allocate for the statistics.
  CoverageDataBlock coverage_data;
  DCHECK(coverage_data_block_ != NULL);
  CHECK(coverage_data.Init(0, coverage_data_block_));
  coverage_data->basic_block_count = bb_ranges_.size();

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
                            bb_ranges_.size(),
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

}  // namespace transforms
}  // namespace instrument
