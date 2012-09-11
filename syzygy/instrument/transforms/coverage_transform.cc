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

#include "syzygy/instrument/transforms/coverage_transform.h"

#include "syzygy/block_graph/basic_block_assembler.h"
#include "syzygy/common/basic_block_frequency_data.h"
#include "syzygy/core/disassembler_util.h"
#include "syzygy/pe/block_util.h"
#include "syzygy/pe/pe_utils.h"

namespace instrument {
namespace transforms {

namespace {

using common::BasicBlockFrequencyData;
using common::kBasicBlockCoverageAgentId;
using core::eax;
using block_graph::ApplyBasicBlockSubGraphTransform;
using block_graph::ApplyBlockGraphTransform;
using block_graph::BasicBlock;
using block_graph::BasicBlockAssembler;
using block_graph::BasicBlockReference;
using block_graph::BlockGraph;
using block_graph::Displacement;
using block_graph::Immediate;
using block_graph::Operand;

typedef CoverageInstrumentationTransform::RelativeAddressRange
    RelativeAddressRange;

const BlockGraph::Offset kFrequencyDataOffset =
    offsetof(BasicBlockFrequencyData, frequency_data);

// Compares two relative address ranges to see if they overlap. Assumes they
// are already sorted. This is used to validate basic-block ranges.
struct RelativeAddressRangesOverlapFunctor {
  bool operator()(const RelativeAddressRange& r1,
                  const RelativeAddressRange& r2) const {
    DCHECK_LT(r1.start(), r2.start());

    if (r1.end() > r2.start())
      return true;

    return false;
  }
};

}  // namespace

const char CoverageInstrumentationTransform::kTransformName[] =
    "CoverageInstrumentationTransform";

CoverageInstrumentationTransform::CoverageInstrumentationTransform()
    : add_bb_freq_data_tx_(kBasicBlockCoverageAgentId) {
  // Initialize the EntryThunkTransform.
  entry_thunk_tx_.set_instrument_unsafe_references(false);
  entry_thunk_tx_.set_only_instrument_module_entry(true);
}

bool CoverageInstrumentationTransform::TransformBasicBlockSubGraph(
    BlockGraph* block_graph,
    BasicBlockSubGraph* basic_block_subgraph) {
  DCHECK(block_graph != NULL);
  DCHECK(basic_block_subgraph != NULL);

  BlockGraph::Block* data_block = add_bb_freq_data_tx_.frequency_data_block();
  DCHECK(data_block != NULL);
  DCHECK_EQ(sizeof(BasicBlockFrequencyData), data_block->data_size());

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
    //   1. mov eax, dword ptr[data.frequency_data]
    //   2. mov byte ptr[eax + basic_block_index], 1
    //   3. pop eax
    BasicBlockAssembler assm(bb.instructions().begin(), &bb.instructions());

    // Prepend the instrumentation instructions.
    assm.push(eax);
    assm.mov(eax, Operand(Displacement(data_block, kFrequencyDataOffset)));
    assm.mov_b(Operand(eax, Displacement(bb_ranges_.size())), Immediate(1));
    assm.pop(eax);

    const BlockGraph::Block::DataRange& data_range = range_pair->first;
    const BlockGraph::Block::SourceRange& src_range = range_pair->second;

    // If we have multiple successors then the instruction following this BB
    // is a conditional. The arcs of the conditional will often be referred to
    // by the line information in a PDB (for example, an 'else' on its own
    // line) but it is meaningless to mark that line as instrumented and/or
    // executed. Thus, we keep a list of conditional successor address ranges
    // so they can be excluded from coverage results.
    if (bb.successors().size() == 2) {
      const block_graph::Successor& succ = bb.successors().front();
      DCHECK_NE(BasicBlock::kNoOffset, succ.instruction_offset());
      DCHECK_NE(0u, succ.instruction_size());

      RelativeAddress succ_addr = src_range.start() +
          (succ.instruction_offset() - data_range.start());
      conditional_ranges_.push_back(
          RelativeAddressRange(succ_addr, succ.instruction_size()));
    }

    // Get the RVA of the BB by translating its offset, and remember the range
    // associated with this BB.
    core::RelativeAddress bb_addr = src_range.start() +
        (bb.offset() - data_range.start());
    bb_ranges_.push_back(RelativeAddressRange(bb_addr, bb.size()));
  }

  return true;
}

bool CoverageInstrumentationTransform::PreBlockGraphIteration(
    BlockGraph* block_graph, BlockGraph::Block* header_block) {
  DCHECK(block_graph != NULL);
  DCHECK(header_block != NULL);

  if (!ApplyBlockGraphTransform(
          &add_bb_freq_data_tx_, block_graph, header_block)) {
    LOG(ERROR) << "Failed to insert basic-block frequency data.";
    return false;
  }

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
  if (!ApplyBasicBlockSubGraphTransform(this, block_graph, block, NULL)) {
    return false;
  }

  return true;
}

bool CoverageInstrumentationTransform::PostBlockGraphIteration(
    BlockGraph* block_graph, BlockGraph::Block* header_block) {
  DCHECK(block_graph != NULL);
  DCHECK(header_block != NULL);

  // Get a reference to the frequency data and make that the parameter that
  // we pass to the entry thunks. We run the thunk transform after the coverage
  // instrumentation transform as it creates new code blocks that we don't
  // want to instrument.
  block_graph::Immediate ref_to_freq_data(
      add_bb_freq_data_tx_.frequency_data_block(), 0);
  entry_thunk_tx_.SetEntryThunkParameter(ref_to_freq_data);
  if (!ApplyBlockGraphTransform(
          &entry_thunk_tx_, block_graph, header_block)) {
    LOG(ERROR) << "Failed to thunk image entry points.";
    return false;
  }

  size_t num_basic_blocks = bb_ranges_.size();
  if (num_basic_blocks == 0) {
    LOG(WARNING) << "Encountered no basic code blocks during instrumentation.";
    return true;
  }

  if (!add_bb_freq_data_tx_.AllocateFrequencyDataBuffer(num_basic_blocks,
                                                       sizeof(uint8))) {
    LOG(ERROR) << "Failed to allocate frequency data buffer.";
    return false;
  }

  // Sort these for efficient searching in the coverage grinder.
  std::sort(conditional_ranges_.begin(), conditional_ranges_.end());

#ifndef NDEBUG
  // If we're in debug mode then sanity check the basic block ranges. When
  // sorted, they should not overlap.
  RelativeAddressRangeVector bb_ranges(bb_ranges_);
  std::sort(bb_ranges.begin(), bb_ranges.end());
  DCHECK(std::adjacent_find(bb_ranges.begin(), bb_ranges.end(),
                            RelativeAddressRangesOverlapFunctor()) ==
      bb_ranges.end());

  // Also sanity check the conditional instruction ranges.
  DCHECK(std::adjacent_find(conditional_ranges_.begin(),
                            conditional_ranges_.end(),
                            RelativeAddressRangesOverlapFunctor()) ==
      conditional_ranges_.end());
#endif

  return true;
}

}  // namespace transforms
}  // namespace instrument
