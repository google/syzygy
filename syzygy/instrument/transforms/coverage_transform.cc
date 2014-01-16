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
#include "syzygy/block_graph/block_util.h"
#include "syzygy/common/indexed_frequency_data.h"
#include "syzygy/core/disassembler_util.h"
#include "syzygy/pe/pe_utils.h"

namespace instrument {
namespace transforms {

namespace {

using common::IndexedFrequencyData;
using common::kBasicBlockCoverageAgentId;
using core::eax;
using block_graph::ApplyBasicBlockSubGraphTransform;
using block_graph::ApplyBlockGraphTransform;
using block_graph::BasicBlock;
using block_graph::BasicCodeBlock;
using block_graph::BasicBlockAssembler;
using block_graph::BasicBlockReference;
using block_graph::BlockGraph;
using block_graph::Displacement;
using block_graph::Immediate;
using block_graph::Operand;
using block_graph::TransformPolicyInterface;

typedef CoverageInstrumentationTransform::RelativeAddressRange
    RelativeAddressRange;

const BlockGraph::Offset kFrequencyDataOffset =
    offsetof(IndexedFrequencyData, frequency_data);

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
    : add_bb_freq_data_tx_(kBasicBlockCoverageAgentId,
                           "Basic-Block Frequency Data",
                           common::kBasicBlockFrequencyDataVersion,
                           common::IndexedFrequencyData::COVERAGE,
                           sizeof(common::IndexedFrequencyData)) {
  // Initialize the EntryThunkTransform.
  entry_thunk_tx_.set_instrument_unsafe_references(false);
  entry_thunk_tx_.set_only_instrument_module_entry(true);
}

bool CoverageInstrumentationTransform::TransformBasicBlockSubGraph(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BasicBlockSubGraph* basic_block_subgraph) {
  DCHECK(policy != NULL);
  DCHECK(block_graph != NULL);
  DCHECK(basic_block_subgraph != NULL);

  BlockGraph::Block* data_block = add_bb_freq_data_tx_.frequency_data_block();
  DCHECK(data_block != NULL);
  DCHECK_EQ(sizeof(IndexedFrequencyData), data_block->data_size());

  // Iterate over the basic blocks.
  BasicBlockSubGraph::BBCollection::iterator it =
      basic_block_subgraph->basic_blocks().begin();
  for (; it != basic_block_subgraph->basic_blocks().end(); ++it) {
    // We're only interested in code blocks.
    BasicCodeBlock* bb = BasicCodeBlock::Cast(*it);
    if (bb == NULL)
      continue;

    // Find the source range associated with this basic-block.
    BlockGraph::Block::SourceRange source_range;
    if (!GetBasicBlockSourceRange(*bb, &source_range)) {
      LOG(ERROR) << "Unable to get source range for basic block '"
                 << bb->name() << "'";
      return false;
    }

    // We prepend each basic code block with the following instructions:
    //   0. push eax
    //   1. mov eax, dword ptr[data.frequency_data]
    //   2. mov byte ptr[eax + basic_block_index], 1
    //   3. pop eax
    BasicBlockAssembler assm(bb->instructions().begin(), &bb->instructions());

    // Prepend the instrumentation instructions.
    assm.push(eax);
    assm.mov(eax, Operand(Displacement(data_block, kFrequencyDataOffset)));
    assm.mov_b(Operand(eax, Displacement(bb_ranges_.size())), Immediate(1));
    assm.pop(eax);

    bb_ranges_.push_back(source_range);
  }

  return true;
}

bool CoverageInstrumentationTransform::PreBlockGraphIteration(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BlockGraph::Block* header_block) {
  DCHECK_NE(reinterpret_cast<TransformPolicyInterface*>(NULL), policy);
  DCHECK_NE(reinterpret_cast<BlockGraph*>(NULL), block_graph);
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), header_block);
  DCHECK_EQ(BlockGraph::PE_IMAGE, block_graph->image_format());

  if (!ApplyBlockGraphTransform(
          &add_bb_freq_data_tx_, policy, block_graph, header_block)) {
    LOG(ERROR) << "Failed to insert basic-block frequency data.";
    return false;
  }

  return true;
}

bool CoverageInstrumentationTransform::OnBlock(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BlockGraph::Block* block) {
  DCHECK(policy != NULL);
  DCHECK(block_graph != NULL);
  DCHECK(block != NULL);

  // We only care about blocks that are safe for basic block decomposition.
  if (!policy->BlockIsSafeToBasicBlockDecompose(block))
    return true;

  // Apply our basic block transform.
  if (!ApplyBasicBlockSubGraphTransform(
      this, policy, block_graph, block, NULL)) {
    return false;
  }

  return true;
}

bool CoverageInstrumentationTransform::PostBlockGraphIteration(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BlockGraph::Block* header_block) {
  DCHECK(policy != NULL);
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
          &entry_thunk_tx_, policy, block_graph, header_block)) {
    LOG(ERROR) << "Failed to thunk image entry points.";
    return false;
  }

  size_t num_basic_blocks = bb_ranges_.size();
  if (num_basic_blocks == 0) {
    LOG(WARNING) << "Encountered no basic code blocks during instrumentation.";
    return true;
  }

  if (!add_bb_freq_data_tx_.ConfigureFrequencyDataBuffer(num_basic_blocks,
                                                         1,
                                                         sizeof(uint8))) {
    LOG(ERROR) << "Failed to configure frequency data buffer.";
    return false;
  }

#ifndef NDEBUG
  // If we're in debug mode then sanity check the basic block ranges. When
  // sorted, they should not overlap.
  RelativeAddressRangeVector bb_ranges(bb_ranges_);
  std::sort(bb_ranges.begin(), bb_ranges.end());
  DCHECK(std::adjacent_find(bb_ranges.begin(), bb_ranges.end(),
                            RelativeAddressRangesOverlapFunctor()) ==
      bb_ranges.end());
#endif

  return true;
}

}  // namespace transforms
}  // namespace instrument
