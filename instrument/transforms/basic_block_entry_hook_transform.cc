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
// Implements the BasicBlockEntryHookTransform class.

#include "syzygy/instrument/transforms/basic_block_entry_hook_transform.h"

#include "base/logging.h"
#include "syzygy/block_graph/block_util.h"
#include "syzygy/common/basic_block_frequency_data.h"
#include "syzygy/instrument/transforms/entry_thunk_transform.h"
#include "syzygy/pe/block_util.h"
#include "syzygy/pe/pe_utils.h"
#include "syzygy/pe/transforms/add_imports_transform.h"

namespace instrument {
namespace transforms {

namespace {

using ::common::kBasicBlockEntryAgentId;
using block_graph::BasicBlock;
using block_graph::BasicCodeBlock;
using block_graph::BasicBlockAssembler;
using block_graph::BlockGraph;
using block_graph::Displacement;
using block_graph::Immediate;
using block_graph::Operand;

typedef BasicBlockEntryHookTransform::RelativeAddressRange RelativeAddressRange;

const char kDefaultModuleName[] = "basic_block_entry.dll";
const char kBasicBlockEnter[] = "_basic_block_enter";

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

// Sets up the basic-block entry hook import.
bool SetupEntryHook(BlockGraph* block_graph,
                    BlockGraph::Block* header_block,
                    const std::string& module_name,
                    BlockGraph::Reference* basic_block_enter) {
  DCHECK(block_graph != NULL);
  DCHECK(header_block != NULL);
  DCHECK(basic_block_enter != NULL);

  // Setup the import module.
  pe::transforms::AddImportsTransform::ImportedModule module(module_name);
  size_t bb_index = module.AddSymbol(kBasicBlockEnter);

  // Setup the add-imports transform.
  pe::transforms::AddImportsTransform add_imports;
  add_imports.AddModule(&module);

  // Add the imports to the block-graph.
  if (!ApplyBlockGraphTransform(&add_imports, block_graph, header_block)) {
    LOG(ERROR) << "Unable to add import entry for basic-block hook function.";
    return false;
  }

  // Get a reference to the entry-hook function.
  if (!module.GetSymbolReference(bb_index, basic_block_enter)) {
    LOG(ERROR) << "Unable to get " << kBasicBlockEnter << ".";
    return false;
  }
  DCHECK(basic_block_enter->IsValid());

  return true;
}

}  // namespace

const char BasicBlockEntryHookTransform::kTransformName[] =
    "BasicBlockEntryHookTransform";

BasicBlockEntryHookTransform::BasicBlockEntryHookTransform()
  : add_frequency_data_(kBasicBlockEntryAgentId),
    thunk_section_(NULL),
    instrument_dll_name_(kDefaultModuleName),
    set_src_ranges_for_thunks_(false) {
}

bool BasicBlockEntryHookTransform::PreBlockGraphIteration(
    BlockGraph* block_graph,
    BlockGraph::Block* header_block) {
  DCHECK(block_graph != NULL);
  DCHECK(header_block != NULL);

  // Setup basic block entry hook.
  if (!SetupEntryHook(block_graph,
                      header_block,
                      instrument_dll_name_,
                      &bb_entry_hook_ref_)) {
    return false;
  }

  // Add the static basic-block frequency data.
  if (!ApplyBlockGraphTransform(
          &add_frequency_data_, block_graph, header_block)) {
    LOG(ERROR) << "Failed to insert basic-block frequency data.";
    return false;
  }

  return true;
}

bool BasicBlockEntryHookTransform::OnBlock(BlockGraph* block_graph,
                                           BlockGraph::Block* block) {
  DCHECK(block_graph != NULL);
  DCHECK(block != NULL);

  if (block->type() != BlockGraph::CODE_BLOCK)
    return true;

  if (!pe::CodeBlockIsBasicBlockDecomposable(block)) {
    // TODO(rogerm): Thunk the entry-point to this block with a basic-block
    //     entry-point hook that represents the entire block.
    return true;
  }

  if (!ApplyBasicBlockSubGraphTransform(this, block_graph, block, NULL))
    return false;

  return true;
}

bool BasicBlockEntryHookTransform::TransformBasicBlockSubGraph(
    BlockGraph* block_graph , BasicBlockSubGraph* subgraph) {
  // TODO(rogerm): A lot of this is boilerplate that can be hoisted to an
  //     IterativeBasicBlockSubgraphTransform (or some such). In particular,
  //     iterating the subgraph, dispatch on code/data basic block, and the
  //     bb_ranges_ are duplicated in the coverage transform.
  DCHECK(block_graph != NULL);
  DCHECK(subgraph != NULL);
  DCHECK(bb_entry_hook_ref_.IsValid());
  DCHECK(add_frequency_data_.frequency_data_block() != NULL);

  // Insert a call to the basic-block entry hook at the top of each code
  // basic-block. We use the id_generator_ to assign an ID to each basic-block.
  BasicBlockSubGraph::BBCollection::iterator it =
      subgraph->basic_blocks().begin();
  for (; it != subgraph->basic_blocks().end(); ++it) {
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

    // We use the location/index in the bb_ranges vector of the current
    // basic-block range as the basic_block_id, and we pass a pointer to
    // the frequency data block as the module_data parameter. We then make
    // a memory indirect call to the bb_entry_hook.
    Immediate basic_block_id(bb_ranges_.size(), core::kSize32Bit );
    Immediate module_data(add_frequency_data_.frequency_data_block(), 0);
    Operand bb_entry_hook(Displacement(bb_entry_hook_ref_.referenced(),
                                       bb_entry_hook_ref_.offset()));

    // Assemble entry hook instrumentation into the instruction stream.
    BasicBlockAssembler bb_asm(bb->instructions().begin(), &bb->instructions());
    bb_asm.push(basic_block_id);
    bb_asm.push(module_data);
    bb_asm.call(bb_entry_hook);

    bb_ranges_.push_back(source_range);
  }

  return true;
}

bool BasicBlockEntryHookTransform::PostBlockGraphIteration(
    BlockGraph* block_graph, BlockGraph::Block* header_block) {
  DCHECK(block_graph != NULL);
  DCHECK(header_block != NULL);

  size_t num_basic_blocks = bb_ranges_.size();
  if (num_basic_blocks == 0) {
    LOG(WARNING) << "Encountered no basic code blocks during instrumentation.";
    return true;
  }

  if (!add_frequency_data_.ConfigureFrequencyDataBuffer(num_basic_blocks,
                                                        sizeof(uint32))) {
    LOG(ERROR) << "Failed to configure frequency data buffer.";
    return false;
  }

  // Add the module entry thunks.
  EntryThunkTransform add_thunks;
  add_thunks.set_only_instrument_module_entry(true);
  add_thunks.set_instrument_dll_name(instrument_dll_name_);
  add_thunks.set_src_ranges_for_thunks(set_src_ranges_for_thunks_);

  Immediate module_data(add_frequency_data_.frequency_data_block(), 0);
  if (!add_thunks.SetEntryThunkParameter(module_data)) {
    LOG(ERROR) << "Failed to configure the entry thunks with the module_data "
               << "parameter.";
    return false;
  }

  if (!ApplyBlockGraphTransform(&add_thunks, block_graph, header_block)) {
    LOG(ERROR) << "Unable to thunk module entry points.";
    return false;
  }
  thunk_section_ = add_thunks.thunk_section();
  DCHECK(thunk_section_ != NULL);

#ifndef NDEBUG
  // If we're in debug mode then sanity check the basic block ranges. When
  // sorted, they should not overlap.
  RelativeAddressRangeVector bb_ranges_copy(bb_ranges_);
  std::sort(bb_ranges_copy.begin(), bb_ranges_copy.end());
  DCHECK(std::adjacent_find(bb_ranges_copy.begin(),
                            bb_ranges_copy.end(),
                            RelativeAddressRangesOverlapFunctor()) ==
             bb_ranges_copy.end());
#endif

  return true;
}


}  // namespace transforms
}  // namespace instrument
