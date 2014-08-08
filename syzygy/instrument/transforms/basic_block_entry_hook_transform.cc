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
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "syzygy/agent/basic_block_entry/basic_block_entry.h"
#include "syzygy/block_graph/block_builder.h"
#include "syzygy/block_graph/block_util.h"
#include "syzygy/common/defs.h"
#include "syzygy/common/indexed_frequency_data.h"
#include "syzygy/instrument/transforms/entry_thunk_transform.h"
#include "syzygy/pe/pe_utils.h"
#include "syzygy/pe/transforms/pe_add_imports_transform.h"

namespace instrument {
namespace transforms {

namespace {

using agent::basic_block_entry::BasicBlockEntry;
using block_graph::BasicBlock;
using block_graph::BasicBlockAssembler;
using block_graph::BasicBlockReference;
using block_graph::BasicCodeBlock;
using block_graph::BlockBuilder;
using block_graph::BlockGraph;
using block_graph::Displacement;
using block_graph::Immediate;
using block_graph::Operand;
using block_graph::Successor;
using block_graph::TransformPolicyInterface;
using common::kBasicBlockEntryAgentId;
using pe::transforms::PEAddImportsTransform;

typedef BasicBlockEntryHookTransform::RelativeAddressRange RelativeAddressRange;
typedef BasicBlockEntry::BasicBlockIndexedFrequencyData
   BasicBlockIndexedFrequencyData;
typedef pe::transforms::ImportedModule ImportedModule;

const char kDefaultModuleName[] = "basic_block_entry_client.dll";
const char kBasicBlockEnter[] = "_increment_indexed_freq_data";

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

// Sets up the basic-block entry and the frequency data hooks import.
bool SetupEntryHooks(const TransformPolicyInterface* policy,
                     BlockGraph* block_graph,
                     BlockGraph::Block* header_block,
                     const std::string& module_name,
                     BlockGraph::Reference* basic_block_enter) {
  DCHECK(block_graph != NULL);
  DCHECK(header_block != NULL);
  DCHECK(basic_block_enter != NULL);

  // Setup the import module.
  ImportedModule module(module_name);
  size_t bb_index = module.AddSymbol(kBasicBlockEnter,
                                     ImportedModule::kAlwaysImport);

  // Setup the add-imports transform.
  PEAddImportsTransform add_imports;
  add_imports.AddModule(&module);

  // Add the imports to the block-graph.
  if (!ApplyBlockGraphTransform(
          &add_imports, policy, block_graph, header_block)) {
    LOG(ERROR) << "Unable to add import entry hook functions.";
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

void AddSuccessorBetween(Successor::Condition condition,
                         BasicCodeBlock* from,
                         BasicCodeBlock* to) {
  from->successors().push_back(
      Successor(condition,
                BasicBlockReference(BlockGraph::RELATIVE_REF,
                                    BlockGraph::Reference::kMaximumSize,
                                    to),
                0));
}

}  // namespace

const char BasicBlockEntryHookTransform::kTransformName[] =
    "BasicBlockEntryHookTransform";

BasicBlockEntryHookTransform::BasicBlockEntryHookTransform()
  : add_frequency_data_(kBasicBlockEntryAgentId,
                        "Basic-Block Frequency Data",
                        common::kBasicBlockFrequencyDataVersion,
                        common::IndexedFrequencyData::BASIC_BLOCK_ENTRY,
                        sizeof(BasicBlockIndexedFrequencyData)),
    thunk_section_(NULL),
    instrument_dll_name_(kDefaultModuleName),
    set_src_ranges_for_thunks_(false),
    set_inline_fast_path_(false) {
}

bool BasicBlockEntryHookTransform::PreBlockGraphIteration(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BlockGraph::Block* header_block) {
  DCHECK_NE(reinterpret_cast<TransformPolicyInterface*>(NULL), policy);
  DCHECK_NE(reinterpret_cast<BlockGraph*>(NULL), block_graph);
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), header_block);
  DCHECK_EQ(BlockGraph::PE_IMAGE, block_graph->image_format());

  // Setup basic block entry and the frequency data hooks.
  if (!SetupEntryHooks(policy,
                       block_graph,
                       header_block,
                       instrument_dll_name_,
                       &bb_entry_hook_ref_)) {
    return false;
  }

  // Add the static basic-block frequency data.
  if (!ApplyBlockGraphTransform(
          &add_frequency_data_, policy, block_graph, header_block)) {
    LOG(ERROR) << "Failed to insert basic-block frequency data.";
    return false;
  }

  // Find or create the section we put our thunks in.
  thunk_section_ = block_graph->FindOrAddSection(common::kThunkSectionName,
                                                 pe::kCodeCharacteristics);
  DCHECK(thunk_section_ != NULL);

  return true;
}

bool BasicBlockEntryHookTransform::OnBlock(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BlockGraph::Block* block) {
  DCHECK(policy != NULL);
  DCHECK(block_graph != NULL);
  DCHECK(block != NULL);
  DCHECK(thunk_section_ != NULL);

  // Skip blocks created by this transform.
  if (block->section() == thunk_section_->id())
    return true;

  if (block->type() != BlockGraph::CODE_BLOCK)
    return true;

  if (!policy->BlockIsSafeToBasicBlockDecompose(block)) {
    if (!ThunkNonDecomposableCodeBlock(block_graph, block))
      return false;
    return true;
  }

  if (!ApplyBasicBlockSubGraphTransform(this, policy, block_graph, block, NULL))
    return false;

  return true;
}

bool BasicBlockEntryHookTransform::TransformBasicBlockSubGraph(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph ,
    BasicBlockSubGraph* subgraph) {
  // TODO(rogerm): A lot of this is boilerplate that can be hoisted to an
  //     IterativeBasicBlockSubgraphTransform (or some such). In particular,
  //     iterating the subgraph, dispatch on code/data basic block, and the
  //     bb_ranges_ are duplicated in the coverage transform.
  DCHECK(policy != NULL);
  DCHECK(block_graph != NULL);
  DCHECK(subgraph != NULL);
  DCHECK(bb_entry_hook_ref_.IsValid());
  DCHECK(add_frequency_data_.frequency_data_block() != NULL);

  // Insert a call to the basic-block entry hook at the top of each code
  // basic-block.
  BasicBlockSubGraph::BBCollection::iterator it =
      subgraph->basic_blocks().begin();
  for (; it != subgraph->basic_blocks().end(); ++it) {
    BasicCodeBlock* bb = BasicCodeBlock::Cast(*it);
    if (bb == NULL || bb->is_padding())
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
    Immediate basic_block_id(bb_ranges_.size(), core::kSize32Bit);
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
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BlockGraph::Block* header_block) {
  DCHECK(policy != NULL);
  DCHECK(block_graph != NULL);
  DCHECK(header_block != NULL);

  size_t num_basic_blocks = bb_ranges_.size();
  if (num_basic_blocks == 0) {
    LOG(WARNING) << "Encountered no basic code blocks during instrumentation.";
    return true;
  }

  if (!add_frequency_data_.ConfigureFrequencyDataBuffer(num_basic_blocks,
                                                        1,
                                                        sizeof(uint32))) {
    LOG(ERROR) << "Failed to configure frequency data buffer.";
    return false;
  }

  // Initialized BasicBlock agent specific fields
  block_graph::TypedBlock<BasicBlockIndexedFrequencyData> frequency_data;
  CHECK(frequency_data.Init(0, add_frequency_data_.frequency_data_block()));
  frequency_data->fs_slot = 0;
  frequency_data->tls_index = TLS_OUT_OF_INDEXES;

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

  if (!ApplyBlockGraphTransform(
          &add_thunks, policy, block_graph, header_block)) {
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

bool BasicBlockEntryHookTransform::ThunkNonDecomposableCodeBlock(
    BlockGraph* block_graph, BlockGraph::Block* code_block) {
  DCHECK(block_graph != NULL);
  DCHECK(code_block != NULL);

  // Typedef for the thunk block map. The key is the offset within the callee
  // block and the value is the thunk block that forwards to the callee at that
  // offset.
  typedef std::map<BlockGraph::Offset, BlockGraph::Block*> ThunkBlockMap;

  // We keep a cache of thunks we've already created (by target offset of the
  // entry-point into the block) so that we only create one thunk per entry
  // point.
  ThunkBlockMap thunk_block_map;

  // Iterate through all the block's referrers, creating thunks as we go.
  // We copy the referrer set for simplicity, as it's potentially mutated
  // in the loop.
  BlockGraph::Block::ReferrerSet referrers = code_block->referrers();
  BlockGraph::Block::ReferrerSet::const_iterator referrer_it(referrers.begin());
  for (; referrer_it != referrers.end(); ++referrer_it) {
    const BlockGraph::Block::Referrer& referrer = *referrer_it;
    if (!EnsureReferrerIsThunked(
            referrer, block_graph, code_block, &thunk_block_map)) {
      return false;
    }
  }

  return true;
}

bool BasicBlockEntryHookTransform::EnsureReferrerIsThunked(
    const BlockGraph::Block::Referrer& referrer,
    BlockGraph* block_graph,
    BlockGraph::Block* code_block,
    ThunkBlockMap* thunk_block_map) {
  DCHECK(block_graph != NULL);
  DCHECK(code_block != NULL);
  DCHECK(thunk_block_map != NULL);

  // Get the reference.
  BlockGraph::Reference ref;
  if (!referrer.first->GetReference(referrer.second, &ref)) {
    LOG(ERROR) << "Unable to get reference from referrer.";
    return false;
  }
  DCHECK_EQ(code_block, ref.referenced());

  // Skip self-references, except long references to the start of the block.
  // Note: This may currently miss important cases. Notably if a block contains
  //     more than one function, and the functions are mutually recursive, we'll
  //     only record the original entry to the block, but will miss the internal
  //     recursion. As-is, this does work for the common case where a block
  //     contains one self-recursive function, however.
  if (referrer.first == code_block) {
    // Skip short references.
    if (ref.size() < sizeof(core::AbsoluteAddress))
      return true;

    // Skip interior references. The block is not bb-decomposable so there is
    // nothing for us to do with them.
    if (ref.offset() != 0)
      return true;
  }

  // Get a thunk for the referenced offset from the thunk block map, creating
  // a new one if one does not already exist.
  BlockGraph::Block* thunk_block = NULL;
  if (!FindOrCreateThunk(block_graph, thunk_block_map, code_block, ref.offset(),
                         &thunk_block)) {
    LOG(ERROR) << "Unable to create thunk block.";
    return false;
  }
  DCHECK(thunk_block != NULL);

  // Update the referrer to point to the thunk.
  BlockGraph::Reference new_ref(ref.type(),
                                ref.size(),
                                thunk_block,
                                0, 0);
  referrer.first->SetReference(referrer.second, new_ref);

  return true;
}

bool BasicBlockEntryHookTransform::FindOrCreateThunk(
    BlockGraph* block_graph,
    ThunkBlockMap* thunk_block_map,
    BlockGraph::Block* code_block,
    BlockGraph::Offset offset,
    BlockGraph::Block** thunk) {
  DCHECK(block_graph != NULL);
  DCHECK(thunk_block_map != NULL);
  DCHECK(code_block != NULL);
  DCHECK(thunk != NULL);
  DCHECK_EQ(BlockGraph::CODE_BLOCK, code_block->type());

  // Do we already have a thunk defined for this offset? If so, return it.
  ThunkBlockMap::const_iterator thunk_it = thunk_block_map->find(offset);
  if (thunk_it != thunk_block_map->end()) {
    *thunk = thunk_it->second;
    return true;
  }

  *thunk = NULL;

  // Determine the name for this thunk.
  std::string name;
  if (offset == 0) {
    name = base::StringPrintf("%s%s",
                              code_block->name().c_str(),
                              common::kThunkSuffix);
  } else {
    name = base::StringPrintf("%s%s+%d",
                              code_block->name().c_str(),
                              common::kThunkSuffix,
                              offset);
  }

  // Set up a basic block subgraph containing a single block description, with
  // that block description containing a single empty basic block, and get an
  // assembler writing into that basic block.
  BasicBlockSubGraph subgraph;
  BasicCodeBlock* bb = subgraph.AddBasicCodeBlock(name);
  BasicBlockSubGraph::BlockDescription* desc = subgraph.AddBlockDescription(
      name,
      NULL,
      BlockGraph::CODE_BLOCK,
      thunk_section_->id(),
      1,
      0);
  desc->basic_block_order.push_back(bb);

  // Find the source range associated with this block.
  BlockGraph::Block::SourceRange source_range;
  if (!code_block->source_ranges().empty())
    source_range = code_block->source_ranges().range_pair(0).second;

  // Make sure we only push the source range if we have not already created
  // a source range mapping for this block (i.e., if the non-decomposable
  // block has multiple entry points, we want them to share an id). We can do
  // this because we handle one block at a time; so, all of a block's thunks
  // will be created as a group. This assertion is sanity checked in the
  // PostBlockGraphIteration function's check for overlapping source ranges.
  if (bb_ranges_.empty() || source_range != bb_ranges_.back())
    bb_ranges_.push_back(source_range);

  // We use the location/index in the bb_ranges vector of the current
  // basic-block range as the basic_block_id, and we pass a pointer to
  // the frequency data block as the module_data parameter. We then make
  // a memory indirect call to the bb_entry_hook.
  Immediate basic_block_id(bb_ranges_.size()-1, core::kSize32Bit);
  Immediate module_data(add_frequency_data_.frequency_data_block(), 0);
  Immediate original_function(Displacement(code_block, offset));
  Operand bb_entry_hook(Displacement(bb_entry_hook_ref_.referenced(),
                                     bb_entry_hook_ref_.offset()));

  // Assemble entry hook instrumentation into the thunk's instruction stream.
  // Note that we turn this into a simulated call, so that the return from
  // the bb entry hook continues from the thunked function.
  BasicBlockAssembler bb_asm(bb->instructions().begin(), &bb->instructions());
  bb_asm.push(basic_block_id);
  bb_asm.push(module_data);
  bb_asm.push(original_function);
  bb_asm.jmp(bb_entry_hook);

  // Condense the whole mess into a block.
  BlockBuilder block_builder(block_graph);
  if (!block_builder.Merge(&subgraph)) {
    LOG(ERROR) << "Failed to build thunk block.";
    return false;
  }

  // Exactly one new block should have been created.
  DCHECK_EQ(1u, block_builder.new_blocks().size());
  *thunk = block_builder.new_blocks().front();
  (*thunk_block_map)[offset] = *thunk;

  return true;
}

}  // namespace transforms
}  // namespace instrument
