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
//
// Implements the BasicBlockEntryHookTransform class.

#include "syzygy/instrument/transforms/basic_block_entry_hook_transform.h"

#include "base/logging.h"
#include "syzygy/pe/block_util.h"
#include "syzygy/pe/pe_utils.h"
#include "syzygy/pe/transforms/add_imports_transform.h"

namespace instrument {
namespace transforms {

const char BasicBlockEntryHookTransform::kDefaultModuleName[] =
    "basic_block_entry.dll";

const char BasicBlockEntryHookTransform::kDefaultFunctionName[] =
    "_basic_block_enter";

const char BasicBlockEntryHookTransform::kTransformName[] =
    "BasicBlockEntryHookTransform";

BasicBlockEntryHookTransform::BasicBlockEntryHookTransform()
    : module_name_(kDefaultModuleName), function_name_(kDefaultFunctionName) {
}

BasicBlockEntryHookTransform::BasicBlockEntryHookTransform(
    const base::StringPiece& module_name,
    const base::StringPiece& function_name)
        : module_name_(module_name.begin(), module_name.end()),
          function_name_(function_name.begin(), function_name.end()) {
  DCHECK(!module_name.empty());
  DCHECK(!function_name.empty());
}

bool BasicBlockEntryHookTransform::PreBlockGraphIteration(
    BlockGraph* block_graph,
    BlockGraph::Block* header_block) {
  pe::transforms::AddImportsTransform::ImportedModule module(module_name_);
  size_t function_index = module.AddSymbol(function_name_);

  pe::transforms::AddImportsTransform add_imports;
  add_imports.AddModule(&module);

  if (!ApplyBlockGraphTransform(&add_imports, block_graph, header_block)) {
    LOG(ERROR) << "Unable to add import entry for basic-block hook function.";
    return false;
  }

  if (!module.GetSymbolReference(function_index, &bb_entry_hook_ref_)) {
    LOG(ERROR) << "Unable to get reference to basic-block entry hook import "
               << module_name_ << ":" << function_name_ << ".";
    return false;
  }

  DCHECK(bb_entry_hook_ref_.IsValid());

  return true;
}

bool BasicBlockEntryHookTransform::OnBlock(BlockGraph* block_graph,
                                           BlockGraph::Block* block) {
  DCHECK(block_graph != NULL);
  DCHECK(block != NULL);

  if (block->type() != BlockGraph::CODE_BLOCK)
    return true;

  if (!pe::CodeBlockIsBasicBlockDecomposable(block))
    return true;

  if (!ApplyBasicBlockSubGraphTransform(this, block_graph, block, NULL))
    return false;

  return true;
}

bool BasicBlockEntryHookTransform::TransformBasicBlockSubGraph(
    BlockGraph* block_graph , BasicBlockSubGraph* subgraph) {
  DCHECK(block_graph != NULL);
  DCHECK(subgraph != NULL);
  DCHECK(bb_entry_hook_ref_.IsValid());

  // Insert a call to the basic-block entry hook at the top of each code
  // basic-block. We use the id_generator_ to assign an ID to each basic-block.
  BasicBlockSubGraph::BBCollection::iterator it =
      subgraph->basic_blocks().begin();
  for (; it != subgraph->basic_blocks().end(); ++it) {
    BasicBlock& bb = it->second;
    if (bb.type() != BasicBlock::BASIC_CODE_BLOCK)
      continue;

    block_graph::BasicBlockAssembler bb_asm(bb.instructions().begin(),
                                            &bb.instructions());

    bb_asm.push(block_graph::Immediate(bb_addresses_.size(), core::kSize32Bit));
    bb_asm.call(block_graph::Immediate(bb_entry_hook_ref_.referenced(),
                                       bb_entry_hook_ref_.offset()));

    // Find the source range associated with this basic-block and translate
    // that to an RVA.
    // TODO(rogerm): Replace this with a call to request the RVA directly from
    //     a basic-block, once that call becomes available.
    const BlockGraph::Block::SourceRanges::RangePair* bb_range_pair =
        subgraph->original_block()->source_ranges().FindRangePair(
            BlockGraph::Block::SourceRanges::SourceRange(bb.offset(), 1));
    DCHECK(bb_range_pair != NULL);
    const BlockGraph::Block::DataRange& data_range = bb_range_pair->first;
    const BlockGraph::Block::SourceRange& src_range = bb_range_pair->second;
    core::RelativeAddress bb_addr = src_range.start() +
        (bb.offset() - data_range.start());

    // Add the basic-block address to the id-to-address vector.
    bb_addresses_.push_back(bb_addr);
  }

  return true;
}

}  // namespace transforms
}  // namespace instrument
