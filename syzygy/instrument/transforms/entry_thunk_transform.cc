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

#include "syzygy/instrument/transforms/entry_thunk_transform.h"

#include "base/logging.h"
#include "base/strings/stringprintf.h"
#include "syzygy/block_graph/block_builder.h"
#include "syzygy/block_graph/block_util.h"
#include "syzygy/common/defs.h"
#include "syzygy/pe/pe_utils.h"
#include "syzygy/pe/transforms/pe_add_imports_transform.h"

namespace instrument {
namespace transforms {

using block_graph::BasicBlock;
using block_graph::BasicCodeBlock;
using block_graph::BasicBlockAssembler;
using block_graph::BasicBlockReference;
using block_graph::BasicBlockSubGraph;
using block_graph::BlockBuilder;
using block_graph::BlockGraph;
using block_graph::Displacement;
using block_graph::Operand;
using block_graph::TransformPolicyInterface;
using pe::transforms::PEAddImportsTransform;

typedef pe::transforms::ImportedModule ImportedModule;

const char EntryThunkTransform::kTransformName[] =
    "EntryThunkTransform";

const char EntryThunkTransform::kEntryHookName[] = "_indirect_penter";
const char EntryThunkTransform::kDllMainEntryHookName[] =
    "_indirect_penter_dllmain";
const char EntryThunkTransform::kExeMainEntryHookName[] =
    "_indirect_penter_exemain";
const char EntryThunkTransform::kDefaultInstrumentDll[] =
    "call_trace_client.dll";

EntryThunkTransform::EntryThunkTransform()
    : thunk_section_(NULL),
      instrument_unsafe_references_(true),
      src_ranges_for_thunks_(false),
      only_instrument_module_entry_(false),
      instrument_dll_name_(kDefaultInstrumentDll) {
}

bool EntryThunkTransform::SetEntryThunkParameter(const Immediate& immediate) {
  if (immediate.size() != core::kSizeNone &&
      immediate.size() != core::kSize32Bit) {
    return false;
  }
  entry_thunk_parameter_ = immediate;
  return true;
}

bool EntryThunkTransform::SetFunctionThunkParameter(
    const Immediate& immediate) {
  if (immediate.size() != core::kSizeNone &&
      immediate.size() != core::kSize32Bit) {
    return false;
  }
  function_thunk_parameter_ = immediate;
  return true;
}

bool EntryThunkTransform::EntryThunkIsParameterized() const {
  return entry_thunk_parameter_.size() != core::kSizeNone;
}

bool EntryThunkTransform::FunctionThunkIsParameterized() const {
  return function_thunk_parameter_.size() != core::kSizeNone;
}

bool EntryThunkTransform::PreBlockGraphIteration(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BlockGraph::Block* header_block) {
  DCHECK_NE(reinterpret_cast<TransformPolicyInterface*>(NULL), policy);
  DCHECK_NE(reinterpret_cast<BlockGraph*>(NULL), block_graph);
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), header_block);
  DCHECK_EQ(BlockGraph::PE_IMAGE, block_graph->image_format());
  DCHECK_EQ(reinterpret_cast<BlockGraph::Section*>(NULL), thunk_section_);

  if (!GetEntryPoints(header_block))
    return false;

  ImportedModule import_module(instrument_dll_name_);

  // We import the minimal set of symbols necessary, depending on the types of
  // entry points we find in the module. We maintain a list of symbol indices/
  // reference pointers, which will be traversed after the import to populate
  // the references.
  typedef std::pair<size_t, BlockGraph::Reference*> ImportHook;
  std::vector<ImportHook> import_hooks;

  // If there are any DllMain-like entry points (TLS initializers or DllMain
  // itself) then we need the DllMain entry hook.
  if (dllmain_entrypoints_.size() > 0) {
    import_hooks.push_back(std::make_pair(
        import_module.AddSymbol(kDllMainEntryHookName,
                                ImportedModule::kAlwaysImport),
        &hook_dllmain_ref_));
  }

  // If this was an EXE then we need the EXE entry hook.
  if (exe_entry_point_.first != NULL) {
    import_hooks.push_back(std::make_pair(
        import_module.AddSymbol(kExeMainEntryHookName,
                                ImportedModule::kAlwaysImport),
        &hook_exe_entry_ref_));
  }

  // If we're not only instrumenting module entry then we need the function
  // entry hook.
  if (!only_instrument_module_entry_) {
    import_hooks.push_back(std::make_pair(
        import_module.AddSymbol(kEntryHookName,
                                ImportedModule::kAlwaysImport),
        &hook_ref_));
  }

  // Nothing to do if we don't need any import hooks.
  if (import_hooks.empty())
    return true;

  // Run the transform.
  PEAddImportsTransform add_imports_transform;
  add_imports_transform.AddModule(&import_module);
  if (!add_imports_transform.TransformBlockGraph(
          policy, block_graph, header_block)) {
    LOG(ERROR) << "Unable to add imports for instrumentation DLL.";
    return false;
  }

  // Get references to each of the imported symbols.
  for (size_t i = 0; i < import_hooks.size(); ++i) {
    if (!import_module.GetSymbolReference(import_hooks[i].first,
                                          import_hooks[i].second)) {
      LOG(ERROR) << "Unable to get reference to import.";
      return false;
    }
  }

  // Find or create the section we put our thunks in.
  thunk_section_ = block_graph->FindOrAddSection(common::kThunkSectionName,
                                                 pe::kCodeCharacteristics);
  DCHECK(thunk_section_ != NULL);

  return true;
}

bool EntryThunkTransform::OnBlock(const TransformPolicyInterface* policy,
                                  BlockGraph* block_graph,
                                  BlockGraph::Block* block) {
  DCHECK(block != NULL);

  if (block->type() != BlockGraph::CODE_BLOCK)
    return true;

  return InstrumentCodeBlock(block_graph, block);
}

bool EntryThunkTransform::InstrumentCodeBlock(
    BlockGraph* block_graph, BlockGraph::Block* block) {
  DCHECK(block_graph != NULL);
  DCHECK(block != NULL);

  // Typedef for the thunk block map. The key is the offset within the callee
  // block and the value is the thunk block that forwards to the callee at that
  // offset.
  ThunkBlockMap thunk_block_map;

  // Iterate through all the block's referrers, creating thunks as we go.
  // We copy the referrer set for simplicity, as it's potentially mutated
  // in the loop.
  BlockGraph::Block::ReferrerSet referrers = block->referrers();
  BlockGraph::Block::ReferrerSet::const_iterator referrer_it(referrers.begin());
  for (; referrer_it != referrers.end(); ++referrer_it) {
    const BlockGraph::Block::Referrer& referrer = *referrer_it;
    if (!InstrumentCodeBlockReferrer(
        referrer, block_graph, block, &thunk_block_map)) {
      return false;
    }
  }

  return true;
}

bool EntryThunkTransform::InstrumentCodeBlockReferrer(
    const BlockGraph::Block::Referrer& referrer,
    BlockGraph* block_graph,
    BlockGraph::Block* block,
    ThunkBlockMap* thunk_block_map) {
  DCHECK(block_graph != NULL);
  DCHECK(block != NULL);
  DCHECK(thunk_block_map != NULL);

  // Get the reference.
  BlockGraph::Reference ref;
  if (!referrer.first->GetReference(referrer.second, &ref)) {
    LOG(ERROR) << "Unable to get reference from referrer.";
    return false;
  }

  // Skip self-references, except long references to the start of the block.
  // TODO(siggi): This needs refining, as it may currently miss important
  //     cases. Notably if a block contains more than one function, and the
  //     functions are mutually recursive, we'll only record the original
  //     entry to the block, but will miss the internal recursion.
  //     As-is, this does work for the common case where a block contains
  //     one self-recursive function, however.
  if (referrer.first == block) {
    // Skip short references.
    if (ref.size() < sizeof(core::AbsoluteAddress))
      return true;

    // Skip interior references. The rationale for this is because these
    // references will tend to be switch tables, and we don't need the
    // overhead of instrumenting and recording all switch statement executions
    // for now.
    if (ref.offset() != 0)
      return true;
  }

  // See whether this is one of the DLL entrypoints.
  pe::EntryPoint entry(ref.referenced(), ref.offset());
  pe::EntryPointSet::const_iterator entry_it(dllmain_entrypoints_.find(
      entry));
  bool is_dllmain_entry = entry_it != dllmain_entrypoints_.end();

  // Determine if this is an EXE entry point.
  bool is_exe_entry = entry == exe_entry_point_;

  // It can't be both an EXE and a DLL entry.
  DCHECK(!is_dllmain_entry || !is_exe_entry);

  // If we're only instrumenting entry points and this isn't one, then skip it.
  if (only_instrument_module_entry_ && !is_dllmain_entry && !is_exe_entry)
    return true;

  if (!instrument_unsafe_references_ &&
      block_graph::IsUnsafeReference(referrer.first, ref)) {
    LOG(INFO) << "Skipping reference between unsafe block pair '"
              << referrer.first->name() << "' and '"
              << block->name() << "'";
    return true;
  }

  // Determine which hook function to use.
  BlockGraph::Reference* hook_ref = &hook_ref_;
  if (is_dllmain_entry)
    hook_ref = &hook_dllmain_ref_;
  else if (is_exe_entry)
    hook_ref = &hook_exe_entry_ref_;
  DCHECK(hook_ref->referenced() != NULL);

  // Determine which parameter to use, if any.
  const Immediate* param = NULL;
  if ((is_dllmain_entry || is_exe_entry) && EntryThunkIsParameterized()) {
    param = &entry_thunk_parameter_;
  } else if (FunctionThunkIsParameterized()) {
    param = &function_thunk_parameter_;
  }

  // Look for the reference in the thunk block map, and only create a new one
  // if it does not already exist.
  BlockGraph::Block* thunk_block = NULL;
  ThunkBlockMap::const_iterator thunk_it = thunk_block_map->find(ref.offset());
  if (thunk_it == thunk_block_map->end()) {
    thunk_block = CreateOneThunk(block_graph, ref, *hook_ref, param);
    if (thunk_block == NULL) {
      LOG(ERROR) << "Unable to create thunk block.";
      return false;
    }
    (*thunk_block_map)[ref.offset()] = thunk_block;
  } else {
    thunk_block = thunk_it->second;
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

BlockGraph::Block* EntryThunkTransform::CreateOneThunk(
    BlockGraph* block_graph,
    const BlockGraph::Reference& destination,
    const BlockGraph::Reference& hook,
    const Immediate* parameter) {
  std::string name;
  if (destination.offset() == 0) {
    name = base::StringPrintf("%s%s",
                              destination.referenced()->name().c_str(),
                              common::kThunkSuffix);
  } else {
    name = base::StringPrintf("%s%s+%d",
                              destination.referenced()->name().c_str(),
                              common::kThunkSuffix,
                              destination.offset());
  }

  // Set up a basic block subgraph containing a single block description, with
  // that block description containing a single empty basic block, and get an
  // assembler writing into that basic block.
  // TODO(chrisha): Make this reusable somehow. Creating a code block via an
  //     assembler is likely to be pretty common.
  BasicBlockSubGraph bbsg;
  BasicBlockSubGraph::BlockDescription* block_desc = bbsg.AddBlockDescription(
      name,
      NULL,
      BlockGraph::CODE_BLOCK,
      thunk_section_->id(),
      1,
      0);
  BasicCodeBlock* bb = bbsg.AddBasicCodeBlock(name);
  block_desc->basic_block_order.push_back(bb);
  BasicBlockAssembler assm(bb->instructions().begin(),
                           &bb->instructions());

  // Set up our thunk:
  // 1. push parameter
  // 2. push func_addr
  // 3. jmp hook_addr
  if (parameter != NULL)
    assm.push(*parameter);
  assm.push(Immediate(destination.referenced(), destination.offset()));
  assm.jmp(Operand(Displacement(hook.referenced(), hook.offset())));

  // Condense the whole mess into a block.
  BlockBuilder block_builder(block_graph);
  if (!block_builder.Merge(&bbsg)) {
    LOG(ERROR) << "Failed to build thunk block.";
    return NULL;
  }

  // Exactly one new block should have been created.
  DCHECK_EQ(1u, block_builder.new_blocks().size());
  BlockGraph::Block* thunk = block_builder.new_blocks().front();

  if (src_ranges_for_thunks_) {
    // Give the thunk a source range synonymous with the destination.
    // That way the debugger will resolve calls and jumps to the thunk to the
    // destination function's name, which makes the assembly much easier to
    // read. The downside to this is that the symbols are now no longer unique,
    // and searching for a function by name may turn up either the function or
    // the thunk.
    const BlockGraph::Block::SourceRanges& source_ranges =
        destination.referenced()->source_ranges();
    const BlockGraph::Block::SourceRanges::RangePair* source =
        source_ranges.FindRangePair(destination.offset(), thunk->size());
    if (source != NULL) {
      // Calculate the offset into the range.
      size_t offs = destination.offset() - source->first.start();
      BlockGraph::Block::DataRange data(0, thunk->size());
      BlockGraph::Block::SourceRange src(source->second.start() + offs,
                                          thunk->size());
      bool pushed = thunk->source_ranges().Push(data, src);
      DCHECK(pushed);
    }
  }

  return thunk;
}

bool EntryThunkTransform::GetEntryPoints(BlockGraph::Block* header_block) {
  // Get the TLS initializer entry-points. These have the same signature and
  // call patterns to DllMain.
  if (!pe::GetTlsInitializers(header_block, &dllmain_entrypoints_)) {
    LOG(ERROR) << "Failed to populate the TLS Initializer entry-points.";
    return false;
  }

  // Get the DLL entry-point.
  pe::EntryPoint dll_entry_point;
  if (!pe::GetDllEntryPoint(header_block, &dll_entry_point)) {
    LOG(ERROR) << "Failed to resolve the DLL entry-point.";
    return false;
  }

  // If the image is an EXE or is a DLL that does not specify an entry-point
  // (the entry-point is optional for DLLs) then the dll_entry_point will have
  // a NULL block pointer. Otherwise, add it to the entry-point set.
  if (dll_entry_point.first != NULL) {
    dllmain_entrypoints_.insert(dll_entry_point);
  } else {
    // Get the EXE entry point. We only need to bother looking if we didn't get
    // a DLL entry point, as we can't have both.
    if (!pe::GetExeEntryPoint(header_block, &exe_entry_point_)) {
      LOG(ERROR) << "Failed to resolve the EXE entry-point.";
      return false;
    }
  }

  return true;
}

}  // namespace transforms
}  // namespace instrument
