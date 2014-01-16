// Copyright 2013 Google Inc. All Rights Reserved.
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

#include "syzygy/instrument/transforms/entry_call_transform.h"

#include "base/logging.h"
#include "base/stringprintf.h"
#include "syzygy/block_graph/basic_block_assembler.h"
#include "syzygy/block_graph/block_builder.h"
#include "syzygy/block_graph/block_util.h"
#include "syzygy/common/defs.h"
#include "syzygy/pe/pe_utils.h"
#include "syzygy/pe/transforms/pe_add_imports_transform.h"

namespace instrument {
namespace transforms {

const char EntryCallBasicBlockTransform::kTransformName[] =
    "EntryCallBasicBlockTransform";

const char EntryCallTransform::kTransformName[] =
    "EntryCallTransform";

const char EntryCallTransform::kEntryHookName[] = "_indirect_penter";
const char EntryCallTransform::kDllMainEntryHookName[] =
    "_indirect_penter_dllmain";
const char EntryCallTransform::kExeMainEntryHookName[] =
    "_indirect_penter_exemain";
const char EntryCallTransform::kDefaultInstrumentDll[] =
    "profile_client.dll";

EntryCallBasicBlockTransform::EntryCallBasicBlockTransform(
    const BlockGraph::Reference& hook_reference, bool debug_friendly)
        : hook_reference_(hook_reference), debug_friendly_(debug_friendly) {
}

bool EntryCallBasicBlockTransform::TransformBasicBlockSubGraph(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BasicBlockSubGraph* basic_block_subgraph) {
  DCHECK_NE(static_cast<TransformPolicyInterface*>(NULL), policy);
  DCHECK_NE(static_cast<BlockGraph*>(NULL), block_graph);
  DCHECK_NE(static_cast<BasicBlockSubGraph*>(NULL), basic_block_subgraph);

  using block_graph::BasicCodeBlock;
  typedef block_graph::BasicBlockSubGraph::BBCollection BBCollection;

  // We expect to be looking into a newly-decomposed basic block graph, with
  // precisely one block description for the originating block.
  DCHECK_EQ(1U, basic_block_subgraph->block_descriptions().size());
  BasicBlockSubGraph::BasicBlockOrdering& bb_order =
      basic_block_subgraph->block_descriptions().front().basic_block_order;

  // An empty BB ordering is nonsensical.
  DCHECK_NE(0U, bb_order.size());

  // Cast the first block to a code block - this should always succeed
  // for code coming from MSVC, but we do a runtime check for proper
  // belt-and-suspenders.
  BasicCodeBlock* bb = BasicCodeBlock::Cast(bb_order.front());
  if (bb == NULL) {
    LOG(ERROR) << "No code at the head of function \""
               << basic_block_subgraph->original_block()->name()
               << "\"";
    return false;
  }

  DCHECK_NE(static_cast<BasicCodeBlock*>(NULL), bb);
  DCHECK_EQ(0, bb->offset());

  // Create a new basic block for the entry hook.
  BasicCodeBlock* entry_hook =
      basic_block_subgraph->AddBasicCodeBlock("EntryHook");
  DCHECK_NE(static_cast<BasicCodeBlock*>(NULL), entry_hook);

  // Add a call instruction to the new block.
  using block_graph::BasicBlockAssembler;
  using block_graph::Operand;
  using block_graph::Displacement;
  block_graph::BasicBlockAssembler assm(entry_hook->instructions().begin(),
                                        &entry_hook->instructions());

  // In debug friendly mode we assign the previously first instruction's
  // address to the inserted call.
  if (debug_friendly_) {
    if (bb->instructions().size() != 0) {
      assm.set_source_range(bb->instructions().front().source_range());
    } else {
      LOG(WARNING) << "Function \""
                   << basic_block_subgraph->original_block()->name()
                   << "\" starts with an empty basic block. "
                   << "Not inserting a source range for it.";
    }
  }

  assm.call(Operand(Displacement(hook_reference_.referenced(),
                                 hook_reference_.offset())));

  // Put the new BB at the top of the function.
  bb_order.push_front(entry_hook);

  // Nominate the original entry point BB as successor for the new block.
  using block_graph::Successor;
  using block_graph::BasicBlockReference;
  entry_hook->successors().push_back(
      Successor(Successor::kConditionTrue,
                BasicBlockReference(BlockGraph::PC_RELATIVE_REF, 4, bb),
                0));

  // Transfer the external referrers from the old head of function to the
  // entry hook.
  bb->referrers().swap(entry_hook->referrers());

  // Now run through the code BBs in the function, and re-route any refs to the
  // former head of function to the entry hook. The point of this is to route
  // explicit self-recursion or self-references through the entry hook, while
  // leaving loops alone.
  // Loops will be implemented as either explicit control flow in successors,
  // or else may involve computed jumps through data "BBs", and by diverting
  // only instructions, we're sure to not divert loops through the entry hook.
  //
  // Note that this is not comprehensive, as it's in general impossible to
  // distinguish tail recursion elimination from a loop at the semantic
  // level of instructions.
  //
  // We choose to err on the side of performance and robustness, as
  // mis-instrumenting a loop will result in pushing the profiler's shadow
  // stack for every loop iteration, and then popping it as many times on exit.
  // This will lead to poor performance at best, but may also cause the
  // shadow stack to blow up in the extreme.
  BasicBlockSubGraph::BasicBlockOrdering::iterator bb_iter = bb_order.begin();

  // Walk past the entry hook BB.
  DCHECK_EQ(entry_hook, *bb_iter);
  ++bb_iter;

  // Walk through all the BBs (in order).
  for (; bb_iter != bb_order.end(); ++bb_iter) {
    BasicCodeBlock* curr_block = BasicCodeBlock::Cast(*bb_iter);
    if (curr_block != NULL) {
      BasicCodeBlock::Instructions& instr = curr_block->instructions();
      BasicCodeBlock::Instructions::iterator inst_it(instr.begin());

      // Walk through instructions for each code block.
      for (; inst_it != instr.end(); ++inst_it) {
        block_graph::Instruction::BasicBlockReferenceMap&
            refs(inst_it->references());
        block_graph::Instruction::BasicBlockReferenceMap::iterator
            ref_it(refs.begin());

        // For each instruction, walk through refrences.
        for (; ref_it != refs.end(); ++ref_it) {
          BasicBlockReference& ref(ref_it->second);
          if (ref.basic_block() == bb) {
            // And if the reference pointed to bb, redirect it to entry_hook.
            ref = BasicBlockReference(ref.reference_type(),
                                      ref.size(),
                                      entry_hook);
          }
        }
      }
    }
  }

  return true;
}

EntryCallTransform::EntryCallTransform(bool debug_friendly)
    : instrument_dll_name_(kDefaultInstrumentDll),
      debug_friendly_(debug_friendly) {
}

bool EntryCallTransform::PreBlockGraphIteration(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BlockGraph::Block* header_block) {
  DCHECK_NE(reinterpret_cast<TransformPolicyInterface*>(NULL), policy);
  DCHECK_NE(reinterpret_cast<BlockGraph*>(NULL), block_graph);
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), header_block);
  DCHECK_EQ(BlockGraph::PE_IMAGE, block_graph->image_format());

  if (!GetEntryPoints(header_block))
    return false;

  using pe::transforms::ImportedModule;
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

  import_hooks.push_back(std::make_pair(
      import_module.AddSymbol(kEntryHookName,
                              ImportedModule::kAlwaysImport),
      &hook_ref_));

  // Nothing to do if we don't need any import hooks.
  if (import_hooks.empty())
    return true;

  // Run the transform.
  pe::transforms::PEAddImportsTransform add_imports_transform;
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

  return true;
}

bool EntryCallTransform::OnBlock(const TransformPolicyInterface* policy,
                                 BlockGraph* block_graph,
                                 BlockGraph::Block* block) {
  DCHECK_NE(static_cast<TransformPolicyInterface*>(NULL), policy);
  DCHECK_NE(static_cast<BlockGraph*>(NULL), block_graph);
  DCHECK_NE(static_cast<BlockGraph::Block*>(NULL), block);

  // Skip blocks that aren't eligible for basic-block decomposition.
  if (!policy->BlockIsSafeToBasicBlockDecompose(block))
    return true;

  // Apply the basic block transform.
  // See whether this is one of the DLL entrypoints.
  pe::EntryPoint entry(block, 0);
  pe::EntryPointSet::const_iterator entry_it(dllmain_entrypoints_.find(
      entry));
  bool is_dllmain_entry = entry_it != dllmain_entrypoints_.end();

  // Determine if this is an EXE entry point.
  bool is_exe_entry = entry == exe_entry_point_;

  // It can't be both an EXE and a DLL entry.
  DCHECK(!is_dllmain_entry || !is_exe_entry);

  // Determine which hook function to use.
  BlockGraph::Reference* hook_ref = &hook_ref_;
  if (is_dllmain_entry)
    hook_ref = &hook_dllmain_ref_;
  else if (is_exe_entry)
    hook_ref = &hook_exe_entry_ref_;

  EntryCallBasicBlockTransform entry_call_transform(*hook_ref, debug_friendly_);
  if (!ApplyBasicBlockSubGraphTransform(
           &entry_call_transform, policy, block_graph, block, NULL)) {
    return false;
  }

  return true;
}

bool EntryCallTransform::GetEntryPoints(BlockGraph::Block* header_block) {
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

bool EntryCallTransform::PostBlockGraphIteration(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BlockGraph::Block* header_block) {
  // Make sure the thunks section contains at least one block, as its existence
  // is what Chrome's glue code looks for to see whether it's instrumented.
  BlockGraph::Section* thunk_section =
      block_graph->FindSection(common::kThunkSectionName);
  if (thunk_section != NULL) {
    // It already exists - we're done!
    return true;
  }

  // The section didn't already exist, create it.
  thunk_section = block_graph->FindOrAddSection(common::kThunkSectionName,
                                                pe::kCodeCharacteristics);
  DCHECK(thunk_section != NULL);

  // Create a one-byte marker block and assign it to the thunks segment.
  BlockGraph::Block* marker =
      block_graph->AddBlock(BlockGraph::CODE_BLOCK, 1, "InstrumentationMarker");
  DCHECK(marker != NULL);

  marker->set_section(thunk_section->id());

  // Provide the marker function with valid code.
  static const uint8 kRet[] = { 0xC3 };
  marker->SetData(kRet, sizeof(kRet));

  return true;
}

}  // namespace transforms
}  // namespace instrument
