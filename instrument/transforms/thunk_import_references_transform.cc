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

#include "syzygy/instrument/transforms/thunk_import_references_transform.h"

#include "base/logging.h"
#include "base/stringprintf.h"
#include "syzygy/block_graph/typed_block.h"
#include "syzygy/pe/pe_utils.h"
#include "syzygy/pe/transforms/add_imports_transform.h"

namespace instrument {
namespace transforms {

namespace {

using block_graph::BlockGraph;
using block_graph::TypedBlock;

// We add this suffix to the destination
const char kThunkSuffix[] = "_thunk";

}  // namespace

using pe::transforms::AddImportsTransform;

const char ThunkImportReferencesTransform::kTransformName[] =
    "ThunkImportReferencesTransform";

const char ThunkImportReferencesTransform::kEntryHookName[] =
    "_indirect_penter";
const char ThunkImportReferencesTransform::kDefaultInstrumentDll[] =
    "call_trace.dll";

// We look up the absolute address of the function to be called on the
// stack, and then we invoke the instrumentation function indirectly
// through the import table.
// Ff6844332211  push  dword ptr [(11223344)]
// FF2588776655  jmp   dword ptr [(55667788)]
const ThunkImportReferencesTransform::Thunk
ThunkImportReferencesTransform::kThunkTemplate = {
    0x35FF, NULL, // push DWORD PTR[immediate]
    0x25FF, NULL  // jmp DWORD PTR[immediate]
  };

ThunkImportReferencesTransform::ThunkImportReferencesTransform()
    : thunk_section_(NULL),
      instrument_dll_name_(kDefaultInstrumentDll) {
}

bool ThunkImportReferencesTransform::TransformBlockGraph(
    BlockGraph* block_graph,
    BlockGraph::Block* header_block) {
  DCHECK(thunk_section_ == NULL);

  AddImportsTransform::ImportedModule import_module(
      instrument_dll_name_.c_str());
  size_t hook_index = import_module.AddSymbol(kEntryHookName);

  add_imports_transform_.AddModule(&import_module);

  if (!add_imports_transform_.TransformBlockGraph(block_graph, header_block)) {
    LOG(ERROR) << "Unable to add imports for instrumentation DLL.";
    return false;
  }

  if (!import_module.GetSymbolReference(hook_index, &hook_ref_)) {
    LOG(ERROR) << "Unable to get import reference for hook.";
    return false;
  }

  // Now grab the block containing the IAT so that we can instrument references
  // to it. We also get the image import descriptor table block so that we
  // can exclude that - we don't want to instrument that.
  BlockGraph::Block* iat_block =
      add_imports_transform_.import_address_table_block();
  DCHECK(iat_block != NULL);
  BlockGraph::Block* iidt_block =
      add_imports_transform_.image_import_descriptor_block();
  DCHECK(iat_block != NULL);

  if (!InstrumentIATReferences(block_graph, iat_block, iidt_block)) {
    LOG(ERROR) << "Unable to instrument references to the IAT.";
    return false;
  }

  return true;
}

void ThunkImportReferencesTransform::ExcludeModule(
  const base::StringPiece& module_name) {
  modules_to_exclude_.insert(module_name.as_string());
}

// This method builds up a set of thunk blocks as well as a thunk table
// containing pointers to these blocks. Existing import references are then
// replaced by references to the thunk table. Since imports are invoked via
// an indirect call or jump instruction, changing the address of the call
// statement from an address into the IAT to an address into the thunk table
// gets the thunk called properly.
bool ThunkImportReferencesTransform::InstrumentIATReferences(
    BlockGraph* block_graph,
    BlockGraph::Block* iat_block,
    BlockGraph::Block* iidt_block) {

  // Find or create the section we put our thunks in.
  thunk_section_ = block_graph->FindOrAddSection(".thunks",
                                                 pe::kCodeCharacteristics);
  if (thunk_section_ == NULL) {
    NOTREACHED();
    return false;
  }

  // Typedef for the thunk block map. The key is the offset into the IAT block
  // (since all callers can use the same thunk) and the value is the offset into
  // the thunk table that points to the thunk block for that IAT entry.
  typedef std::map<BlockGraph::Offset, BlockGraph::Offset> ThunkBlockMap;
  ThunkBlockMap thunk_block_map;

  // Create the thunk table. Make it the same size as the IAT, assuming that
  // we will need a thunk for each import.
  // TODO(robertshield): Resize the block afterwards if not all imports are
  //                     thunked.
  BlockGraph::Block* thunk_table_block =
      block_graph->AddBlock(BlockGraph::DATA_BLOCK,
                            iat_block->size(),
                            "ImportsThunkTable");
  thunk_table_block->AllocateData(iat_block->size());
  thunk_table_block->set_section(thunk_section_->id());
  BlockGraph::Offset thunk_table_offset = 0;

  // Next, list all Referrers to get all References into the IAT. For each
  // Reference, create a thunk (in its own block) and add a pointer to it to
  // the thunk table.
  BlockGraph::Block::ReferrerSet iat_referrers(iat_block->referrers());
  BlockGraph::Block::ReferrerSet::const_iterator iat_referrer_iter(
      iat_referrers.begin());
  for (; iat_referrer_iter != iat_referrers.end(); ++iat_referrer_iter) {
    const BlockGraph::Block::Referrer& referrer = *iat_referrer_iter;

    if (referrer.first == iat_block) {
      LOG(WARNING) << "Unexpected self-reference in IAT.";
      continue;
    }

    if (referrer.first->type() != BlockGraph::CODE_BLOCK) {
      LOG(INFO) << "Skipping non-code block reference.";
      continue;
    }

    // Now that we know the referring block, we need to find out where in the
    // IAT it refers to.
    BlockGraph::Reference ref;
    if (!referrer.first->GetReference(referrer.second, &ref)) {
      LOG(ERROR) << "Unable to get reference from referrer.";
      return false;
    }

    // Now we need to figure out if the IAT entry being referred to points
    // to one of the excluded modules.
    // To do that, figure out the ranges for each of our excluded modules.
    // TODO(robertshield): ^ this.

    // Look for the reference in the thunk block map, and only create a new one
    // if it does not already exist.
    BlockGraph::Block* thunk_block = NULL;
    BlockGraph::Offset new_ref_offset = 0;

    ThunkBlockMap::const_iterator thunk_it = thunk_block_map.find(ref.offset());
    if (thunk_it == thunk_block_map.end()) {
      // Create the thunk block for this offset into the IAT.
      thunk_block = CreateOneThunk(block_graph, ref);
      if (thunk_block == NULL) {
        LOG(DFATAL) << "Unable to create thunk block.";
        return false;
      }

      // Now add a reference to the thunk in the thunk table.
      BlockGraph::Reference thunk_ref(BlockGraph::ABSOLUTE_REF,
                                      sizeof(core::AbsoluteAddress),
                                      thunk_block, 0, 0);
      thunk_table_block->SetReference(thunk_table_offset, thunk_ref);

      // Remember this thunk in case we need to use it again.
      thunk_block_map[ref.offset()] = thunk_table_offset;

      new_ref_offset = thunk_table_offset;

      // Move to the next empty entry in the thunk table.
      thunk_table_offset += sizeof(core::AbsoluteAddress);
      DCHECK_LT(static_cast<BlockGraph::Size>(thunk_table_offset),
                thunk_table_block->size());
    } else {
      new_ref_offset = thunk_it->second;
    }

    // Update the referrer to point to the new location in the thunk table.
    BlockGraph::Reference new_ref(ref.type(),
                                  ref.size(),
                                  thunk_table_block,
                                  new_ref_offset,
                                  0);
    referrer.first->SetReference(referrer.second, new_ref);
  }

  return true;
}

BlockGraph::Block* ThunkImportReferencesTransform::CreateOneThunk(
    BlockGraph* block_graph,
    const BlockGraph::Reference& destination) {
  std::string name;
  // TODO(robertshield): Name the thunks according to the import they are
  // thunking.
  if (destination.offset() == 0) {
    name = base::StringPrintf("%s%s",
                              destination.referenced()->name().c_str(),
                              kThunkSuffix);
  } else {
    name = base::StringPrintf("%s%s+%d",
                              destination.referenced()->name().c_str(),
                              kThunkSuffix,
                              destination.offset());
  }

  // Create and initialize the new thunk.
  BlockGraph::Block* thunk = block_graph->AddBlock(BlockGraph::CODE_BLOCK,
                                                   sizeof(kThunkTemplate),
                                                   name.c_str());
  if (thunk == NULL)
    return NULL;

  thunk->set_section(thunk_section_->id());
  thunk->SetData(reinterpret_cast<const uint8*>(&kThunkTemplate),
                 sizeof(kThunkTemplate));

  if (!InitializeThunk(thunk, destination, hook_ref_)) {
    bool removed = block_graph->RemoveBlock(thunk);
    DCHECK(removed);

    thunk = NULL;
  }

  return thunk;
}

bool ThunkImportReferencesTransform::InitializeThunk(
    BlockGraph::Block* thunk_block,
    const BlockGraph::Reference& destination,
    const BlockGraph::Reference& import_entry) {
  TypedBlock<Thunk> thunk;
  if (!thunk.Init(0, thunk_block))
    return false;

  if (!thunk.SetReference(BlockGraph::ABSOLUTE_REF,
                          thunk->func_addr,
                          destination.referenced(),
                          destination.offset(),
                          destination.offset())) {
    return false;
  }

  if (!thunk.SetReference(BlockGraph::ABSOLUTE_REF,
                          thunk->hook_addr,
                          import_entry.referenced(),
                          import_entry.offset(),
                          import_entry.offset())) {
    return false;
  }

  return true;
}

}  // namespace transforms
}  // namespace instrument
