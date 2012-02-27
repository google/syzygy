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

#include "syzygy/instrument/transforms/entry_thunk_transform.h"

#include "base/logging.h"
#include "base/stringprintf.h"
#include "syzygy/block_graph/typed_block.h"
#include "syzygy/pe/pe_utils.h"
#include "syzygy/pe/transforms/add_imports_transform.h"

namespace {

using block_graph::BlockGraph;
using block_graph::TypedBlock;

// We add this suffix to the destination
const char kThunkSuffix[] = "_thunk";

}  // namespace

namespace instrument {
namespace transforms {

using pe::transforms::AddImportsTransform;

const char EntryThunkTransform::kTransformName[] =
    "EntryThunkTransform";

const char EntryThunkTransform::kEntryHookName[] = "_indirect_penter";
const char EntryThunkTransform::kDllMainEntryHookName[] =
    "_indirect_penter_dllmain";
const char EntryThunkTransform::kDefaultInstrumentDll[] = "call_trace.dll";

// We push the absolute address of the function to be called on the
// stack, and then we invoke the instrumentation function indirectly
// through the import table.
// 6844332211    push  offset (11223344)
// FF2588776655  jmp   dword ptr [(55667788)]
const EntryThunkTransform::Thunk EntryThunkTransform::kThunkTemplate = {
    0x68, NULL, // push immediate
    0x25FF, NULL  // jmp DWORD PTR[immediate]
  };

EntryThunkTransform::EntryThunkTransform()
    : thunk_section_(NULL),
      instrument_interior_references_(true),
      instrument_dll_name_(kDefaultInstrumentDll) {
}

bool EntryThunkTransform::PreIteration(BlockGraph* block_graph,
                                       BlockGraph::Block* header_block) {
  DCHECK(thunk_section_ == NULL);

  AddImportsTransform::ImportedModule import_module(
      instrument_dll_name_.c_str());
  size_t hook_index = import_module.AddSymbol(kEntryHookName);
  size_t hook_dllmain_index = import_module.AddSymbol(kDllMainEntryHookName);

  AddImportsTransform add_imports_transform;
  add_imports_transform.AddModule(&import_module);

  if (!add_imports_transform.Apply(block_graph, header_block)) {
    LOG(ERROR) << "Unable to add imports for instrumentation DLL.";
    return false;
  }

  if (!import_module.GetSymbolReference(hook_index, &hook_ref_) ||
      !import_module.GetSymbolReference(hook_dllmain_index,
                                        &hook_dllmain_ref_)) {
    LOG(ERROR) << "Unable to get import references.";
    return false;
  }

  if (!PopulateDllMainEntryPoints(header_block)) {
    LOG(ERROR) << "Failed to populate DLL entrypoints.";
    return false;
  }

  // Find or create the section we put our thunks in.
  thunk_section_ = block_graph->FindOrAddSection(".thunks",
                                                 pe::kCodeCharacteristics);
  DCHECK(thunk_section_ != NULL);

  return true;
}

bool EntryThunkTransform::OnBlock(BlockGraph* block_graph,
                                  BlockGraph::Block* block) {
  DCHECK(block != NULL);

  if (block->type() != BlockGraph::CODE_BLOCK)
    return true;

  return InstrumentCodeBlock(block_graph, block);
}

bool EntryThunkTransform::InstrumentCodeBlock(
    BlockGraph* block_graph, BlockGraph::Block* block) {
  // Typedef for the thunk block map. The key is the offset within the callee
  // block and the value is the thunk block that forwards to the callee at that
  // offset.
  typedef std::map<BlockGraph::Offset, BlockGraph::Block*> ThunkBlockMap;
  ThunkBlockMap thunk_block_map;

  // Iterate through all the block's referrers, creating thunks as we go.
  // We copy the referrer set for simplicity, as it's potentially mutated
  // in the loop.
  BlockGraph::Block::ReferrerSet referrers = block->referrers();
  BlockGraph::Block::ReferrerSet::const_iterator referrer_it(referrers.begin());
  for (; referrer_it != referrers.end(); ++referrer_it) {
    const BlockGraph::Block::Referrer& referrer = *referrer_it;

    // Skip self-references.
    // TODO(siggi): Is this valid?
    if (referrer.first == block)
      continue;

    // Get the reference.
    BlockGraph::Reference ref;
    if (!referrer.first->GetReference(referrer.second, &ref)) {
      LOG(ERROR) << "Unable to get reference from referrer.";
      return false;
    }

    // Skip references with a non-zero offset if we're
    // not instrumenting interior references.
    if (!instrument_interior_references_ && ref.offset() != 0)
      continue;

    // Look for the reference in the thunk block map, and only create a new one
    // if it does not already exist.
    BlockGraph::Block* thunk_block = NULL;
    ThunkBlockMap::const_iterator thunk_it = thunk_block_map.find(ref.offset());
    if (thunk_it == thunk_block_map.end()) {
      // See whether this is one of the special entrypoints.
      EntryPointSet::const_iterator entry_it(dllmain_entrypoints_.find(
          std::make_pair(ref.referenced(), ref.offset())));
      bool is_dllmain_entry = entry_it != dllmain_entrypoints_.end();

      thunk_block = CreateOneThunk(block_graph, ref, is_dllmain_entry);
      if (thunk_block == NULL) {
        LOG(ERROR) << "Unable to create thunk block.";
        return false;
      }
      thunk_block_map[ref.offset()] = thunk_block;
    } else {
      thunk_block = thunk_it->second;
    }
    DCHECK(thunk_block != NULL);

    // Update the referrer to point to the thunk.
    BlockGraph::Reference new_ref(ref.type(),
                                  ref.size(),
                                  thunk_block,
                                  0);
    referrer.first->SetReference(referrer.second, new_ref);
  }

  return true;
}

BlockGraph::Block* EntryThunkTransform::CreateOneThunk(
    BlockGraph* block_graph, const BlockGraph::Reference& destination,
    bool is_dll_entry_signature) {
  std::string name;
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

  // Give the thunk a source range synonymous with the destination.
  // That way the debugger will resolve calls and jumps to the thunk to the
  // destination function's name, which makes the assembly much easier to read.
  // The downside to this is that the symbols are now no longer unique, and
  // searching for a function by name may turn up either the function or the
  // thunk.
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

  const BlockGraph::Reference& import_ref =
      is_dll_entry_signature ? hook_dllmain_ref_ : hook_ref_;

  if (!InitializeThunk(thunk, destination, import_ref)) {
    bool removed = block_graph->RemoveBlock(thunk);
    DCHECK(removed);

    thunk = NULL;
  }

  return thunk;
}

bool EntryThunkTransform::PopulateDllMainEntryPoints(
    BlockGraph::Block* header_block) {
  BlockGraph::Block* nt_headers_block =
      pe::GetNtHeadersBlockFromDosHeaderBlock(header_block);

  TypedBlock<IMAGE_NT_HEADERS> nt_headers;
  if (nt_headers_block == NULL || !nt_headers.Init(0, nt_headers_block)) {
    LOG(ERROR) << "Unable to retrieve NT Headers.";
    return false;
  }

  // Note the entrypoint for DLLs.
  if (nt_headers->FileHeader.Characteristics & IMAGE_FILE_DLL) {
    BlockGraph::Reference ref;
    if (nt_headers.block()->GetReference(
            offsetof(IMAGE_NT_HEADERS, OptionalHeader.AddressOfEntryPoint),
            &ref)) {
      // Note this entrypoint.
      dllmain_entrypoints_.insert(
          std::make_pair(ref.referenced(), ref.offset()));
    }
  }

  // If the module has no TLS directory then there are no TLS initializers
  // and hence nothing to do.
  const IMAGE_DATA_DIRECTORY& data_dir =
      nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
  if (data_dir.Size == 0 || !nt_headers.HasReference(data_dir.VirtualAddress)) {
    return true;
  }

  // Find the TLS directory.
  TypedBlock<IMAGE_TLS_DIRECTORY> tls_dir;
  if (!nt_headers.Dereference(data_dir.VirtualAddress, &tls_dir)) {
    LOG(ERROR) << "Failed to cast TLS directory.";
    return false;
  }

  // Get the TLS initializer callbacks.
  TypedBlock<DWORD> callbacks;
  if (!tls_dir.Dereference(tls_dir->AddressOfCallBacks, &callbacks)) {
    LOG(ERROR) << "Failed to locate TLS initializers.";
    return false;
  }

  // Note each of the thunks.
  typedef BlockGraph::Block::ReferenceMap ReferenceMap;
  const ReferenceMap& ref_map = callbacks.block()->references();
  ReferenceMap::const_iterator iter = ref_map.begin();
  for (; iter != ref_map.end(); ++iter) {
    const BlockGraph::Reference& ref = iter->second;
    DCHECK(ref.size() == sizeof(core::AbsoluteAddress));

    // Note this TLS entrypoint.
    dllmain_entrypoints_.insert(
        std::make_pair(ref.referenced(), ref.offset()));
  }

  return true;
}

bool EntryThunkTransform::InitializeThunk(
    BlockGraph::Block* thunk_block,
    const BlockGraph::Reference& destination,
    const BlockGraph::Reference& import_entry) {
  TypedBlock<Thunk> thunk;
  if (!thunk.Init(0, thunk_block))
    return false;

  if (!thunk.SetReference(BlockGraph::ABSOLUTE_REF,
                          thunk->func_addr,
                          destination.referenced(),
                          destination.offset())) {
    return false;
  }

  if (!thunk.SetReference(BlockGraph::ABSOLUTE_REF,
                          thunk->hook_addr,
                          import_entry.referenced(),
                          import_entry.offset())) {
    return false;
  }

  return true;
}

}  // namespace transforms
}  // namespace instrument
