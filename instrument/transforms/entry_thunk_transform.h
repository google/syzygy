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
// Implementation of the entry thunk instrumentation transform.

#ifndef SYZYGY_INSTRUMENT_TRANSFORMS_ENTRY_THUNK_TRANSFORM_H_
#define SYZYGY_INSTRUMENT_TRANSFORMS_ENTRY_THUNK_TRANSFORM_H_

#include <set>
#include <string>

#include "base/string_piece.h"
#include "syzygy/block_graph/iterate.h"
#include "syzygy/block_graph/transforms/iterative_transform.h"

namespace instrument {
namespace transforms {

class EntryThunkTransform
    : public block_graph::transforms::IterativeTransformImpl<
        EntryThunkTransform> {
 public:
  EntryThunkTransform();

  // @name Accessors.
  // @{
  void set_instrument_interior_references(bool instrument) {
    instrument_interior_references_ = instrument;
  }
  bool instrument_interior_references() const {
    return instrument_interior_references_;
  }

  bool set_instrument_dll_name(const base::StringPiece& instrument_dll_name) {
    instrument_dll_name.CopyToString(&instrument_dll_name_);
  }
  const char* instrument_dll_name() const {
    return instrument_dll_name_.c_str();
  }
  // @}

  // The name of the import for general entry hooks.
  static const char kEntryHookName[];
  // The name of the import for DllMain-like function entry hooks.
  static const char kDllMainEntryHookName[];

  // The name of the DLL imported default.
  static const char kDefaultInstrumentDll[];

 protected:
  typedef block_graph::BlockGraph BlockGraph;
  struct Thunk;

  // @name IterativeTransformImpl implementation.
  // @{
  bool PreIteration(BlockGraph* block_graph, BlockGraph::Block* header_block);
  bool OnBlock(BlockGraph* block_graph, BlockGraph::Block* block);
  // @}

  // Accessor.
  BlockGraph::Section* thunk_section() const { return thunk_section_; }

  // Instrument a single block.
  bool InstrumentCodeBlock(BlockGraph* block_graph, BlockGraph::Block* block);

  // Create a single thunk to destination.
  // @param destination the destination reference.
  // @param is_dll_entry_signature true iff this should be a DLL entry thunk.
  BlockGraph::Block* CreateOneThunk(BlockGraph* block_graph,
                                    const BlockGraph::Reference& destination,
                                    bool is_dll_entry_signature);

  // Locates the image entrypoints that should be thunked with the
  // dllmain hook import and stores them in dllmain_entrypoints_.
  bool PopulateDllMainEntryPoints(BlockGraph::Block* header_block);

  // Initializes the references in thunk_block, which must be an allocated
  // thunk of size sizeof(Thunk), containing data of the same size.
  static bool InitializeThunk(BlockGraph::Block* thunk_block,
                             const BlockGraph::Reference& destination,
                             const BlockGraph::Reference& import_entry);

 private:
  friend IterativeTransformImpl<EntryThunkTransform>;
  friend NamedTransformImpl<EntryThunkTransform>;

  // For NamedTransformImpl.
  static const char kTransformName[];

  // The section we put our thunks in. Valid after successful PreIteration.
  BlockGraph::Section* thunk_section_;

  // References to _indirect_penter and _indirect_penter_dllmain import
  // entries. Valid after successful PreIteration.
  BlockGraph::Reference hook_ref_;
  BlockGraph::Reference hook_dllmain_ref_;

  // Iff true, instrument references with a non-zero offset into the
  // destination block.
  bool instrument_interior_references_;

  // Name of the instrumentation DLL we import. Defaults to "call_trace.dll".
  std::string instrument_dll_name_;

  // This contains the set of entrypoints that have DllMain calling conventions.
  // These are thunked to the dllmain hook import, instead of the generic
  // hook import. Valid after successful PreIteration.
  typedef std::pair<BlockGraph::Block*, BlockGraph::Offset> EntryPointKey;
  typedef std::set<EntryPointKey> EntryPointSet;
  EntryPointSet dllmain_entrypoints_;

  static const Thunk kThunkTemplate;

  DISALLOW_COPY_AND_ASSIGN(EntryThunkTransform);
};

// This defines the memory layout for the thunks we create.
#pragma pack(push)
#pragma pack(1)
struct EntryThunkTransform::Thunk {
  BYTE push;
  DWORD func_addr;  // The real function to invoke.
  WORD jmp;
  DWORD hook_addr;  // The instrumentation hook that gets called beforehand.
};
#pragma pack(pop)

}  // namespace transforms
}  // namespace instrument

#endif  // SYZYGY_INSTRUMENT_TRANSFORMS_ENTRY_THUNK_TRANSFORM_H_
