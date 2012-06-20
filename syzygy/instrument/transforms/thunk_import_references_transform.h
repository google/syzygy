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
// Declaration of the thunk import references instrumentation transform.
//
// This transform is designed to traverse all blocks containing references to
// entries in the import tables and replace them with references to conjured-up
// thunks that delegate to the instrumentation machinery.
// It accepts a list of modules to exclude from this process to allow for
// e.g. not thunking the instrumentation.

#ifndef SYZYGY_INSTRUMENT_TRANSFORMS_THUNK_IMPORT_REFERENCES_TRANSFORM_H_
#define SYZYGY_INSTRUMENT_TRANSFORMS_THUNK_IMPORT_REFERENCES_TRANSFORM_H_

#include <set>
#include <string>

#include "base/string_piece.h"
#include "syzygy/block_graph/iterate.h"
#include "syzygy/block_graph/transforms/iterative_transform.h"
#include "syzygy/pe/transforms/add_imports_transform.h"

namespace instrument {
namespace transforms {

class ThunkImportReferencesTransform
    : public block_graph::transforms::NamedTransformImpl<
          ThunkImportReferencesTransform> {
 public:
  ThunkImportReferencesTransform();

  // Adds a module to the list of those from which imports are excluded from
  // being thunked. @p module_name is the name of the module including
  // the extension, e.g. kernel32.dll.
  void ExcludeModule(const base::StringPiece& module_name);

  // The name of the import for general entry hooks.
  static const char kEntryHookName[];

  // The name of the instrumentation DLL imported by default.
  static const char kDefaultInstrumentDll[];

 protected:
  typedef block_graph::BlockGraph BlockGraph;
  struct Thunk;

  // @name IterativeTransformImpl implementation.
  // @{
  virtual bool TransformBlockGraph(
      BlockGraph* block_graph, BlockGraph::Block* header_block) OVERRIDE;
  // @}

  // Accessor.
  BlockGraph::Section* thunk_section() const { return thunk_section_; }

  // Instrument all references to the IAT, excluding the block containing the
  // image import descriptor table passed in @p iidt_block.
  bool InstrumentIATReferences(BlockGraph* block_graph,
                               BlockGraph::Block* iat_block,
                               BlockGraph::Block* iidt_block);

  // Create a single thunk to destination.
  // @param destination the destination reference.
  // @param is_dll_entry_signature true iff this should be a DLL entry thunk.
  BlockGraph::Block* CreateOneThunk(BlockGraph* block_graph,
                                    const BlockGraph::Reference& destination);

  // Initializes the references in thunk_block, which must be an allocated
  // thunk of size sizeof(Thunk), containing data of the same size.
  static bool InitializeThunk(BlockGraph::Block* thunk_block,
                             const BlockGraph::Reference& destination,
                             const BlockGraph::Reference& import_entry);

  // Exposed for testing. Valid after Apply() is called.
  pe::transforms::AddImportsTransform& add_imports_transform() {
    return add_imports_transform_;
  }

 private:
  friend NamedTransformImpl<ThunkImportReferencesTransform>;

  // For NamedTransformImpl.
  static const char kTransformName[];

  // The section we put our thunks in.
  BlockGraph::Section* thunk_section_;

  // References to _indirect_penter and _indirect_penter_dllmain import
  // entries.
  BlockGraph::Reference hook_ref_;

  // The transform used to add imports for our instrumentation. It also
  // conveniently stores references to the blocks containing the IAT and IDT.
  pe::transforms::AddImportsTransform add_imports_transform_;

  // Name of the instrumentation DLL we import. Defaults to "call_trace.dll".
  std::string instrument_dll_name_;

  // Set of names of modules whose imports will not be thunked.
  std::set<std::string> modules_to_exclude_;

  static const Thunk kThunkTemplate;

  DISALLOW_COPY_AND_ASSIGN(ThunkImportReferencesTransform);
};

// This defines the memory layout for the thunks we create.
#pragma pack(push)
#pragma pack(1)
struct ThunkImportReferencesTransform::Thunk {
  WORD push;
  DWORD func_addr;  // The address to dereference to find the import address.
  WORD jmp;
  DWORD hook_addr;  // The instrumentation hook that gets called beforehand.
};
#pragma pack(pop)

}  // namespace transforms
}  // namespace instrument

#endif  // SYZYGY_INSTRUMENT_TRANSFORMS_THUNK_IMPORT_REFERENCES_TRANSFORM_H_
