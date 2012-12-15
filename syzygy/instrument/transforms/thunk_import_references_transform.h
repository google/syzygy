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

// A transform that replaces references to imports with a reference to
// an entry hook thunk.
class ThunkImportReferencesTransform
    : public block_graph::transforms::NamedBlockGraphTransformImpl<
          ThunkImportReferencesTransform> {
 public:
  ThunkImportReferencesTransform();

  // Adds a module to the list of those from which imports are excluded from
  // being thunked. @p module_name is the name of the module including
  // the extension, e.g. kernel32.dll.
  void ExcludeModule(const base::StringPiece& module_name);

  // Accessors.
  const char* instrument_dll_name() const {
    return instrument_dll_name_.c_str();
  }
  void set_instrument_dll_name(const base::StringPiece& name) {
    instrument_dll_name_.assign(name.begin(), name.end());
  }

  // The name of the import for general entry hooks.
  static const char kEntryHookName[];

  // The name of the instrumentation DLL imported by default.
  static const char kDefaultInstrumentDll[];

 protected:
  friend NamedBlockGraphTransformImpl<ThunkImportReferencesTransform>;
  typedef block_graph::BlockGraph BlockGraph;
  class ModuleNameLess;
  typedef std::set<std::string, ModuleNameLess> ModuleNameSet;

  // We keep a map from the blocks/offsets where there are imports we want to
  // thunk (e.g. imports to non-excluded modules) to their dll/function names,
  // during instrumentation.
  typedef std::pair<const BlockGraph::Block*, BlockGraph::Offset>
      ImportAddressLocation;
  typedef std::map<ImportAddressLocation, std::string>
      ImportAddressLocationNameMap;

  // Comparator for module names, this class wants to be fully declared before
  // use of the typedefs referencing it.
  class ModuleNameLess {
   public:
    bool operator()(const std::string& lhs, const std::string& rhs) const;
  };

  // @name IterativeTransformImpl implementation.
  // @{
  virtual bool TransformBlockGraph(
      BlockGraph* block_graph, BlockGraph::Block* header_block) OVERRIDE;
  // @}

  // Accessor.
  BlockGraph::Section* thunk_section() const { return thunk_section_; }

  // Instrument all references to @p iat_block that have an entry
  // in @p location_names, excluding references from @p iidt_block.
  // @param block_grap the block graph to operate on.
  // @param location_names tags the entries to instrument.
  // @param iat_block the import address table to process.
  // TODO(siggi): It should be possible to reuse this function for
  //     delay imports.
  // TODO(siggi): The iat_block parameter is redundant as the location_names
  //     map references one or more import address tables. With that change
  //     this function could instrument imports and delay imports in a
  //     single go.
  bool InstrumentIATReferences(
      BlockGraph* block_graph,
      const ImportAddressLocationNameMap& location_names,
      BlockGraph::Block* iat_block);

  // Create a single thunk to destination.
  // @param destination the destination reference.
  // @param is_dll_entry_signature true iff this should be a DLL entry thunk.
  // @param name is the name of the import referenced.
  BlockGraph::Block* CreateOneThunk(BlockGraph* block_graph,
                                    const BlockGraph::Reference& destination,
                                    const base::StringPiece& name);

  // Exposed for testing. Valid after Apply() is called.
  pe::transforms::AddImportsTransform& add_imports_transform() {
    return add_imports_transform_;
  }

  // Implementation function, exposed for testing.
  static bool LookupImportNames(const ModuleNameSet& exclusions,
                                BlockGraph::Block* header_block,
                                ImportAddressLocationNameMap* location_names);

  // For NamedBlockGraphTransformImpl.
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
  ModuleNameSet modules_to_exclude_;

  DISALLOW_COPY_AND_ASSIGN(ThunkImportReferencesTransform);
};

}  // namespace transforms
}  // namespace instrument

#endif  // SYZYGY_INSTRUMENT_TRANSFORMS_THUNK_IMPORT_REFERENCES_TRANSFORM_H_
