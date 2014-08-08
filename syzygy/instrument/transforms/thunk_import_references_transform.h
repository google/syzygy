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

#include "base/strings/string_piece.h"
#include "syzygy/block_graph/iterate.h"
#include "syzygy/block_graph/transforms/iterative_transform.h"
#include "syzygy/pe/transforms/pe_add_imports_transform.h"

namespace instrument {
namespace transforms {

// A transform that replaces references to imports with a reference to
// an entry hook thunk.
class ThunkImportReferencesTransform
    : public block_graph::transforms::NamedBlockGraphTransformImpl<
          ThunkImportReferencesTransform> {
 public:
  typedef block_graph::TransformPolicyInterface TransformPolicyInterface;

  ThunkImportReferencesTransform();

  // Adds a module to the list of those from which imports are excluded from
  // being thunked.
  // @param module_name the base name, including extension, of the module
  //   to exclude e.g. "kernel32.dll". The module name is case insensitive.
  // @note that the instrumentation DLL is implicitly always excluded from
  //     instrumentation.
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
  typedef std::pair<BlockGraph::Block*, BlockGraph::Offset>
      ImportAddressLocation;
  typedef std::map<ImportAddressLocation, std::string>
      ImportAddressLocationNameMap;
  typedef std::set<BlockGraph::Block*> BlockSet;

  // Comparator for module names, this class wants to be fully declared before
  // use of the typedefs referencing it.
  class ModuleNameLess {
   public:
    bool operator()(const std::string& lhs, const std::string& rhs) const;
  };

  // @name IterativeTransformImpl implementation.
  // @{
  virtual bool TransformBlockGraph(
      const TransformPolicyInterface* policy,
      BlockGraph* block_graph,
      BlockGraph::Block* header_block) OVERRIDE;
  // @}

  // Accessor.
  BlockGraph::Section* thunk_section() const { return thunk_section_; }

  // Instrument all references to @p iat_block that have an entry
  // in @p import_locations, excluding references from @p iidt_block.
  // @param block_graph the block graph to operate on.
  // @param import_locations tags the entries to instrument.
  // @returns true on success, false on failure.
  bool InstrumentImportReferences(
      BlockGraph* block_graph,
      const ImportAddressLocationNameMap& import_locations);

  // Create a single thunk to destination.
  // @param destination the destination reference.
  // @param is_dll_entry_signature true iff this should be a DLL entry thunk.
  // @param name is the name of the import referenced.
  BlockGraph::Block* CreateOneThunk(BlockGraph* block_graph,
                                    const BlockGraph::Reference& destination,
                                    const base::StringPiece& name);

  // Exposed for testing. Valid after Apply() is called.
  pe::transforms::PEAddImportsTransform& add_imports_transform() {
    return add_imports_transform_;
  }

  // Retrieves the set of blocks referenced by import_locations.
  static bool GetImportBlocks(
      const ImportAddressLocationNameMap& import_locations,
      BlockSet* import_blocks);

  // Implementation function, exposed for testing.
  static bool LookupImportLocations(
      const ModuleNameSet& exclusions,
      BlockGraph::Block* header_block,
      ImportAddressLocationNameMap* import_locations);

  // Implementation function, exposed for testing.
  static bool LookupDelayImportLocations(
      const ModuleNameSet& exclusions,
      BlockGraph::Block* header_block,
      ImportAddressLocationNameMap* import_locations);

  // For NamedBlockGraphTransformImpl.
  static const char kTransformName[];

  // The section we put our thunks in.
  BlockGraph::Section* thunk_section_;

  // References to _indirect_penter and _indirect_penter_dllmain import
  // entries.
  BlockGraph::Reference hook_ref_;

  // The transform used to add imports for our instrumentation. It also
  // conveniently stores references to the blocks containing the IAT and IDT.
  pe::transforms::PEAddImportsTransform add_imports_transform_;

  // Name of the instrumentation DLL we import. Defaults to "call_trace.dll".
  std::string instrument_dll_name_;

  // Set of names of modules whose imports will not be thunked.
  ModuleNameSet modules_to_exclude_;

  DISALLOW_COPY_AND_ASSIGN(ThunkImportReferencesTransform);
};

}  // namespace transforms
}  // namespace instrument

#endif  // SYZYGY_INSTRUMENT_TRANSFORMS_THUNK_IMPORT_REFERENCES_TRANSFORM_H_
