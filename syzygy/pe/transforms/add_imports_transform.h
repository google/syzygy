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
// Defines a PE-specific block-graph transform that finds or adds imports to a
// given module. Multiple libraries may be specified, and multiple functions per
// library. If an import is not found and the mode is kFindOnly, then the
// import will be added. This may also cause an entire imported module to
// be added.
//
// Use is as follows:
//
//   ImportedModule foo_dll("foo.dll");
//   size_t foo_foo_index = foo_dll.AddSymbol("foo");
//   size_t foo_bar_index = foo_dll.AddSymbol("bar");
//
//   AddImportsTransform add_imports_transform;
//   add_imports_transform.AddModule(&foo_dll);
//   add_imports_transform.TransformBlockGraph(block_graph, dos_header_block);
//
//   // Create a reference to function 'bar' in 'foo.dll'.
//   BlockGraph::Reference foo_bar_ref;
//   CHECK(foo_dll.GetSymbolReference(foo_bar_index, &foo_bar_ref));
//   some_block->SetReference(some_offset, foo_bar_ref);
//
// NOTE: The references provided by GetSymbolReference are only valid
//     immediately after they are constructed. If the import directory entries
//     are changed between creating the reference and adding it to a block,
//     than it may have been invalidated.

#ifndef SYZYGY_PE_TRANSFORMS_ADD_IMPORTS_TRANSFORM_H_
#define SYZYGY_PE_TRANSFORMS_ADD_IMPORTS_TRANSFORM_H_

#include <windows.h>

#include "syzygy/block_graph/typed_block.h"
#include "syzygy/block_graph/transforms/named_transform.h"

namespace pe {
namespace transforms {

using block_graph::transforms::NamedBlockGraphTransformImpl;

// A transform for adding imported modules/symbols to a given block-graph.
class AddImportsTransform
    : public NamedBlockGraphTransformImpl<AddImportsTransform> {
 public:
  typedef block_graph::BlockGraph BlockGraph;

  // Some forward declares.
  struct ImportedModule;

  AddImportsTransform();

  // Adds the given module and symbols to the list of modules and symbols to
  // import.
  void AddModule(ImportedModule* imported_module) {
    DCHECK(imported_module != NULL);
    imported_modules_.push_back(imported_module);
  }

  // Performs the transform. Adds entries for any missing modules and symbols,
  // returning references to their entries via the ImportedModule structures.
  //
  // @param block_graph the BlockGraph to populate.
  // @param dos_header_block the block containing the module's DOS header.
  // @returns true on success, false otherwise.
  virtual bool TransformBlockGraph(
      BlockGraph* block_graph, BlockGraph::Block* dos_header_block) OVERRIDE;

  // @returns the number of imported modules that were added to the image.
  size_t modules_added() const { return modules_added_; }

  // @returns the number of imported symbols that were added to the image.
  size_t symbols_added() const { return symbols_added_; }

  // @returns a pointer to the Block containing the Image Import Descriptor.
  BlockGraph::Block* image_import_descriptor_block() {
    return image_import_descriptor_block_;
  }

  // @returns a pointer to the Block containing the Import Address Table.
  BlockGraph::Block* import_address_table_block() {
    return import_address_table_block_;
  }

  // The name of this transform.
  static const char kTransformName[];

 protected:
  // A collection of modules (and symbols from them) to be imported. This
  // must be populated prior to calling the transform.
  std::vector<ImportedModule*> imported_modules_;

  // Statistics regarding the completed transform.
  size_t modules_added_;
  size_t symbols_added_;

  // We cache the blocks containing the IDT and IAT.
  BlockGraph::Block* image_import_descriptor_block_;
  BlockGraph::Block* import_address_table_block_;
};

// Describes a list of symbols to be imported from a module.
struct AddImportsTransform::ImportedModule {
  ImportedModule() { }

  typedef block_graph::TypedBlock<IMAGE_IMPORT_DESCRIPTOR>
      ImageImportDescriptor;

  // Used to indicate that a symbol has not been imported.
  static const size_t kInvalidIatIndex;

  // The various modes in which the transform will treat a symbol.
  enum TransformMode {
    // Will search for the imported symbol and explicitly add an import entry
    // for it if it doesn't already exist.
    kAlwaysImport,
    // Will search for the imported symbol, ignoring it if not found.
    kFindOnly,
  };

  // @param module_name the name of the module to import.
  explicit ImportedModule(const base::StringPiece& module_name)
      : name_(module_name.begin(), module_name.end()), mode_(kFindOnly),
        added_(false) {
  }

  // Accesses the name of the module.
  // @returns the name of the module to import.
  const std::string& name() const { return name_; }

  // @returns the mode of the transform.
  TransformMode mode() const { return mode_; }

  // Determines if this module has been imported.
  // @returns true if there is an import entry for this module, false otherwise.
  // @note this is only meaningful after this transform has been applied.
  bool ModuleIsImported() const { return import_descriptor_.block() != NULL; }

  // Determines if this module was added to the import table by the transform.
  // @returns true if the module was added, false otherwise.
  // @note this is only meaningful after this transform has been applied.
  bool ModuleWasAdded() const { return added_; }

  // @returns the import descriptor for this module.
  // @note this is only meaningful after this transform has been applied, and
  //     is only valid immediately after the transform. All bets are off if
  //     another transform is applied.
  const ImageImportDescriptor& import_descriptor() const {
    return import_descriptor_;
  }
  ImageImportDescriptor& import_descriptor() {
    return import_descriptor_;
  }

  // Adds a symbol to be imported, returning its index.
  // @param symbol_name the symbol to be added.
  // @param mode the transform mode.
  // @returns the index of the symbol in this module, to be used for querying
  //     information about the symbol post-transform.
  size_t AddSymbol(const base::StringPiece& symbol_name,
                   TransformMode mode);

  // Returns the number of symbols that are to be imported from this module.
  size_t size() const { return symbols_.size(); }

  // Accesses the name of the index'th symbol.
  //
  // @param index the index of the symbol to fetch.
  // @returns the name of the index'th symbol.
  const std::string& GetSymbolName(size_t index) const {
    DCHECK_LT(index, symbols_.size());
    return symbols_[index].name;
  }

  // @param index the index of the symbol to query.
  // @returns true if the @p index'th symbol is find only.
  TransformMode GetSymbolMode(size_t index) const {
    DCHECK_LT(index, symbols_.size());
    return symbols_[index].mode;
  }

  // @param index the index of the symbol to query.
  // @returns true if the @p index symbol has an import entry.
  // @note this is only meaningful after the transformation has been applied.
  bool SymbolIsImported(size_t index) const {
    DCHECK_LT(index, symbols_.size());
    return symbols_[index].iat_index != kInvalidIatIndex;
  }

  // @param index the index of the symbol to fetch.
  // @returns true if the symbol was added, false otherwise.
  // @note this is only meaningful after the transformation has been applied.
  bool SymbolWasAdded(size_t index) const {
    DCHECK_LT(index, symbols_.size());
    return symbols_[index].added;
  }

  // @param index the index of the symbol to query.
  // @returns the index of the symbol in the IAT and the HNA/INT. This can be
  //     used for directly navigating the IID returned by 'import_descriptor'.
  //     Returns kInvalidIatIndex if the symbol was not imported.
  // @note this is only meaningful after the transformation has been applied.
  size_t GetSymbolIatIndex(size_t index) const {
    DCHECK_LT(index, symbols_.size());
    return symbols_[index].iat_index;
  }

  // Gets an absolute reference to the IAT entry of the ith symbol. Returns
  // true on success, false if this was not possible. This will fail if the
  // AddImportsTransform has not successfully run on this ImportedModule
  // object, or if this symbol is in kFindOnly mode and no import exists for
  // the symbol. See SymbolIsImported.
  //
  // The returned reference is only valid while the import data directory is
  // not modified. Once added to a block, the imports may be further modified
  // and reference tracking will ensure things are kept up to date; until this
  // time @p abs_reference is left dangling.
  //
  // @param index the index of the symbol to fetch.
  // @param abs_reference the reference to populate.
  // @returns true on success, false otherwise.
  bool GetSymbolReference(size_t index,
                          BlockGraph::Reference* abs_reference) const;

 private:
  // The AddImportsTransform is a friend so that it may directly set certain
  // output structures.
  friend AddImportsTransform;

  // Represents a symbol imported from this library. Currently this only
  // supports importing by name, but we could always extend this to handle
  // ordinals.
  struct Symbol {
    // The name of the symbol to import.
    std::string name;
    // The index of the imported symbol in the module's Import Name Table. This
    // is left as kInvalidIatIndex if this symbol's mode is kFindOnly and the
    // import does not exist.
    size_t iat_index;
    // The transform mode for this symbol.
    TransformMode mode;
    // If this is true then the symbol was added by the transform.
    bool added;
  };

  // The name of the module to be imported.
  std::string name_;

  // The image import descriptor associated with this module. This will refer
  // to a block in the block-graph provided to the AddImportsTransform, assuming
  // successful completion.
  ImageImportDescriptor import_descriptor_;

  // The list of symbols to be imported from this module.
  std::vector<Symbol> symbols_;

  // Transform mode for the whole module. Is kFindOnly if all symbols in this
  // module are kFindOnly, otherwise is kAlwaysImport.
  TransformMode mode_;

  // Set to true if this module was added to image by the transform.
  bool added_;

  DISALLOW_COPY_AND_ASSIGN(ImportedModule);
};

}  // namespace transforms
}  // namespace pe

#endif  // SYZYGY_PE_TRANSFORMS_ADD_IMPORTS_TRANSFORM_H_
