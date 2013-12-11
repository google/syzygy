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
//
// Definitions of the PECoffAddImportsTransform base class, and auxiliary
// ImportedModule class. PECoffAddImportsTransform is the base class common
// to both PE and COFF transforms that add external (imported) symbols to
// a block graph.
//
// The base class provides helper routines and definitions, as well as part
// of the common interface, through the ImportedModule class and AddModule()
// method.

#ifndef SYZYGY_PE_TRANSFORMS_PE_COFF_ADD_IMPORTS_TRANSFORM_H_
#define SYZYGY_PE_TRANSFORMS_PE_COFF_ADD_IMPORTS_TRANSFORM_H_

#include "base/string_piece.h"
#include "syzygy/block_graph/block_graph.h"

namespace pe {
namespace transforms {

// A list of symbols to be imported from a module.
class ImportedModule {
 public:
  // Used to indicate that the date/time stamp for the module should not be
  // updated.
  static const uint32 kInvalidDate = -1;

  // Used to indicate that a symbol has not been imported.
  static const size_t kInvalidImportIndex = -1;

  // The modes in which the transform will treat a symbol.
  enum TransformMode {
    // Will search for the imported symbol and explicitly add an import entry
    // for it if it doesn't already exist.
    kAlwaysImport,
    // Will search for the imported symbol, ignoring it if not found.
    kFindOnly,
  };

  // Construct an empty module with the specified name, that initially
  // specifies no symbol to import.
  //
  // @param module_name the name of the module to import.
  explicit ImportedModule(const base::StringPiece& module_name)
      : name_(module_name.begin(), module_name.end()),
        date_(kInvalidDate),
        imported_(false),
        mode_(kFindOnly),
        added_(false) {
  }

  // Construct an empty module with the specified name and date, that
  // initially specifies no symbol to import.
  //
  // If not kInvalidDate, @p date specifies a version time stamp to be
  // associated with the imported module, the exact meaning of which, if
  // any, is dependent on the format.
  //
  // @param module_name the name of the module to import.
  // @param date the version time stamp.
  ImportedModule(const base::StringPiece& module_name, uint32 date)
      : name_(module_name.begin(), module_name.end()),
        date_(date),
        imported_(false),
        mode_(kFindOnly),
        added_(false) {
  }

  // @returns the name of the module to import.
  const std::string& name() const { return name_; }

  // @returns the version date/time stamp of the module to import.
  uint32 date() const { return date_; }

  // @returns the mode of the transform.
  TransformMode mode() const { return mode_; }

  // After a successful transform, retrieve whether the module is imported.
  //
  // @returns true if there is an import entry for this module, false otherwise.
  bool ModuleIsImported() const { return imported_; }

  // After a successful transform, retrieve whether the module has been added.
  //
  // @returns true if the module was added, false otherwise.
  bool ModuleWasAdded() const { return added_; }

  // Add a symbol to be imported, returning its index. If the symbol already
  // exists this will return the existing index rather than adding it a second
  // time.
  //
  // @param symbol_name the symbol to be added.
  // @param mode the transform mode.
  // @returns the index of the symbol in this module, to be used for querying
  //     information about the symbol.
  size_t AddSymbol(const base::StringPiece& symbol_name,
                   TransformMode mode);

  // @returns the number of symbols that are to be imported from this module.
  size_t size() const { return symbols_by_index_.size(); }

  // Retrieve the name of a symbol to import.
  //
  // @param index the index of the symbol to fetch.
  // @returns the name of the symbol.
  const std::string& GetSymbolName(size_t index) const {
    DCHECK_GT(symbols_by_index_.size(), index);
    return symbols_by_index_[index]->name;
  }

  // Retrieve the transform mode of a symbol to import.
  //
  // @param index the index of the symbol to query.
  // @returns the mode of the symbol.
  TransformMode GetSymbolMode(size_t index) const {
    DCHECK_GT(symbols_by_index_.size(), index);
    return symbols_by_index_[index]->mode;
  }

  // After a successful transform, retrieve whether the specified symbol is
  // effectively imported. If the symbol mode is kAlwaysImport, true will
  // always be returned; if it is kFindOnly, the import state of the symbol
  // is returned.
  //
  // @param index the index of the symbol to query.
  // @returns true if the symbol @p index has an import entry.
  bool SymbolIsImported(size_t index) const {
    DCHECK_GT(symbols_by_index_.size(), index);
    return symbols_by_index_[index]->import_index != kInvalidImportIndex;
  }

  // After a successful transform, retrieve whether the specified symbol was
  // added by the transform. If the symbol mode is kFindOnly, false will
  // always be returned; if it is kAlwaysImport, true is returned if adding
  // a symbol entry was necessary.
  //
  // @param index the index of the symbol to fetch.
  // @returns true if the symbol was added, false otherwise.
  bool SymbolWasAdded(size_t index) const {
    DCHECK_GT(symbols_by_index_.size(), index);
    return symbols_by_index_[index]->added;
  }

  // After a successful transform, retrieve the index of the symbol
  // entry. If the symbol mode is kFindOnly and the symbol was not found,
  // the default index kInvalidImportIndex is returned.
  //
  // @param index the index of the symbol to query.
  // @returns the index of the symbol entry, the meaning of which is
  //     dependent on the underlying import table representation, but is
  //     guaranteed to be distinct for distinct symbols.
  size_t GetSymbolImportIndex(size_t index) const {
    DCHECK_GT(symbols_by_index_.size(), index);
    return symbols_by_index_[index]->import_index;
  }

  // After a successful transform, retrieve an absolute reference to the
  // imported symbol. The returned reference may either be used as
  // a reference to the imported entity (if @p is_ptr is set to false), or
  // a reference to a pointer to the imported entity (if @p is_ptr is set to
  // true).
  //
  // The returned reference is only valid while no new symbols are imported,
  // and must be used or discarded before applying other transforms that may
  // add or remove symbols.
  //
  // Once a reference is used and inserted in a block, the imports may be
  // further modified and reference tracking will ensure things are kept up
  // to date; until then, @p reference is left dangling.
  //
  // @param index the index of the symbol to fetch.
  // @param ref the reference to populate.
  // @param is_ptr set to true if the reference is to a pointer instead of
  //     the actual imported entity.
  // @returns true on success, false otherwise.
  bool GetSymbolReference(size_t index,
                          block_graph::BlockGraph::Reference* ref,
                          bool* is_ptr) const;

  // Legacy GetSymbolReference() method.
  //
  // @see GetSymbolReference(size_t,block_graph::BlockGraph::Reference*,bool*)
  bool GetSymbolReference(size_t index,
                          block_graph::BlockGraph::Reference* ref) const {
    bool is_ptr = false;
    return GetSymbolReference(index, ref, &is_ptr);
  }

 protected:
  friend class PECoffAddImportsTransform;

  // A symbol imported from a module, by name.
  struct Symbol {
    // The name of the symbol to import.
    std::string name;
    // The ID of this symbol wrt to this imported module. This is an index into
    // symbols_by_index_.
    size_t symbol_index;
    // The index of the imported symbol in the symbol or import table. This
    // is left as kInvalidImportIndex if this symbol's mode is kFindOnly and
    // the import does not exist.
    size_t import_index;
    // The transform mode for this symbol.
    TransformMode mode;
    // If this is true then the symbol was added by the transform.
    bool added;
    // The reference to the imported symbol.
    block_graph::BlockGraph::Reference ref;
    // Whether the import symbol reference is to a pointer (true), or
    // directly to the object or function (false).
    bool is_ptr;

    // A comparison functor. This compares symbols by their names, ensuring
    // uniqueness.
    bool operator<(const Symbol& other) const {
      return name < other.name;
    }
  };

  typedef std::set<Symbol> SymbolSet;

  // The name of the module to be imported.
  std::string name_;

  // A version time stamp associated with the module.
  uint32 date_;

  // The symbols to be imported, sorted by name. This ensures that symbols are
  // stored uniquely.
  SymbolSet symbols_by_name_;

  // A mapping from symbol indices to symbol objects.
  std::vector<Symbol*> symbols_by_index_;

  // Set to true if this module was added or found by the transform.
  bool imported_;

  // Transform mode for the whole module. Is kFindOnly if all symbols in this
  // module are kFindOnly, otherwise is kAlwaysImport.
  TransformMode mode_;

  // Set to true if this module was added to image by the transform.
  bool added_;

 private:
  DISALLOW_COPY_AND_ASSIGN(ImportedModule);
};

// Common base class for transforms that add imported modules/symbols to
// a given block graph, for both PE and COFF formats.
class PECoffAddImportsTransform {
 public:
  // Construct an empty PECoffAddImportsTransform, that imports nothing
  // initially.
  PECoffAddImportsTransform() : modules_added_(0), symbols_added_(0) {}

  // Add the given module and its symbols to the list of modules and symbols
  // to import.
  //
  // @param imported_module the module to import.
  void AddModule(ImportedModule* imported_module) {
    DCHECK(imported_module != NULL);
    imported_modules_.push_back(imported_module);
  }

  // @returns the number of imported modules that were added to the image.
  size_t modules_added() const { return modules_added_; }

  // @returns the number of imported symbols that were added to the image.
  size_t symbols_added() const { return symbols_added_; }

 protected:
  // Update the import state of the specified module.
  //
  // @param imported whether the module is imported.
  // @param added whether the module has been added by the transform.
  // @param imported_module the module to update.
  static void UpdateModule(bool imported,
                           bool added,
                           ImportedModule* imported_module);

  // Update the import index of the specified symbol.
  //
  // @param index the index of the symbol to update.
  // @param import_index the import index to associate with the symbol.
  // @param added whether an entry was added for this symbol.
  // @param imported_module the module to update.
  static void UpdateModuleSymbolIndex(
      size_t index,
      size_t import_index,
      bool added,
      ImportedModule* imported_module);

  // Update the import reference of the specified symbol.
  //
  // @param index the index of the symbol to update.
  // @param ref the import reference to associate with the symbol.
  // @param is_ptr whether the reference is to a pointer or the actual thing.
  // @param imported_module the module to update.
  static void UpdateModuleSymbolReference(
      size_t index,
      block_graph::BlockGraph::Reference ref,
      bool is_ptr,
      ImportedModule* imported_module);

  // A collection of modules (and symbols from them) to be imported. This
  // must be populated prior to calling TransformBlockGraph().
  std::vector<ImportedModule*> imported_modules_;

  // Statistics regarding the completed transform.
  size_t modules_added_;
  size_t symbols_added_;

 private:
  DISALLOW_COPY_AND_ASSIGN(PECoffAddImportsTransform);
};

}  // namespace transforms
}  // namespace pe

#endif  // SYZYGY_PE_TRANSFORMS_PE_COFF_ADD_IMPORTS_TRANSFORM_H_
