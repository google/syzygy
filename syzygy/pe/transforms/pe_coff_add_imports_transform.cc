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

#include "syzygy/pe/transforms/pe_coff_add_imports_transform.h"

namespace pe {
namespace transforms {

using block_graph::BlockGraph;

size_t ImportedModule::AddSymbol(const base::StringPiece& symbol_name,
                                 TransformMode mode) {
  Symbol symbol = { symbol_name.as_string(),
                    symbols_by_index_.size(),
                    mode };
  std::pair<SymbolSet::iterator, bool> result = symbols_by_name_.insert(symbol);

  // We can safely cast away constness because we are not changing the key
  // portion of the Symbol (it's name). This is a bit of a hack that allows us
  // to use a std::set rather than a std::map and some hoop jumping.
  Symbol* inserted_symbol = const_cast<Symbol*>(&(*result.first));

  if (!result.second) {
    // Upgrade the mode to always-import if the symbol was previously inserted
    // as find-only.
    if (mode == ImportedModule::kAlwaysImport &&
        inserted_symbol->mode == ImportedModule::kFindOnly) {
      inserted_symbol->mode = ImportedModule::kAlwaysImport;
    }
  } else {
    // This symbol was newly added. Insert it into the reverse lookup array.
    DCHECK_EQ(symbol.symbol_index, inserted_symbol->symbol_index);
    symbols_by_index_.push_back(inserted_symbol);
  }

  // Keep track of whether all symbols in this module are kFindOnly; if at
  // least one is not, the whole module is considered kAlwaysImport.
  if (mode != ImportedModule::kFindOnly)
    mode_ = ImportedModule::kAlwaysImport;

  // Return the index of the symbol.
  return inserted_symbol->symbol_index;
}

bool ImportedModule::GetSymbolReference(size_t index,
                                        BlockGraph::Reference* ref,
                                        bool* is_ptr) const {
  DCHECK_GT(symbols_by_index_.size(), index);
  DCHECK(ref != NULL);
  DCHECK(is_ptr != NULL);

  Symbol* symbol = symbols_by_index_[index];
  if (!symbol->imported)
    return false;

  *ref = symbol->ref;
  *is_ptr = symbol->is_ptr;
  return true;
}

void PECoffAddImportsTransform::UpdateModule(bool imported,
                                             bool added,
                                             ImportedModule* imported_module) {
  DCHECK(imported_module != NULL);
  imported_module->imported_ = imported;
  imported_module->added_ = added;
}

void PECoffAddImportsTransform::UpdateModuleSymbolInfo(
    size_t index,
    bool imported,
    bool added,
    ImportedModule* imported_module) {
  DCHECK(imported_module != NULL);
  DCHECK_GT(imported_module->symbols_by_index_.size(), index);
  ImportedModule::Symbol* symbol = imported_module->symbols_by_index_[index];
  symbol->imported = imported;
  symbol->added = added;
}

void PECoffAddImportsTransform::UpdateModuleSymbolReference(
    size_t index,
    BlockGraph::Reference ref,
    bool is_ptr,
    ImportedModule* imported_module) {
  DCHECK(imported_module != NULL);
  DCHECK_GT(imported_module->symbols_by_index_.size(), index);
  ImportedModule::Symbol* symbol = imported_module->symbols_by_index_[index];
  symbol->ref = ref;
  symbol->is_ptr = is_ptr;
}

}  // namespace transforms
}  // namespace pe
