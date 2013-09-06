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
  Symbol symbol = { symbol_name.as_string(), kInvalidImportIndex, mode };
  symbols_.push_back(symbol);

  // Keep track of whether all symbols in this module are kFindOnly; if at
  // least one is not, the whole module is considered kAlwaysImport.
  if (mode != ImportedModule::kFindOnly)
    mode_ = ImportedModule::kAlwaysImport;

  return symbols_.size() - 1;
}

bool ImportedModule::GetSymbolReference(size_t index,
                                        BlockGraph::Reference* ref,
                                        bool* is_ptr) const {
  DCHECK_GT(symbols_.size(), index);
  DCHECK(ref != NULL);
  DCHECK(is_ptr != NULL);

  if (symbols_[index].import_index == kInvalidImportIndex)
    return false;

  *ref = symbols_[index].ref;
  *is_ptr = symbols_[index].is_ptr;
  return true;
}

void PECoffAddImportsTransform::UpdateModule(bool imported,
                                             bool added,
                                             ImportedModule* imported_module) {
  DCHECK(imported_module != NULL);
  imported_module->imported_ = imported;
  imported_module->added_ = added;
}

void PECoffAddImportsTransform::UpdateModuleSymbolIndex(
    size_t index,
    size_t import_index,
    bool added,
    ImportedModule* imported_module) {
  DCHECK(imported_module != NULL);
  DCHECK_GT(imported_module->symbols_.size(), index);
  ImportedModule::Symbol* symbol = &imported_module->symbols_[index];
  symbol->import_index = import_index;
  symbol->added = added;
}

void PECoffAddImportsTransform::UpdateModuleSymbolReference(
    size_t index,
    BlockGraph::Reference ref,
    bool is_ptr,
    ImportedModule* imported_module) {
  DCHECK(imported_module != NULL);
  DCHECK_GT(imported_module->symbols_.size(), index);
  ImportedModule::Symbol* symbol = &imported_module->symbols_[index];
  symbol->ref = ref;
  symbol->is_ptr = is_ptr;
}

}  // namespace transforms
}  // namespace pe
