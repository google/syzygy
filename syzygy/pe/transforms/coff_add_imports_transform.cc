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

#include "syzygy/pe/transforms/coff_add_imports_transform.h"

#include <windows.h>
#include <map>

#include "base/string_piece.h"
#include "base/string_util.h"
#include "base/stringprintf.h"
#include "syzygy/common/align.h"
#include "syzygy/pe/pe_utils.h"

namespace pe {
namespace transforms {
namespace {

using block_graph::BlockGraph;
using block_graph::ConstTypedBlock;
using block_graph::TypedBlock;

const size_t kInvalidIndex = static_cast<size_t>(-1);

// Read symbols from the symbol table into a map from names to symbol
// indexes.
//
// @param symbols the symbol table.
// @param strings the string table.
// @param known_names map to which symbols are to be added.
void ReadExistingSymbols(const TypedBlock<IMAGE_SYMBOL>& symbols,
                         const TypedBlock<char>& strings,
                         CoffAddImportsTransform::NameMap* known_names) {
  size_t num_symbols = symbols.ElementCount();
  for (size_t i = 0; i < num_symbols; i += 1 + symbols[i].NumberOfAuxSymbols) {
    IMAGE_SYMBOL* symbol = &symbols[i];
    std::string name;
    if (symbol->N.Name.Short != 0)
      name = std::string(reinterpret_cast<const char*>(&symbol->N.ShortName));
    else
      name = std::string(&strings[symbol->N.Name.Long]);
    known_names->insert(std::make_pair(name, i));
  }
}

}  // namespace

const char CoffAddImportsTransform::kTransformName[] =
    "CoffAddImportsTransform";

bool CoffAddImportsTransform::TransformBlockGraph(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BlockGraph::Block* headers_block) {
  DCHECK_NE(reinterpret_cast<TransformPolicyInterface*>(NULL), policy);
  DCHECK_NE(reinterpret_cast<BlockGraph*>(NULL), block_graph);
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), headers_block);
  DCHECK_EQ(BlockGraph::COFF_IMAGE, block_graph->image_format());

  // Get file header.
  TypedBlock<IMAGE_FILE_HEADER> file_header;
  if (!file_header.Init(0, headers_block)) {
    LOG(ERROR) << "Unable to cast COFF file header.";
    return false;
  }

  // Get symbol and string tables.
  BlockGraph::Block* symbols_block = NULL;
  BlockGraph::Block* strings_block = NULL;
  if (!FindCoffSpecialBlocks(block_graph,
                             NULL, &symbols_block, &strings_block)) {
    LOG(ERROR) << "Block graph is missing some COFF special blocks. "
               << "Not a COFF block graph?";
    return false;
  }
  DCHECK(symbols_block != NULL);
  DCHECK(strings_block != NULL);

  TypedBlock<IMAGE_SYMBOL> symbols;
  if (!symbols.Init(0, symbols_block)) {
    LOG(ERROR) << "Unable to cast symbol table.";
    return false;
  }
  DCHECK_EQ(file_header->NumberOfSymbols, symbols.ElementCount());

  TypedBlock<char> strings;
  if (!strings.Init(0, strings_block)) {
    LOG(ERROR) << "Unable to cast string table.";
    return false;
  }

  // Read existing symbols.
  NameMap known_names;
  ReadExistingSymbols(symbols, strings, &known_names);

  // Handle symbols from each library.
  NameMap names_to_add;
  size_t string_len_to_add = 0;
  for (size_t i = 0; i < imported_modules_.size(); ++i) {
    if (!FindAndCollectSymbolsFromModule(file_header, known_names,
                                         imported_modules_[i],
                                         &names_to_add, &string_len_to_add))
      return false;
  }

  // Add symbols if necessary.
  if (names_to_add.size() > 0) {
    // Update symbol and string blocks.
    symbols_block->InsertData(symbols_block->size(),
                              names_to_add.size() * sizeof(IMAGE_SYMBOL),
                              true);
    symbols_block->ResizeData(symbols_block->size());
    if (!symbols.Init(0, symbols_block)) {
      LOG(ERROR) << "Unable to cast symbol table.";
      return false;
    }

    size_t string_cursor = strings_block->size();
    strings_block->InsertData(string_cursor, string_len_to_add, true);
    strings_block->ResizeData(strings_block->size());
    if (!strings.Init(0, strings_block)) {
      LOG(ERROR) << "Unable to cast string table.";
      return false;
    }

    NameMap::iterator to_add_it = names_to_add.begin();
    for (; to_add_it != names_to_add.end(); ++to_add_it) {
      DCHECK_GT(strings_block->size(), string_cursor);
      std::memcpy(&strings[string_cursor], to_add_it->first.c_str(),
                  to_add_it->first.size() + 1);
      IMAGE_SYMBOL* symbol = &symbols[to_add_it->second];
      symbol->N.Name.Short = 0;
      symbol->N.Name.Long = string_cursor;
      symbol->Type = IMAGE_SYM_DTYPE_FUNCTION << 4;
      symbol->StorageClass = IMAGE_SYM_CLASS_EXTERNAL;
      string_cursor += to_add_it->first.size() + 1;
    }
    DCHECK_EQ(strings_block->size(), string_cursor);

    // Update the file header.
    file_header->NumberOfSymbols = symbols.ElementCount();

    // Update string table size.
    TypedBlock<uint32> strings_size;
    if (!strings_size.Init(0, strings_block)) {
      LOG(ERROR) << "Unable to cast string table size prefix.";
      return false;
    }
    *strings_size = string_cursor;
  }

  // Update import module symbols.
  for (size_t i = 0; i < imported_modules_.size(); ++i)
    UpdateModuleReferences(symbols_block, imported_modules_[i]);

  return true;
}

bool CoffAddImportsTransform::FindAndCollectSymbolsFromModule(
    const TypedBlock<IMAGE_FILE_HEADER>& file_header,
    const NameMap& known_names,
    ImportedModule* module,
    NameMap* names_to_add,
    size_t* string_len_to_add) {
  DCHECK(module != NULL);
  DCHECK(names_to_add != NULL);
  DCHECK(string_len_to_add != NULL);

  for (size_t i = 0; i < module->size(); ++i) {
    size_t symbol_import_index = kInvalidIndex;
    bool symbol_imported = false;
    bool symbol_added = false;

    std::string name(module->GetSymbolName(i));
    NameMap::const_iterator it = known_names.find(name);
    if (it != known_names.end()) {
      // This symbol is already defined. Simply grab its 'index' which we can
      // use to draw a reference to it later.
      symbol_import_index = it->second;
      symbol_imported = true;
    } else if (module->GetSymbolMode(i) == ImportedModule::kAlwaysImport) {
      // The symbol is not defined, but requested to be. Create it.
      size_t new_index = file_header->NumberOfSymbols + names_to_add->size();
      if (!names_to_add->insert(std::make_pair(name, new_index)).second) {
        LOG(ERROR) << "Duplicate entry \"" << name
                    << "\" in requested imported module.";
        return false;
      }
      symbol_import_index = new_index;
      symbol_imported = true;
      symbol_added = true;
      *string_len_to_add += name.size() + 1;
    }

    UpdateModuleSymbolInfo(i, symbol_imported, symbol_added, module);
    symbols_added_ += symbol_added;
    if (symbol_imported) {
      module_symbol_index_map_.insert(
          std::make_pair(std::make_pair(module, i), symbol_import_index));
    }
  }

  // All modules are considered imported in a COFF file, and none is ever
  // added by the transform.
  UpdateModule(true, false, module);

  return true;
}

void CoffAddImportsTransform::UpdateModuleReferences(
    BlockGraph::Block* symbols_block,
    ImportedModule* module) {
  for (size_t i = 0; i < module->size(); ++i) {
    ModuleSymbolIndexMap::const_iterator index_it =
        module_symbol_index_map_.find(std::make_pair(module, i));
    if (index_it == module_symbol_index_map_.end())
      continue;
    size_t import_index = index_it->second;
    DCHECK_NE(kInvalidIndex, import_index);
    BlockGraph::Offset offset = import_index * sizeof(IMAGE_SYMBOL);
    BlockGraph::Reference ref(BlockGraph::RELOC_ABSOLUTE_REF, sizeof(uint32),
                              symbols_block, offset, offset);
    UpdateModuleSymbolReference(i, ref, false, module);
  }
}

}  // namespace transforms
}  // namespace pe
