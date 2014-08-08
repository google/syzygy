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

#include "base/strings/string_piece.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "syzygy/common/align.h"

namespace pe {
namespace transforms {
namespace {

using block_graph::BlockGraph;
using block_graph::ConstTypedBlock;
using block_graph::TypedBlock;

static const BlockGraph::Offset kInvalidCoffSymbol = -1;

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

  // Read existing symbols.
  CoffSymbolNameOffsetMap known_names;
  if (!BuildCoffSymbolNameOffsetMap(symbols_block, strings_block,
                                    &known_names)) {
    return false;
  }

  // Handle symbols from each library.
  CoffSymbolNameOffsetMap names_to_add;
  size_t string_len_to_add = 0;
  for (size_t i = 0; i < imported_modules_.size(); ++i) {
    if (!FindAndCollectSymbolsFromModule(file_header, known_names,
                                         imported_modules_[i],
                                         &names_to_add, &string_len_to_add))
      return false;
  }

  // Add symbols if necessary.
  if (names_to_add.size() > 0) {
    size_t old_symbols_block_size = symbols_block->size();

    // Update symbol and string blocks.
    symbols_block->InsertData(old_symbols_block_size,
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

    CoffSymbolNameOffsetMap::iterator to_add_it = names_to_add.begin();
    for (; to_add_it != names_to_add.end(); ++to_add_it) {
      DCHECK_GT(strings_block->size(), string_cursor);
      DCHECK_EQ(1u, to_add_it->second.size());

      BlockGraph::Offset offset = *to_add_it->second.begin();
      DCHECK_LE(old_symbols_block_size, static_cast<size_t>(offset));
      size_t index = offset / sizeof(IMAGE_SYMBOL);

      std::memcpy(strings_block->GetMutableData() + string_cursor,
                  to_add_it->first.c_str(), to_add_it->first.size() + 1);
      IMAGE_SYMBOL* symbol = &symbols[index];
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
    const CoffSymbolNameOffsetMap& known_names,
    ImportedModule* module,
    CoffSymbolNameOffsetMap* names_to_add,
    size_t* string_len_to_add) {
  DCHECK(module != NULL);
  DCHECK(names_to_add != NULL);
  DCHECK(string_len_to_add != NULL);

  for (size_t i = 0; i < module->size(); ++i) {
    BlockGraph::Offset symbol_import_offset = kInvalidCoffSymbol;
    bool symbol_imported = false;
    bool symbol_added = false;

    std::string name(module->GetSymbolName(i));
    CoffSymbolNameOffsetMap::const_iterator it = known_names.find(name);
    if (it != known_names.end()) {
      // This symbol is already defined. Simply grab its offset which we can
      // use to draw a reference to it later. We grab the offset of its first
      // definition if it is multiply defined.
      symbol_import_offset = *it->second.begin();
      symbol_imported = true;
    } else if (module->GetSymbolMode(i) == ImportedModule::kAlwaysImport) {
      // The symbol is not defined, but requested to be. Create it.
      size_t new_index = file_header->NumberOfSymbols + names_to_add->size();
      symbol_import_offset = new_index * sizeof(IMAGE_SYMBOL);
      CoffSymbolNameOffsetMap::iterator add_it =
          names_to_add->insert(std::make_pair(name, CoffSymbolOffsets())).first;

      if (add_it->second.empty()) {
        // When adding the symbol for the first time ensure to reserve room in
        // the string table.
        add_it->second.insert(symbol_import_offset);
        *string_len_to_add += name.size() + 1;
      } else {
        // If this symbols is already to be added then reuse its offset.
        symbol_import_offset = *add_it->second.begin();
      }

      symbol_imported = true;
      symbol_added = true;
    }

    UpdateModuleSymbolInfo(i, symbol_imported, symbol_added, module);
    symbols_added_ += symbol_added;
    if (symbol_imported) {
      module_symbol_offset_map_.insert(
          std::make_pair(std::make_pair(module, i), symbol_import_offset));
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
    ModuleSymbolOffsetMap::const_iterator offset_it =
        module_symbol_offset_map_.find(std::make_pair(module, i));
    if (offset_it == module_symbol_offset_map_.end())
      continue;
    BlockGraph::Offset import_offset = offset_it->second;
    DCHECK_NE(kInvalidCoffSymbol, import_offset);
    BlockGraph::Reference ref(BlockGraph::RELOC_ABSOLUTE_REF, sizeof(uint32),
                              symbols_block, import_offset, import_offset);
    UpdateModuleSymbolReference(i, ref, false, module);
  }
}

}  // namespace transforms
}  // namespace pe
