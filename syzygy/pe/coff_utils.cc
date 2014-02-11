// Copyright 2014 Google Inc. All Rights Reserved.
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

#include "syzygy/pe/coff_utils.h"

#include "base/bind.h"
#include "syzygy/block_graph/typed_block.h"

namespace pe {

namespace {

using block_graph::BlockGraph;
using block_graph::TypedBlock;

// This is used by FindCoffSymbol as a callback function with VisitCoffSymbols.
bool VisitCoffSymbol(const base::StringPiece& symbol_name,
                     BlockGraph::Offset* out_symbol_offset,
                     BlockGraph::Block* symbols_block,
                     BlockGraph::Block* strings_block,
                     BlockGraph::Offset symbol_offset) {
  DCHECK_NE(reinterpret_cast<BlockGraph::Offset*>(NULL), out_symbol_offset);
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), symbols_block);
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), strings_block);

  // We can abort the rest of the search in this case.
  if (*out_symbol_offset == kDuplicateCoffSymbol)
    return true;

  // Look for matching names.
  base::StringPiece name;
  if (!GetCoffSymbolName(symbols_block, strings_block, symbol_offset, &name))
    return false;
  if (name != symbol_name)
    return true;

  if (*out_symbol_offset == kInvalidCoffSymbol) {
    // This is the first time we've encountered this symbol name.
    *out_symbol_offset = symbol_offset;
  } else {
    // We've already encountered this symbol name.
    *out_symbol_offset = kDuplicateCoffSymbol;
  }

  return true;
}

bool AddSymbolToNameOffsetMap(CoffSymbolNameOffsetMap* map,
                              BlockGraph::Block* symbols_block,
                              BlockGraph::Block* strings_block,
                              BlockGraph::Offset symbol_offset) {
  DCHECK_NE(reinterpret_cast<CoffSymbolNameOffsetMap*>(NULL), map);
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), symbols_block);
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), strings_block);

  base::StringPiece name;
  if (!GetCoffSymbolName(symbols_block, strings_block, symbol_offset, &name))
    return false;

  std::string name2 = name.as_string();
  CoffSymbolNameOffsetMap::iterator it = map->find(name2);
  if (it != map->end()) {
    it->second = kDuplicateCoffSymbol;
    return true;
  }

  CHECK(map->insert(std::make_pair(name2, symbol_offset)).second);
  return true;
}

}  // namespace

bool FindCoffSpecialBlocks(BlockGraph* block_graph,
                           BlockGraph::Block** headers_block,
                           BlockGraph::Block** symbols_block,
                           BlockGraph::Block** strings_block) {
  DCHECK_NE(reinterpret_cast<BlockGraph*>(NULL), block_graph);

  bool headers_block_found = false;
  bool symbols_block_found = false;
  bool strings_block_found = false;

  // Walk through all the blocks once to find all the special blocks.
  BlockGraph::BlockMap& blocks = block_graph->blocks_mutable();
  BlockGraph::BlockMap::iterator it = blocks.begin();
  for (; it != blocks.end(); ++it) {
    if ((it->second.attributes() & BlockGraph::COFF_HEADERS) != 0) {
      if (headers_block != NULL)
        *headers_block = &it->second;
      headers_block_found = true;
    } else if ((it->second.attributes() & BlockGraph::COFF_SYMBOL_TABLE) != 0) {
      if (symbols_block != NULL)
        *symbols_block = &it->second;
      symbols_block_found = true;
    } else if ((it->second.attributes() & BlockGraph::COFF_STRING_TABLE) != 0) {
      if (strings_block != NULL)
        *strings_block = &it->second;
      strings_block_found = true;
    }
  }

  if (!headers_block_found || !symbols_block_found || !strings_block_found)
    return false;
  return true;
}

bool GetCoffSymbolName(const BlockGraph::Block* symbols_block,
                       const BlockGraph::Block* strings_block,
                       BlockGraph::Offset symbol_offset,
                       base::StringPiece* name) {
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), symbols_block);
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), strings_block);
  DCHECK_LE(0, symbol_offset);
  DCHECK_GE(symbols_block->data_size(), symbol_offset + sizeof(IMAGE_SYMBOL));
  DCHECK_NE(reinterpret_cast<base::StringPiece*>(NULL), name);

  // Cast to a raw symbol.
  const IMAGE_SYMBOL* symbol = reinterpret_cast<const IMAGE_SYMBOL*>(
      symbols_block->data() + symbol_offset);

  // If the symbol name is short enough it's stored directly in the symbol
  // record.
  if (symbol->N.Name.Short != 0) {
    // The string isn't necessarily zero terminated if it uses the whole
    // length, so we determine it's length using a cap.
    const char* s = reinterpret_cast<const char*>(&symbol->N.ShortName);

    size_t length = ::strnlen(s, sizeof(symbol->N.ShortName));
    *name = base::StringPiece(s, length);
    return true;
  }

  // Otherwise the name is stored in the string table, and is zero
  // terminated.
  size_t i = symbol->N.Name.Long;
  if (i >= strings_block->size()) {
    LOG(ERROR) << "COFF symbol name outside of strings block.";
    return false;
  }

  // If the string is outside of the data portion of the block then it is
  // implicitly zero length.
  if (i >= strings_block->data_size()) {
    *name = base::StringPiece(NULL, 0);
    return true;
  }

  // Determine the length of the symbol name.
  const char* s = reinterpret_cast<const char*>(
      strings_block->data() + symbol->N.Name.Long);
  size_t max_length = strings_block->data_size() - symbol->N.Name.Long;
  size_t length = ::strnlen(s, max_length);

  // Ensure the terminating zero is actually in the strings block.
  if (length == max_length &&
      strings_block->data_size() == strings_block->size()) {
    LOG(ERROR) << "COFF symbol name has no terminating NUL.";
    return false;
  }

  *name = base::StringPiece(s, length);
  return true;
}

bool VisitCoffSymbols(const VisitCoffSymbolCallback& callback,
                      BlockGraph::Block* symbols_block,
                      BlockGraph::Block* strings_block) {
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), symbols_block);
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), strings_block);

  TypedBlock<IMAGE_SYMBOL> symbols;
  if (!symbols.Init(0, symbols_block)) {
    LOG(ERROR) << "Unable to cast symbol table.";
    return false;
  }

  size_t num_symbols = symbols.ElementCount();
  for (size_t i = 0; i < num_symbols; i += 1 + symbols[i].NumberOfAuxSymbols) {
    IMAGE_SYMBOL* symbol = &symbols[i];
    size_t symbol_offset = i * sizeof(IMAGE_SYMBOL);
    if (!callback.Run(symbols_block, strings_block, symbol_offset))
      return false;
  }

  return true;
}

bool VisitCoffSymbols(const VisitCoffSymbolCallback& callback,
                      BlockGraph* block_graph) {
  DCHECK_NE(reinterpret_cast<BlockGraph*>(NULL), block_graph);

  BlockGraph::Block* symbols_block = NULL;
  BlockGraph::Block* strings_block = NULL;
  if (!FindCoffSpecialBlocks(block_graph, NULL, &symbols_block,
                             &strings_block)) {
    return false;
  }

  if (!VisitCoffSymbols(callback, symbols_block, strings_block))
    return false;

  return true;
}

bool FindCoffSymbol(const base::StringPiece& symbol_name,
                    BlockGraph::Block* symbols_block,
                    BlockGraph::Block* strings_block,
                    BlockGraph::Offset* symbol_offset) {
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), symbols_block);
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), strings_block);
  DCHECK_NE(reinterpret_cast<BlockGraph::Offset*>(NULL), symbol_offset);

  *symbol_offset = kInvalidCoffSymbol;
  VisitCoffSymbolCallback callback = base::Bind(
      &VisitCoffSymbol, symbol_name, symbol_offset);
  if (!VisitCoffSymbols(callback, symbols_block, strings_block))
    return false;
  return true;
}

bool FindCoffSymbol(const base::StringPiece& symbol_name,
                    BlockGraph* block_graph,
                    BlockGraph::Offset* symbol_offset) {
  DCHECK_NE(reinterpret_cast<BlockGraph*>(NULL), block_graph);
  DCHECK_NE(reinterpret_cast<BlockGraph::Offset*>(NULL), symbol_offset);

  BlockGraph::Block* symbols_block = NULL;
  BlockGraph::Block* strings_block = NULL;
  if (!FindCoffSpecialBlocks(block_graph, NULL, &symbols_block,
                             &strings_block)) {
    return false;
  }

  if (!FindCoffSymbol(symbol_name, symbols_block, strings_block,
                      symbol_offset)) {
    return false;
  }

  return true;
}

bool BuildCoffSymbolNameOffsetMap(BlockGraph::Block* symbols_block,
                                  BlockGraph::Block* strings_block,
                                  CoffSymbolNameOffsetMap* map) {
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), symbols_block);
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), strings_block);
  DCHECK_NE(reinterpret_cast<CoffSymbolNameOffsetMap*>(NULL), map);

  map->clear();
  VisitCoffSymbolCallback callback = base::Bind(
      &AddSymbolToNameOffsetMap, base::Unretained(map));
  if (!VisitCoffSymbols(callback, symbols_block, strings_block))
    return false;
  return true;
}

bool BuildCoffSymbolNameOffsetMap(BlockGraph* block_graph,
                                  CoffSymbolNameOffsetMap* map) {
  DCHECK_NE(reinterpret_cast<BlockGraph*>(NULL), block_graph);
  DCHECK_NE(reinterpret_cast<CoffSymbolNameOffsetMap*>(NULL), map);

  BlockGraph::Block* symbols_block = NULL;
  BlockGraph::Block* strings_block = NULL;
  if (!FindCoffSpecialBlocks(block_graph, NULL, &symbols_block,
                             &strings_block)) {
    return false;
  }

  if (!BuildCoffSymbolNameOffsetMap(symbols_block, strings_block, map))
    return false;

  return true;
}

}  // namespace pe
