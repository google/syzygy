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
//
// Utilities that are specific to dealing with COFF files in block-graph
// representation.

#ifndef SYZYGY_PE_COFF_UTILS_H_
#define SYZYGY_PE_COFF_UTILS_H_

#include <windows.h>
#include <winnt.h>

#include "base/callback.h"
#include "syzygy/block_graph/block_graph.h"

namespace pe {

// Retrieve the blocks containing the headers, symbol and strings tables
// from the block graph. Each of @p headers_block, @p symbols_block and
// @p strings_block may be NULL if the corresponding block needs not be
// retrieved.
//
// @param block_graph the graph to extract blocks from.
// @param headers_block where to store the headers block.
// @param symbols_block where to store the symbol table block.
// @param strings_block where to store the string table block.
// @returns true if all three blocks are found, false otherwise.
bool FindCoffSpecialBlocks(block_graph::BlockGraph* block_graph,
                           block_graph::BlockGraph::Block** headers_block,
                           block_graph::BlockGraph::Block** symbols_block,
                           block_graph::BlockGraph::Block** strings_block);

// Gets the name of a symbol in the given block and offset.
// @param symbols_block block containing symbols.
// @param strings_block block containing strings.
// @param symbol_offset The offset of the symbol in question.
// @param name receives the name of the symbol.
// @returns true on success, false otherwise.
bool GetCoffSymbolName(const block_graph::BlockGraph::Block* symbols_block,
                       const block_graph::BlockGraph::Block* strings_block,
                       block_graph::BlockGraph::Offset symbol_offset,
                       base::StringPiece* name);

// Visitor callback for symbol iteration.
// |symbols_block| is the block containing the symbols.
// |strings_block| is the block containing the strings.
// |symbol_offset| is the offset of the symbol.
// The callback returns true to indicate success and continue the iteration,
// and false to indicate an error and abort the iteraton.
typedef base::Callback<
    bool(block_graph::BlockGraph::Block* /* symbols_block */,
         block_graph::BlockGraph::Block* /* strings_block */,
         block_graph::BlockGraph::Offset /* symbol_offset */)>
    VisitCoffSymbolCallback;

// @{
// Iterates over the symbols in a COFF image.
// @param callback is the callback to invoke for each symbol.
// @param symbols_block is the block containing the symbols.
// @param strings_block is the block containing the strings.
// @param block_graph is the block-graph containing a decomposed COFF image.
// @returns true on success, false otherwise.
bool VisitCoffSymbols(const VisitCoffSymbolCallback& callback,
                      block_graph::BlockGraph::Block* symbols_block,
                      block_graph::BlockGraph::Block* strings_block);
bool VisitCoffSymbols(const VisitCoffSymbolCallback& callback,
                      block_graph::BlockGraph* block_graph);
// @}

typedef std::set<block_graph::BlockGraph::Offset> CoffSymbolOffsets;

// @{
// Searches for a COFF symbol by name and returns its offset if found.
// @param symbol_name is the name of the symbol to find.
// @param symbols_block is the block containing the symbols.
// @param strings_block is the block containing the strings.
// @param block_graph is the block-graph containing a decomposed COFF image.
// @param symbol_offsets will be populated with the offsets of the corresponding
//     symbols. If no symbol is found this will be empty.
// @returns true on completion, false on error.
bool FindCoffSymbol(const base::StringPiece& symbol_name,
                    block_graph::BlockGraph::Block* symbols_block,
                    block_graph::BlockGraph::Block* strings_block,
                    CoffSymbolOffsets* symbol_offsets);
bool FindCoffSymbol(const base::StringPiece& symbol_name,
                    block_graph::BlockGraph* block_graph,
                    CoffSymbolOffsets* symbol_offsets);
// @}

// Used for mapping COFF symbols from their name to their offset(s) in the
// symbol block.
typedef std::map<std::string, CoffSymbolOffsets> CoffSymbolNameOffsetMap;

// @{
// Builds a map of COFF symbols by name, mapped to their offset in the symbols
// block. Special COFF symbols that are multiply defined map to
// kDuplicateCoffSymbol.
// @param symbols_block is the block containing the symbols.
// @param strings_block is the block containing the strings.
// @param block_graph is the block-graph containing a decomposed COFF image.
// @param map the map to be populated.
// @return true on success, false otherwise.
bool BuildCoffSymbolNameOffsetMap(
    block_graph::BlockGraph::Block* symbols_block,
    block_graph::BlockGraph::Block* strings_block,
    CoffSymbolNameOffsetMap* map);
bool BuildCoffSymbolNameOffsetMap(
    block_graph::BlockGraph* block_graph,
    CoffSymbolNameOffsetMap* map);
// @}

}  // namespace pe

#endif  // SYZYGY_PE_COFF_UTILS_H_
