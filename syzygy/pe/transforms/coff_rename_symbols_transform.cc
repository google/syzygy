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

#include "syzygy/pe/transforms/coff_rename_symbols_transform.h"

#include <string>
#include <vector>

#include "syzygy/block_graph/typed_block.h"
#include "syzygy/pe/pe_utils.h"

namespace pe {
namespace transforms {

namespace {

using block_graph::BlockGraph;
using block_graph::TypedBlock;

void AddSymbol(const base::StringPiece& symbol_name,
               size_t template_index,
               BlockGraph::Block* symbols_block,
               BlockGraph::Block* strings_block,
               size_t* symbol_index) {
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), symbols_block);
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), strings_block);
  DCHECK_NE(reinterpret_cast<size_t*>(NULL), symbol_index);

  TypedBlock<IMAGE_SYMBOL> symbols;
  CHECK(symbols.Init(0, symbols_block));
  size_t symbol_count = symbols.ElementCount();
  size_t symbol_offset = sizeof(IMAGE_SYMBOL) * symbol_count;
  symbols_block->InsertData(symbol_offset, sizeof(IMAGE_SYMBOL), true);
  *symbol_index = symbol_count;
  IMAGE_SYMBOL* orig = &symbols[template_index];
  IMAGE_SYMBOL* symbol = &symbols[symbol_count];

  // Copy the metadata from the template symbol.
  symbol->Value = orig->Value;
  symbol->SectionNumber = orig->SectionNumber;
  symbol->Type = orig->Type;
  symbol->StorageClass = orig->StorageClass;
  symbol->NumberOfAuxSymbols = 0;

  // Determine whether the name goes in the string table or is embedded in the
  // symbol record itself.
  char* symbol_name_dst = NULL;
  size_t copy_size = 0;
  if (symbol_name.size() <= sizeof(symbol->N.ShortName)) {
    symbol_name_dst = reinterpret_cast<char*>(symbol->N.ShortName);
  } else {
    size_t string_offset = strings_block->size();
    strings_block->set_size(strings_block->size() + symbol_name.size() + 1);
    strings_block->ResizeData(strings_block->size());
    symbol_name_dst = reinterpret_cast<char*>(
        strings_block->GetMutableData()) + string_offset;
    symbol->N.Name.Long = string_offset;
  }

  // Copy the symbol name. We don't explicitly copy the terminating NULL, as
  // the data structure was initialized with zeros and we don't always need one
  // (the case of an 8-byte name, which is stored directly in the symbol).
  ::memcpy(symbol_name_dst, symbol_name.data(), symbol_name.size());

  return;
}

void TransferReferrers(BlockGraph::Offset src_offset,
                       BlockGraph::Offset dst_offset,
                       BlockGraph::Block* block) {
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), block);

  // Make a copy of the referrers set because we'll be modifying the original
  // as we traverse.
  BlockGraph::Block::ReferrerSet referrers = block->referrers();
  BlockGraph::Block::ReferrerSet::const_iterator ref_it = referrers.begin();
  for (; ref_it != referrers.end(); ++ref_it) {
    BlockGraph::Reference ref;
    CHECK(ref_it->first->GetReference(ref_it->second, &ref));
    DCHECK_EQ(block, ref.referenced());
    if (ref.offset() != src_offset)
      continue;

    BlockGraph::Offset delta = ref.base() - ref.offset();
    ref = BlockGraph::Reference(ref.type(), ref.size(), ref.referenced(),
                                dst_offset, dst_offset + delta);
    CHECK(!ref_it->first->SetReference(ref_it->second, ref));
  }
}

}  // namespace

const char CoffRenameSymbolsTransform::kTransformName[] =
    "CoffRenameSymbolsTransform";

void CoffRenameSymbolsTransform::AddSymbolMapping(const base::StringPiece& from,
                                                  const base::StringPiece& to) {
  mappings_.push_back(std::make_pair(from.as_string(), to.as_string()));
}

bool CoffRenameSymbolsTransform::TransformBlockGraph(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BlockGraph::Block* headers_block) {
  BlockGraph::Block* symbols_block;
  BlockGraph::Block* strings_block;
  if (!FindCoffSpecialBlocks(block_graph,
                             NULL, &symbols_block, &strings_block)) {
    LOG(ERROR) << "Block graph is missing some COFF special blocks. "
               << "Not a COFF block graph?";
    return false;
  }

  TypedBlock<IMAGE_SYMBOL> symbols;
  if (!symbols.Init(0, symbols_block)) {
    LOG(ERROR) << "Unable to cast symbol table.";
    return false;
  }

  block_graph::TypedBlock<char> strings;
  if (!strings.Init(0, strings_block)) {
    LOG(ERROR) << "Unable to cast string table.";
    return false;
  }

  typedef std::map<std::string, size_t> SymbolIndexMap;
  SymbolIndexMap symbol_index_map;

  strings_block->ResizeData(strings_block->size());

  // Process all of the symbols and maintain a map of their indexes.
  size_t num_symbols = symbols.ElementCount();
  for (size_t i = 0; i < num_symbols; i += 1 + symbols[i].NumberOfAuxSymbols) {
    IMAGE_SYMBOL* symbol = &symbols[i];
    std::string name;
    if (symbol->N.Name.Short != 0) {
      name = std::string(reinterpret_cast<const char*>(&symbol->N.ShortName));
    } else {
      name = std::string(&strings[symbol->N.Name.Long]);
    }

    symbol_index_map[name] = i;
  }

  for (size_t i = 0; i < mappings_.size(); ++i) {
    const std::string& src = mappings_[i].first;
    const std::string& dst = mappings_[i].second;
    SymbolIndexMap::const_iterator src_it = symbol_index_map.find(src);
    if (src_it == symbol_index_map.end()) {
      LOG(ERROR) << "Unable to find source symbol \"" << src << "\".";
      return false;
    }

    SymbolIndexMap::const_iterator dst_it = symbol_index_map.find(dst);
    size_t symbol_index = 0;
    if (dst_it != symbol_index_map.end()) {
      symbol_index = dst_it->second;
    } else {
      // If the symbol does not exist, then append it to the strings block.
      AddSymbol(dst, src_it->second, symbols_block, strings_block,
                &symbol_index);
    }

    BlockGraph::Offset src_offset = src_it->second * sizeof(IMAGE_SYMBOL);
    BlockGraph::Offset dst_offset = symbol_index * sizeof(IMAGE_SYMBOL);
    TransferReferrers(src_offset, dst_offset, symbols_block);
  }

  return true;
}

}  // namespace transforms
}  // namespace pe
