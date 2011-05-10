// Copyright 2011 Google Inc.
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

#include "syzygy/relink/order_relinker.h"

#include "base/file_util.h"
#include "base/json/json_reader.h"
#include "base/values.h"
#include "syzygy/pe/decomposer.h"

using pe::Decomposer;

OrderRelinker::OrderRelinker(
    const BlockGraph::AddressSpace& original_addr_space,
    BlockGraph* block_graph,
    const FilePath& order_file_path)
    : Relinker(original_addr_space, block_graph),
      order_file_path_(order_file_path) {
}

OrderRelinker::~OrderRelinker() {
}

bool OrderRelinker::Relink(const FilePath& input_dll_path,
                           const FilePath& input_pdb_path,
                           const FilePath& output_dll_path,
                           const FilePath& output_pdb_path,
                           const FilePath& order_file_path) {
  DCHECK(!input_dll_path.empty());
  DCHECK(!input_pdb_path.empty());
  DCHECK(!output_dll_path.empty());
  DCHECK(!output_pdb_path.empty());
  DCHECK(!order_file_path.empty());

  // Read and decompose the input image for starters.
  pe::PEFile input_dll;
  if (!input_dll.Init(input_dll_path)) {
    LOG(ERROR) << "Unable to read " << input_dll_path.value() << ".";
    return false;
  }

  Decomposer decomposer(input_dll, input_dll_path);
  Decomposer::DecomposedImage decomposed;
  if (!decomposer.Decompose(&decomposed, NULL,
                            Decomposer::STANDARD_DECOMPOSITION)) {
    LOG(ERROR) << "Unable to decompose " << input_dll_path.value() << ".";
    return false;
  }

  OrderRelinker relinker(decomposed.address_space, &decomposed.image,
                         order_file_path);
  if (!relinker.Relinker::Relink(decomposed.header, input_pdb_path,
                                 output_dll_path, output_pdb_path)) {
    LOG(ERROR) << "Unable to relink " << output_dll_path.value() << ".";
    return false;
  }

  return true;
}

bool OrderRelinker::ReorderCode(const IMAGE_SECTION_HEADER& section) {
  std::string file_string;
  if (!file_util::ReadFileToString(order_file_path_, &file_string)) {
    LOG(ERROR) << "Unable to read order file to string";
    return false;
  }

  scoped_ptr<Value> value(base::JSONReader::Read(file_string, false));
  ListValue* order;
  if (value.get() == NULL || !value->GetAsList(&order)) {
    LOG(ERROR) << "Order file does not contain a valid JSON list";
    return false;
  }

  RelativeAddress start = builder().next_section_address();
  RelativeAddress insert_at = start;
  std::set<BlockGraph::Block*> inserted_blocks;

  // Insert the ordered blocks into the new address space.
  for (ListValue::iterator iter = order->begin(); iter < order->end(); ++iter) {
    int address;
    if (!(*iter)->GetAsInteger(&address)) {
      LOG(ERROR) << "Unable to read address value from order list";
      return false;
    }

    BlockGraph::Block* block = original_addr_space().GetBlockByAddress(
        RelativeAddress(address));
    if (!block) {
      LOG(ERROR) << "Unable to get block at address " << address;
      return false;
    }
    // Two separate RVAs may point to the same block, so make sure we only
    // insert each block once.
    if (inserted_blocks.find(block) != inserted_blocks.end())
      continue;

    if (!builder().address_space().InsertBlock(insert_at, block)) {
      LOG(ERROR) << "Unable to insert block '" << block->name() << "' at "
          << insert_at;
    }
    insert_at += block->size();
    inserted_blocks.insert(block);
  }

  // Copy the remaining blocks from the code section.
  BlockGraph::AddressSpace::Range section_range(
      RelativeAddress(section.VirtualAddress), section.Misc.VirtualSize);
  AddressSpace::RangeMapConstIterPair section_blocks =
      original_addr_space().GetIntersectingBlocks(section_range.start(),
                                                  section_range.size());

  AddressSpace::RangeMapConstIter& section_it = section_blocks.first;
  for (; section_it != section_blocks.second; ++section_it) {
    BlockGraph::Block* block = section_it->second;
    if (inserted_blocks.find(block) != inserted_blocks.end())
      continue;

    if (!builder().address_space().InsertBlock(insert_at, block)) {
      LOG(ERROR) << "Unable to insert block '" << block->name() << "' at "
          << insert_at;
    }
    insert_at += block->size();
    inserted_blocks.insert(block);
  }

  // Create the code section.
  uint32 code_size = insert_at - start;
  builder().AddSegment(".text",
                       code_size,
                       code_size,
                       IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE |
                       IMAGE_SCN_MEM_READ);

  return true;
}
