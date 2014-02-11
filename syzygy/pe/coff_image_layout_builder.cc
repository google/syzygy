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

// The COFF image layout builder does a lot of things (maybe too much for
// its own good):
// - Assign an address to each block.
// - Create and add a relocation block for each section, and remove old ones.
// - Fix file offset pointers in section contents, headers, and tables.
//
// Since these tasks are very dependent on internals of COFF, which are
// missing from our intermediate representation (the block graph and
// associated metadata), they must rely on additional data structures and
// book-keeping. Hence they are all collected in this single step instead
// of existing as distinct transforms.
//
// New relocation blocks need to be bound to specific sections, and that
// link is not represented in the section info we have in the block
// graph. It is probably not useful there as it would only be needed during
// patching of COFF headers, and useless with PE.
//
// Old relocation block removal could be done in a separate transform, but
// is image-layout-dependent and hence does not classify as a block graph
// transform.
//
// Fixing references could alternatively be done in the file writer. Most
// header fields need to be patched (or their reference updated) during
// image laying out, though. Also, relocation references need to be handled
// with the creation of the new relocation tables (and do not require
// patching). Here we choose to handle all references in the image layout
// builder instead of spreading the task across classes.

#include "syzygy/pe/coff_image_layout_builder.h"

#include <vector>

#include "base/auto_reset.h"
#include "base/string_util.h"
#include "syzygy/block_graph/typed_block.h"
#include "syzygy/common/align.h"
#include "syzygy/pe/coff_utils.h"
#include "syzygy/pe/pe_utils.h"

namespace pe {
namespace {

using block_graph::BlockGraph;
using block_graph::ConstTypedBlock;
using block_graph::OrderedBlockGraph;
using block_graph::TypedBlock;
using core::FileOffsetAddress;

// A temporary vector holding relocation entries, while building new
// relocation blocks.
typedef std::vector<IMAGE_RELOCATION> RelocVector;

// A map from references to symbol indexes, in order to translate references
// to relocations, which are symbol-based.
typedef std::map<std::pair<BlockGraph::Block*, BlockGraph::Offset>, size_t>
    SymbolMap;

// A map from section IDs to their (new) position in the resulting layout.
typedef std::map<BlockGraph::SectionId, size_t> SectionIndexMap;

// Microsoft specifications recommend 4-byte alignment for object files.
const size_t kFileAlignment = 4;

// The name of the new relocation blocks, generated from references.
const char kNewRelocsBlockName[] = "<refs>";

// Retrieve the COFF relocation type corresponding to the specified
// reference type and size.
//
// @param ref_type the reference type.
// @param ref_size the reference size.
// @param coff_reloc_type where to put the resulting COFF relocation type.
// @returns true on success, false on failure.
bool GetCoffRelocationType(BlockGraph::ReferenceType ref_type,
                           BlockGraph::Size ref_size,
                           uint16* coff_reloc_type) {
  switch (ref_type) {
    case BlockGraph::RELOC_ABSOLUTE_REF:
      DCHECK_EQ(sizeof(uint32), ref_size);
      *coff_reloc_type = IMAGE_REL_I386_DIR32;
      return true;
    case BlockGraph::RELOC_RELATIVE_REF:
      DCHECK_EQ(sizeof(uint32), ref_size);
      *coff_reloc_type = IMAGE_REL_I386_DIR32NB;
      return true;
    case BlockGraph::RELOC_SECTION_REF:
      DCHECK_EQ(sizeof(uint16), ref_size);
      *coff_reloc_type = IMAGE_REL_I386_SECTION;
      return true;
    case BlockGraph::RELOC_SECTION_OFFSET_REF:
      if (ref_size == sizeof(uint32)) {
         *coff_reloc_type = IMAGE_REL_I386_SECREL;
      } else {
        DCHECK_EQ(1u, ref_size);
        *coff_reloc_type = IMAGE_REL_I386_SECREL7;
      }
      return true;
    case BlockGraph::RELOC_PC_RELATIVE_REF:
      DCHECK_EQ(sizeof(uint32), ref_size);
      *coff_reloc_type = IMAGE_REL_I386_REL32;
      return true;
    default:
      LOG(ERROR) << "Unexpected reference type.";
      return false;
  }
}

// Write a reference value at the specified location. Write the full value
// for non-relocation references, or the additional offset only for
// relocation references.
//
// @tparam ValueType the type of data to write.
// @param ref the reference to write.
// @param block_offset the offset within @p block to alter.
// @param block the block to alter.
template <typename ValueType>
bool WriteReferenceValue(BlockGraph::Reference ref,
                         BlockGraph::Offset block_offset,
                         BlockGraph::Block* block) {
  DCHECK_EQ(sizeof(ValueType), ref.size());
  TypedBlock<ValueType> value;
  if (!value.Init(block_offset, block)) {
    LOG(ERROR) << "Unable to cast reference.";
    return false;
  }
  if ((ref.type() & BlockGraph::RELOC_REF_BIT) != 0) {
    *value = ref.offset() - ref.base();
  } else {
    *value = ref.offset();
  }
  return true;
}

// For each relocation reference in @p block, add a COFF relocation to the
// specified vector.
//
// @param block the block whose references are to be translated to
//     relocations.
// @param symbol_map the symbol map to use to match references with symbols.
// @param relocs vector to which the relocations are to be added.
// @returns true on success, false on failure.
bool AddRelocs(const BlockGraph::Block& block,
               const SymbolMap& symbol_map,
               RelocVector* relocs) {
  DCHECK(relocs != NULL);

  BlockGraph::Block::ReferenceMap::const_iterator it =
      block.references().begin();
  for (; it != block.references().end(); ++it) {
    // Skip non-relocation references.
    if ((it->second.type() & BlockGraph::RELOC_REF_BIT) == 0)
      continue;

    IMAGE_RELOCATION reloc = {};

    // Sections constructed by this class all have zero base RVA, so the
    // virtual address is just the offset.
    reloc.VirtualAddress = it->first;

    SymbolMap::const_iterator symbol_it =
        symbol_map.find(std::make_pair(it->second.referenced(),
                                       it->second.base()));
    if (symbol_it == symbol_map.end()) {
      LOG(ERROR) << "Missing COFF symbol for reference within a section block; "
                 << "cannot translate to relocation.";
      return false;
    }
    reloc.SymbolTableIndex = symbol_it->second;
    if (!GetCoffRelocationType(it->second.type(), it->second.size(),
                               &reloc.Type))
      return false;

    relocs->push_back(reloc);
  }
  return true;
}

}  // namespace

CoffImageLayoutBuilder::CoffImageLayoutBuilder(ImageLayout* image_layout)
    : PECoffImageLayoutBuilder(image_layout),
      headers_block_(NULL),
      symbols_block_(NULL),
      strings_block_(NULL) {
  PECoffImageLayoutBuilder::Init(kFileAlignment, kFileAlignment);
}

bool CoffImageLayoutBuilder::LayoutImage(
    const OrderedBlockGraph& ordered_graph) {
  DCHECK_EQ(image_layout_->blocks.graph(), ordered_graph.block_graph());

  BlockGraph::Block* headers_block = NULL;
  BlockGraph::Block* symbols_block = NULL;
  BlockGraph::Block* strings_block = NULL;

  if (!FindCoffSpecialBlocks(image_layout_->blocks.graph(),
                             &headers_block, &symbols_block, &strings_block)) {
    LOG(ERROR) << "Block graph is missing some COFF special blocks. "
               << "Not a COFF block graph?";
    return false;
  }
  DCHECK(headers_block != NULL);
  DCHECK(symbols_block != NULL);
  DCHECK(strings_block != NULL);

  DCHECK(headers_block_ == NULL);
  DCHECK(symbols_block_ == NULL);
  DCHECK(strings_block_ == NULL);
  base::AutoReset<BlockGraph::Block*> auto_reset_headers_block(
      &headers_block_, headers_block);
  base::AutoReset<BlockGraph::Block*> auto_reset_symbols_block(
      &symbols_block_, symbols_block);
  base::AutoReset<BlockGraph::Block*> auto_reset_strings_block(
      &strings_block_, strings_block);

  if (!LayoutHeaders())
    return false;

  if (!LayoutSectionBlocks(ordered_graph))
    return false;

  if (!LayoutSymbolAndStringTables(ordered_graph))
    return false;

  if (!RemoveOldRelocBlocks())
    return false;

  return true;
}

bool CoffImageLayoutBuilder::LayoutHeaders() {
  DCHECK(headers_block_ != NULL);
  DCHECK_EQ(0u, image_layout_->blocks.address_space_impl().size());
  DCHECK_EQ(0u, image_layout_->sections.size());

  if (IsValidDosHeaderBlock(headers_block_)) {
    LOG(ERROR) << "Found DOS header in purported COFF file.";
    return false;
  }

  // Lay out headers as the block in the image layout.
  DCHECK_EQ(0u, cursor_.value());
  if (!LayoutBlockImpl(headers_block_))
    return false;

  return true;
}

bool CoffImageLayoutBuilder::LayoutSectionBlocks(
    const OrderedBlockGraph& ordered_graph) {
  DCHECK(headers_block_ != NULL);
  DCHECK(symbols_block_ != NULL);
  DCHECK_LT(0u, cursor_.value());
  DCHECK_EQ(0u, image_layout_->sections.size());

  // Fetch pointers to headers.
  ConstTypedBlock<IMAGE_FILE_HEADER> file_header;
  if (!file_header.Init(0, headers_block_)) {
    LOG(ERROR) << "Unable to cast file header.";
    return false;
  }
  TypedBlock<IMAGE_SECTION_HEADER> section_headers;
  if (!section_headers.Init(sizeof(IMAGE_FILE_HEADER), headers_block_)) {
    LOG(ERROR) << "Unable to cast section headers.";
    return false;
  }
  if (file_header->NumberOfSections != section_headers.ElementCount()) {
    LOG(ERROR) << "File header section count does not agree with "
               << "element count in headers block ("
               << file_header->NumberOfSections
               << " vs " << section_headers.ElementCount() << ").";
    return false;
  }

  // Fetch pointer to symbols.
  ConstTypedBlock<IMAGE_SYMBOL> symbols;
  if (!symbols.Init(0, symbols_block_)) {
    LOG(ERROR) << "Unable to cast symbol table.";
    return false;
  }
  size_t num_symbols = symbols.ElementCount();

  // Collect symbol information for relocations.
  SymbolMap symbol_map;
  BlockGraph::Block::ReferenceMap::const_iterator it =
      symbols_block_->references().begin();
  for (size_t i = 0; i < num_symbols; i += 1 + symbols[i].NumberOfAuxSymbols) {
    if (it != symbols_block_->references().end()) {
      size_t ref_symbol_index = it->first / sizeof(IMAGE_SYMBOL);
      DCHECK_LE(i, ref_symbol_index);
      DCHECK_GT(num_symbols, ref_symbol_index);

      if (i == ref_symbol_index) {
        // Resolved (referenced) symbol. We override previously inserted
        // symbols for the same reference; this gives priority to actual
        // symbols at offset zero, rather than section definition symbols.
        DCHECK_LT(0, symbols[i].SectionNumber);
        std::pair<BlockGraph::Block*, BlockGraph::Offset> ref_pair =
          std::make_pair(it->second.referenced(), it->second.base());
        symbol_map.insert(std::make_pair(ref_pair, i)).first->second = i;

        // Skip any other references for this symbol or its auxiliary
        // symbols.
        size_t next_index = i + 1 + symbols[i].NumberOfAuxSymbols;
        do {
          ++it;
        } while (it != symbols_block_->references().end() &&
                 it->first / sizeof(IMAGE_SYMBOL) < next_index);

        continue;
      }
    }

    // External or misc (unreferenced), that lies between references.
    DCHECK_GE(0, symbols[i].SectionNumber);
    std::pair<BlockGraph::Block*, BlockGraph::Offset> ref_pair =
        std::make_pair(symbols_block_, i * sizeof(symbols[i]));
    symbol_map.insert(std::make_pair(ref_pair, i));
  }
  DCHECK(it == symbols_block_->references().end());

  // Lay out section and relocation blocks.
  OrderedBlockGraph::SectionList::const_iterator section_it =
      ordered_graph.ordered_sections().begin();
  OrderedBlockGraph::SectionList::const_iterator section_end =
      ordered_graph.ordered_sections().end();
  size_t section_index = 0;
  for (; section_it != section_end; ++section_it) {
    BlockGraph::Section* section = (*section_it)->section();
    DCHECK(section != NULL);

    // Fill in common section header information.
    if (section_index >= file_header->NumberOfSections) {
      LOG(ERROR) << "Not enough space in headers block for "
                 << "so many sections (" << section_index << ").";
      return false;
    }
    IMAGE_SECTION_HEADER* header = &section_headers[section_index];

    std::memset(header, 0, sizeof(*header));
    std::strncpy(reinterpret_cast<char*>(header->Name),
                 section->name().c_str(),
                 arraysize(header->Name));
    header->Characteristics = section->characteristics();

    // Handle section data.
    if (!OpenSection(*section))
      return false;

    FileOffsetAddress section_start(cursor_.value());
    RelocVector relocs;

    // Lay out section blocks and collect relocations.
    OrderedBlockGraph::BlockList::const_iterator block_it =
        (*section_it)->ordered_blocks().begin();
    OrderedBlockGraph::BlockList::const_iterator block_end =
        (*section_it)->ordered_blocks().end();
    for (; block_it != block_end; ++block_it) {
      BlockGraph::Block* block = *block_it;
      DCHECK(block != NULL);
      DCHECK(block->type() == BlockGraph::CODE_BLOCK ||
             (block->attributes() &
              (BlockGraph::SECTION_CONTRIB | BlockGraph::COFF_BSS)) != 0);

      // Fix references.
      BlockGraph::Block::ReferenceMap::const_iterator ref_it =
          block->references().begin();
      for (; ref_it != block->references().end(); ++ref_it) {
        // Section blocks should only have relocations and function-relative
        // file pointers, represented as section offsets, thanks to
        // function-level linking.
        BlockGraph::Reference ref(ref_it->second);
        if ((ref.type() & BlockGraph::RELOC_REF_BIT) == 0 &&
            ref.type() != BlockGraph::SECTION_OFFSET_REF) {
            LOG(ERROR) << "Unexpected reference type " << ref.type()
                       << " in section " << section_index << ".";
            return false;
        }

        switch (ref.size()) {
          case sizeof(uint32):
            if (!WriteReferenceValue<uint32>(ref, ref_it->first, block))
              return false;
            break;
          case sizeof(uint16):
            if (!WriteReferenceValue<uint16>(ref, ref_it->first, block))
              return false;
            break;
          case sizeof(uint8):
            // TODO(chrisha): This is really a special 7-bit relocation; we do
            // not touch these, for now.
            break;
          default:
            LOG(ERROR) << "Unsupported relocation value size ("
                       << ref.size() << ").";
            return false;
        }
      }

      // Lay out and collect relocations.
      if (!LayoutBlock(block))
        return false;
      if (!AddRelocs(*block, symbol_map, &relocs))
        return false;
    }

    if (!CloseSection())
      return false;

    // Fix section header. We use section_index - 1, as the value has been
    // incremented already.
    const ImageLayout::SectionInfo& info =
        image_layout_->sections[section_index];
    if ((section->characteristics() & IMAGE_SCN_CNT_UNINITIALIZED_DATA) == 0) {
      // Normal section.
      header->PointerToRawData = section_start.value();
      header->SizeOfRawData = info.data_size;
    } else {
      // BSS section. The COFF specifications state that SizeOfRawData
      // should be set to zero, but MSVC sets it to the size of the
      // uninitialized data.
      header->SizeOfRawData = info.size;
    }
    DCHECK_EQ(header->Characteristics, info.characteristics);

    // Lay out relocations, if necessary.
    if (relocs.size() != 0) {
      size_t relocs_size = relocs.size() * sizeof(relocs[0]);
      BlockGraph::Block* relocs_block =
          image_layout_->blocks.graph()->AddBlock(BlockGraph::DATA_BLOCK,
                                                  relocs_size,
                                                  kNewRelocsBlockName);
      DCHECK(relocs_block != NULL);
      relocs_block->set_attribute(BlockGraph::COFF_RELOC_DATA);
      if (relocs_block->CopyData(relocs_size, &relocs[0]) == NULL)
        return false;

      // Fix relocation information in header.
      header->PointerToRelocations = cursor_.value();
      header->NumberOfRelocations = relocs.size();

      // Lay out the relocation block outside of the section.
      if (!LayoutBlockImpl(relocs_block))
        return false;
    }

    ++section_index;
  }

  if (section_index < file_header->NumberOfSections) {
    LOG(ERROR) << "Missing sections from ordered block graph ("
               << file_header->NumberOfSections << " expected vs "
               << section_index << " found).";
    return false;
  }

  return true;
}

bool CoffImageLayoutBuilder::LayoutSymbolAndStringTables(
    const OrderedBlockGraph& ordered_graph) {
  DCHECK(headers_block_ != NULL);
  DCHECK(symbols_block_ != NULL);
  DCHECK(strings_block_ != NULL);

  TypedBlock<IMAGE_FILE_HEADER> file_header;
  if (!file_header.Init(0, headers_block_)) {
    LOG(ERROR) << "Unable to cast file header.";
    return false;
  }

  TypedBlock<IMAGE_SYMBOL> symbols;
  if (!symbols.Init(0, symbols_block_)) {
    LOG(ERROR) << "Unable to cast symbol table.";
    return false;
  }

  file_header->PointerToSymbolTable = cursor_.value();
  file_header->NumberOfSymbols = symbols.ElementCount();

  // Lay out the blocks.
  if (!LayoutBlockImpl(symbols_block_))
    return false;
  if (!LayoutBlockImpl(strings_block_))
    return false;

  // Compute the section index map, used to remap symbol section references.
  SectionIndexMap section_index_map;
  OrderedBlockGraph::SectionList::const_iterator section_it =
      ordered_graph.ordered_sections().begin();
  OrderedBlockGraph::SectionList::const_iterator section_end =
      ordered_graph.ordered_sections().end();
  size_t section_index = 0;
  for (; section_it != section_end; ++section_it) {
    BlockGraph::Section* section = (*section_it)->section();
    DCHECK(section != NULL);
    section_index_map.insert(std::make_pair(section->id(), section_index));
    ++section_index;
  }

  // Fix references.
  BlockGraph::Block::ReferenceMap::const_iterator it =
      symbols_block_->references().begin();
  for (; it != symbols_block_->references().end(); ++it) {
    size_t symbol_index = it->first / sizeof(IMAGE_SYMBOL);
    DCHECK_GT(file_header->NumberOfSymbols, symbol_index);

    switch (it->second.type()) {
      case BlockGraph::SECTION_REF: {
        DCHECK_EQ(2u, it->second.size());
        TypedBlock<uint16> section_number;
        if (!section_number.Init(it->first, symbols_block_)) {
          LOG(ERROR) << "Unable to cast reference.";
          return false;
        }

        SectionIndexMap::iterator section_index_it =
            section_index_map.find(it->second.referenced()->section());
        if (section_index_it == section_index_map.end()) {
          LOG(ERROR) << "Reference to unmapped section.";
          return false;
        }
        *section_number = section_index_it->second + 1;
        DCHECK_EQ(*section_number, symbols[symbol_index].SectionNumber);
        break;
      }

      case BlockGraph::SECTION_OFFSET_REF: {
        DCHECK_EQ(4u, it->second.size());
        TypedBlock<uint32> value;
        if (!value.Init(it->first, symbols_block_)) {
          LOG(ERROR) << "Unable to cast reference.";
          return false;
        }

        *value = it->second.offset();
        DCHECK_EQ(static_cast<size_t>(it->second.offset()),
                  symbols[symbol_index].Value);
        break;
      }

      default:
        LOG(ERROR) << "Unexpected reference type " << it->second.type()
                   << " in symbol table.";
        return false;
    }
  }

  return true;
}

bool CoffImageLayoutBuilder::RemoveOldRelocBlocks() {
  // Find blocks not mapped in the image layout, and ensure they are (old)
  // COFF relocation blocks; if not, that is an error.
  //
  // Relocation blocks found during this pass do not include new relocation
  // blocks (which must have been inserted into the image layout).
  BlockGraph::BlockMap& blocks =
      image_layout_->blocks.graph()->blocks_mutable();
  std::vector<BlockGraph::Block*> blocks_to_remove;

  BlockGraph::BlockMap::iterator it = blocks.begin();
  for (; it != blocks.end(); ++it) {
    if (!image_layout_->blocks.ContainsBlock(&it->second)) {
      if ((it->second.attributes() & BlockGraph::COFF_RELOC_DATA) == 0) {
        LOG(ERROR) << "Found unmapped block \"" << it->second.name()
                   << "\" in block graph; "
                   << "originally mapped at address " << it->second.addr()
                   << ".";
        return false;
      }
      blocks_to_remove.push_back(&it->second);
    }
  }

  // Remove old relocation blocks from the block graph.
  std::vector<BlockGraph::Block*>::iterator it_to_remove =
      blocks_to_remove.begin();
  for (; it_to_remove != blocks_to_remove.end(); ++it_to_remove) {
    if (!image_layout_->blocks.graph()->RemoveBlock(*it_to_remove)) {
      LOG(ERROR) << "Unable to remove block with ID " << (*it_to_remove)->id()
                 << " from the block graph.";
    }
  }

  DCHECK_EQ(image_layout_->blocks.size(),
            image_layout_->blocks.graph()->blocks().size());

  return true;
}

}  // namespace pe
