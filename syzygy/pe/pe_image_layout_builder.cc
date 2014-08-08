// Copyright 2012 Google Inc. All Rights Reserved.
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

#include "syzygy/pe/pe_image_layout_builder.h"

#include <algorithm>
#include <ctime>

#include "base/strings/string_util.h"
#include "syzygy/block_graph/typed_block.h"
#include "syzygy/common/align.h"
#include "syzygy/pe/pe_utils.h"

namespace {

using block_graph::BlockGraph;
using block_graph::ConstTypedBlock;
using block_graph::TypedBlock;
using core::RelativeAddress;

typedef std::vector<uint8> ByteVector;

// A utility class to help with formatting the relocations section.
class RelocWriter {
 public:
  RelocWriter() : curr_page_(0), curr_header_offset_(0) {
  }

  void WriteReloc(RelativeAddress addr) {
    DWORD page = PageFromAddr(addr);

    // Initialization case, open the first page.
    if (buf_.size() == 0)
      OpenPage(addr);

    // Close the current page, and open the next if we're outside it.
    if (page != curr_page_) {
      ClosePage();
      OpenPage(addr);
    }

    DCHECK_EQ(curr_page_, page);
    WORD type_offset = (IMAGE_REL_BASED_HIGHLOW << 12) | OffsetFromAddr(addr);
    Append(&type_offset, sizeof(type_offset));
  }

  void Close(ByteVector* relocs_out) {
    DCHECK(relocs_out != NULL);

    // Close the page in progress.
    if (buf_.size() != 0)
      ClosePage();

    relocs_out->swap(buf_);
  }

 private:
  static const DWORD kPageMask = 0x00000FFF;
  DWORD PageFromAddr(RelativeAddress addr) {
    return addr.value() & ~kPageMask;
  }

  WORD OffsetFromAddr(RelativeAddress addr) {
    return static_cast<WORD>(addr.value() & kPageMask);
  }

  void ClosePage() {
    size_t block_len = buf_.size() - curr_header_offset_;
    if (block_len % 4 != 0) {
      DCHECK_EQ(0U, block_len % 2);
      WORD filler = IMAGE_REL_BASED_ABSOLUTE << 12;
      Append(&filler, sizeof(filler));
      block_len += sizeof(filler);
    }
    DCHECK_EQ(0U, block_len % 4);

    IMAGE_BASE_RELOCATION* header =
        reinterpret_cast<IMAGE_BASE_RELOCATION*>(&buf_.at(curr_header_offset_));

    header->SizeOfBlock = block_len;
  }

  void OpenPage(RelativeAddress addr) {
    curr_page_ = PageFromAddr(addr);
    curr_header_offset_ = buf_.size();

    IMAGE_BASE_RELOCATION header = { curr_page_, sizeof(header) };
    Append(&header, sizeof(header));
  }

  void Append(const void* data, size_t size) {
    const uint8* buf = reinterpret_cast<const uint8*>(data);
    buf_.insert(buf_.end(), buf, buf + size);
  }

  // The buffer where we write the data.
  ByteVector buf_;

  // The current page our header is for.
  DWORD curr_page_;

  // The offset of the last IMAGE_BASE_RELOCATION header we wrote.
  size_t curr_header_offset_;
};

// Returns true iff ref is a valid reference in addr_space.
bool IsValidReference(const BlockGraph::AddressSpace& addr_space,
                      const BlockGraph::Reference& ref) {
  // Check that there is a referenced block.
  if (ref.referenced() == NULL)
    return false;

  // Check that the block is in the image.
  RelativeAddress addr;
  if (!addr_space.GetAddressOf(ref.referenced(), &addr))
    return false;

  return true;
}

// Functor to order references by the address of their referred block.
class RefAddrLess {
 public:
  explicit RefAddrLess(const BlockGraph::AddressSpace* addr_space)
      : addr_space_(addr_space),
        failed_(false) {
    DCHECK(addr_space_ != NULL);
  }

  bool operator()(const BlockGraph::Reference& lhs,
                  const BlockGraph::Reference& rhs) {
    RelativeAddress lhs_addr;
    RelativeAddress rhs_addr;
    if (!addr_space_->GetAddressOf(lhs.referenced(), &lhs_addr) ||
        !addr_space_->GetAddressOf(rhs.referenced(), &rhs_addr)) {
      failed_ = true;
    }
    return lhs_addr < rhs_addr;
  }

  bool failed() const {
    return failed_;
  }

 private:
  const BlockGraph::AddressSpace* const addr_space_;
  bool failed_;
};

}  // namespace

namespace pe {

PEImageLayoutBuilder::PEImageLayoutBuilder(ImageLayout* image_layout)
    : PECoffImageLayoutBuilder(image_layout),
      dos_header_block_(NULL),
      nt_headers_block_(NULL) {
}

bool PEImageLayoutBuilder::LayoutImageHeaders(
    BlockGraph::Block* dos_header_block) {
  DCHECK(dos_header_block != NULL);
  DCHECK(dos_header_block_ == NULL);
  DCHECK_EQ(0u, image_layout_->blocks.address_space_impl().size());
  DCHECK_EQ(0u, image_layout_->sections.size());

  if (!IsValidDosHeaderBlock(dos_header_block)) {
    LOG(ERROR) << "Invalid DOS header.";
    return false;
  }

  BlockGraph::Block* nt_headers_block =
      GetNtHeadersBlockFromDosHeaderBlock(dos_header_block);
  if (nt_headers_block == NULL) {
    LOG(ERROR) << "Invalid NT headers.";
    return false;
  }

  // We keep these around for later.
  dos_header_block_ = dos_header_block;
  nt_headers_block_ = nt_headers_block;

  // Initialize alignments.
  ConstTypedBlock<IMAGE_NT_HEADERS> nt_headers;
  if (!nt_headers.Init(0, nt_headers_block)) {
    LOG(ERROR) << "Unable to cast NT headers.";
    return false;
  }
  PECoffImageLayoutBuilder::Init(nt_headers->OptionalHeader.SectionAlignment,
                                 nt_headers->OptionalHeader.FileAlignment);

  // Layout the two blocks in the image layout.
  if (!LayoutBlockImpl(dos_header_block))
    return false;
  if (!LayoutBlockImpl(nt_headers_block))
    return false;

  return true;
}

bool PEImageLayoutBuilder::LayoutOrderedBlockGraph(
    const OrderedBlockGraph& obg) {
  // The ordered block graph has to refer to the same underlying block graph,
  // and the headers must be laid out. However, nothing else should yet have
  // been laid out.
  DCHECK_EQ(obg.block_graph(), image_layout_->blocks.graph());
  DCHECK(nt_headers_block_ != NULL);
  DCHECK_EQ(2u, image_layout_->blocks.address_space_impl().size());
  DCHECK_EQ(0u, image_layout_->sections.size());

  OrderedBlockGraph::SectionList::const_iterator section_it =
      obg.ordered_sections().begin();
  OrderedBlockGraph::SectionList::const_iterator section_end =
      obg.ordered_sections().end();

  // Iterate through the sections.
  for (; section_it != section_end; ++section_it) {
    BlockGraph::Section* section = (*section_it)->section();
    DCHECK(section != NULL);

    // Stop iterating when we see the relocs.
    if (section->name() == kRelocSectionName) {
      ++section_it;
      break;
    }

    if (!OpenSection(*section))
      return false;

    // Iterate over the blocks.
    OrderedBlockGraph::BlockList::const_iterator block_it =
        (*section_it)->ordered_blocks().begin();
    OrderedBlockGraph::BlockList::const_iterator block_end =
        (*section_it)->ordered_blocks().end();
    for (; block_it != block_end; ++block_it) {
      BlockGraph::Block* block = *block_it;
      if (!LayoutBlock(block))
        return false;
    }

    if (!CloseSection())
      return false;
  }

  // There should be nothing beyond the relocs, if it was present.
  if (section_it != section_end) {
    LOG(ERROR) << kRelocSectionName << " not the last section.";
  }

  return true;
}

bool PEImageLayoutBuilder::Finalize() {
  if (!CreateRelocsSection())
    return false;

  if (!ReconcileBlockGraphAndImageLayout())
    return false;

  if (!SortSafeSehTable())
    return false;

  if (!FinalizeHeaders())
    return false;

  return true;
}

bool PEImageLayoutBuilder::SortSafeSehTable() {
  DCHECK(nt_headers_block_ != NULL);

  TypedBlock<IMAGE_NT_HEADERS> nt_headers;
  if (!nt_headers.Init(0, nt_headers_block_)) {
    LOG(ERROR) << "Unable to cast NT headers.";
    return false;
  }

  // If there is no load config directory then we can exit early.
  IMAGE_DATA_DIRECTORY* load_config =
      nt_headers->OptionalHeader.DataDirectory +
          IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG;
  if (load_config->VirtualAddress == 0 && load_config->Size == 0 &&
      !nt_headers.HasReference(load_config->VirtualAddress)) {
    return true;
  }

  TypedBlock<IMAGE_LOAD_CONFIG_DIRECTORY> load_config_directory;
  if (!nt_headers.Dereference(load_config->VirtualAddress,
                              &load_config_directory)) {
      LOG(ERROR) << "Failed to dereference Load Config Directory.";
    return false;
  }

  TypedBlock<DWORD> safe_seh_table;
  if (!load_config_directory.Dereference(
          load_config_directory->SEHandlerTable, &safe_seh_table)) {
    // There's no SEHandlerTable.
    return true;
  }

  // Grab the references to the safe SEH code blocks.
  typedef BlockGraph::Block::ReferenceMap ReferenceMap;
  const ReferenceMap& orig_references = safe_seh_table.block()->references();

  // We should have as many references as there are handlers and we expect the
  // safe seh block to be zero offset and exactly the right size.
  size_t num_references = orig_references.size();
  if (num_references != load_config_directory->SEHandlerCount ||
      safe_seh_table.offset() != 0 ||
      safe_seh_table.block()->size() != num_references * sizeof(DWORD)) {
    LOG(ERROR) << "Safe SEH Table block does not conform to expectations.";
    return false;
  }

  // Create a secondary vector large enough to hold the sorted references.
  typedef std::vector<BlockGraph::Reference> ReferenceVector;
  ReferenceVector sorted_references;
  sorted_references.reserve(orig_references.size());

  // Copy the references into a secondary vector.
  for (ReferenceMap::const_iterator iter = orig_references.begin();
       iter != orig_references.end();
       ++iter) {
    sorted_references.push_back(iter->second);
  }

  // Sort the secondary vector in the order their referred blocks appear
  // in the image layout.
  RefAddrLess comparator(&image_layout_->blocks);
  std::sort(sorted_references.begin(), sorted_references.end(), comparator);
  if (comparator.failed()) {
    LOG(ERROR) << "One or more exception handler blocks is invalid.";
    return false;
  }

  // Reset the references in the Safe SEH Table in sorted order.
  size_t offset = 0;
  for (ReferenceVector::iterator iter = sorted_references.begin();
       iter != sorted_references.end();
       offset += sizeof(DWORD), ++iter) {
    DCHECK(iter->size() == sizeof(DWORD));
    DCHECK(iter->referenced()->type() == BlockGraph::CODE_BLOCK);
    safe_seh_table.block()->SetReference(offset, *iter);
  }

  return true;
}

bool PEImageLayoutBuilder::CreateRelocsSection() {
  RelocWriter writer;

  DCHECK(nt_headers_block_ != NULL);
  TypedBlock<IMAGE_NT_HEADERS> nt_headers;
  if (!nt_headers.Init(0, nt_headers_block_)) {
    LOG(ERROR) << "Unable to cast NT headers.";
    return false;
  }

  // Get the existing relocs block so we can reuse it.
  TypedBlock<unsigned char> reloc_data;
  if (!nt_headers.Dereference(
      nt_headers->OptionalHeader.DataDirectory[
          IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress, &reloc_data)) {
    LOG(ERROR) << "Unable to dereference relocs block.";
    return false;
  }
  BlockGraph::Block* relocs_block = reloc_data.block();
  CHECK_EQ(0, reloc_data.offset());

  // Iterate over all blocks in the address space, in the order of increasing
  // addresses.
  BlockGraph::AddressSpace::RangeMap::const_iterator it(
      image_layout_->blocks.address_space_impl().ranges().begin());
  BlockGraph::AddressSpace::RangeMap::const_iterator end(
      image_layout_->blocks.address_space_impl().ranges().end());

  for (; it != end; ++it) {
    const BlockGraph::Block* block = it->second;
    RelativeAddress block_addr;
    CHECK(image_layout_->blocks.GetAddressOf(block, &block_addr));

    // Iterate over all outgoing references in this block in
    // order of increasing offset.
    BlockGraph::Block::ReferenceMap::const_iterator ref_it(
        block->references().begin());
    BlockGraph::Block::ReferenceMap::const_iterator ref_end(
        block->references().end());
    for (; ref_it != ref_end; ++ref_it) {
      // Add each absolute reference to the relocs.
      if (ref_it->second.type() == BlockGraph::ABSOLUTE_REF) {
        writer.WriteReloc(block_addr + ref_it->first);
      }
    }
  }

  // Get the relocations data from the writer.
  ByteVector relocs;
  writer.Close(&relocs);

  // Update the block and the data directory.
  relocs_block->source_ranges().clear();
  relocs_block->SetData(NULL, 0);
  relocs_block->set_size(relocs.size());
  if (!relocs_block->CopyData(relocs.size(), &relocs.at(0))) {
    LOG(ERROR) << "Unable to copy relocs data.";
    return false;
  }
  nt_headers->OptionalHeader.DataDirectory[
      IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = relocs.size();

  // Layout the relocs.
  if (!OpenSection(kRelocSectionName, kRelocCharacteristics))
    return false;
  if (!LayoutBlock(relocs_block))
    return false;
  if (!CloseSection())
    return false;

  return true;
}

bool PEImageLayoutBuilder::ReconcileBlockGraphAndImageLayout() {
  // Get the reloc section ID from the block-graph.
  BlockGraph::Section* reloc_section =
      image_layout_->blocks.graph()->FindSection(kRelocSectionName);
  if (reloc_section == NULL) {
    LOG(ERROR) << "Unable to find the reloc section in the block-graph.";
    return false;
  }
  BlockGraph::SectionId reloc_section_id = reloc_section->id();

  // Iterate over the blocks of the block-graph to see if some of them are not
  // in the image layout. If we find one we check if it belongs to the reloc
  // section, in this case we put it in a list of blocks that we should remove
  // from the graph, otherwise we return an error.
  BlockGraph::BlockMap::iterator it_block_graph =
      image_layout_->blocks.graph()->blocks_mutable().begin();
  std::list<BlockGraph::Block*> blocks_to_remove;

  for (; it_block_graph != image_layout_->blocks.graph()->blocks().end();
       ++it_block_graph) {
    // Determine if the current block exist in the image layout.
    if (!image_layout_->blocks.ContainsBlock(&it_block_graph->second)) {
      // If it doesn't we check to see if this block belongs to the reloc
      // section.
      if (it_block_graph->second.section() != reloc_section_id) {
        LOG(ERROR) << "There is a block in the block-graph that is not in the "
                   << "image layout (id=" << it_block_graph->second.id()
                   << ", name=\"" << it_block_graph->second.name() << "\", "
                   << "original address=" << it_block_graph->second.addr()
                   << ").";
        return false;
      } else {
        // The block is added to the list of blocks to remove from the graph.
        blocks_to_remove.push_back(&it_block_graph->second);
      }
    }
  }

  // The useless blocks are removed from the block-graph.
  std::list<BlockGraph::Block*>::iterator iter_blocks =
      blocks_to_remove.begin();
  for (; iter_blocks != blocks_to_remove.end(); ++iter_blocks) {
    if (!image_layout_->blocks.graph()->RemoveBlock(*iter_blocks)) {
      LOG(ERROR) << "Unable to remove block with ID " << (*iter_blocks)->id()
                 << " from the block-graph.";
    }
  }

  DCHECK_EQ(image_layout_->blocks.size(),
            image_layout_->blocks.graph()->blocks().size());

  return true;
}

bool PEImageLayoutBuilder::FinalizeHeaders() {
  // The DOS and NT headers must be set at this point.
  DCHECK(dos_header_block_ != NULL);
  DCHECK(nt_headers_block_ != NULL);

  TypedBlock<IMAGE_NT_HEADERS> nt_headers;
  if (!nt_headers.Init(0, nt_headers_block_)) {
    LOG(ERROR) << "Unable to cast NT headers.";
    return false;
  }

  TypedBlock<IMAGE_SECTION_HEADER> section_headers;
  if (!section_headers.Init(sizeof(IMAGE_NT_HEADERS), nt_headers_block_)) {
    LOG(ERROR) << "Unable to cast section headers.";
    return false;
  }

  // Ensure the section headers have the expected size. If they don't we bail,
  // as this should have been done prior to layout (PrepareHeadersTransform).
  if (section_headers.ElementCount() != image_layout_->sections.size()) {
    LOG(ERROR) << "Section header count does not agree with layout section "
               << "count (" << section_headers.ElementCount() << " != "
               << image_layout_->sections.size() << ").";
    return false;
  }

  core::FileOffsetAddress section_file_start(
      nt_headers->OptionalHeader.SizeOfHeaders);

  // Iterate through our sections to initialize the code/data fields in the NT
  // headers.
  nt_headers->OptionalHeader.SizeOfCode = 0;
  nt_headers->OptionalHeader.SizeOfInitializedData = 0;
  nt_headers->OptionalHeader.SizeOfUninitializedData = 0;
  nt_headers->OptionalHeader.BaseOfCode = 0;
  nt_headers->OptionalHeader.BaseOfData = 0;
  for (size_t i = 0; i < image_layout_->sections.size(); ++i) {
    const ImageLayout::SectionInfo& section = image_layout_->sections[i];
    IMAGE_SECTION_HEADER& hdr = section_headers[i];

    if (section.characteristics& IMAGE_SCN_CNT_CODE) {
      nt_headers->OptionalHeader.SizeOfCode += section.data_size;
      if (nt_headers->OptionalHeader.BaseOfCode == 0) {
        nt_headers->OptionalHeader.BaseOfCode = section.addr.value();
      }
    }
    if (section.characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) {
      nt_headers->OptionalHeader.SizeOfInitializedData += section.data_size;

      if (nt_headers->OptionalHeader.BaseOfData == 0)
        nt_headers->OptionalHeader.BaseOfData = section.addr.value();
    }
    if (section.characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) {
      nt_headers->OptionalHeader.SizeOfUninitializedData +=
          section.data_size;
      if (nt_headers->OptionalHeader.BaseOfData == 0)
        nt_headers->OptionalHeader.BaseOfData = section.addr.value();
    }

    // Zero the header to get rid of any old crud in it.
    memset(&hdr, 0, sizeof(hdr));

    strncpy(reinterpret_cast<char*>(hdr.Name),
            section.name.c_str(),
            arraysize(hdr.Name));
    hdr.Misc.VirtualSize = section.size;
    hdr.VirtualAddress = section.addr.value();
    hdr.SizeOfRawData = section.data_size;
    hdr.PointerToRawData = section_file_start.value();
    hdr.Characteristics = section.characteristics;

    section_file_start += section.data_size;
  }

  nt_headers->OptionalHeader.SizeOfImage =
      cursor_.AlignUp(nt_headers->OptionalHeader.SectionAlignment).value();

  return true;
}

}  // namespace pe
