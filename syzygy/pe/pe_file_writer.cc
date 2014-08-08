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

#include "syzygy/pe/pe_file_writer.h"

#include <windows.h>
#include <winnt.h>
#include <imagehlp.h>  // NOLINT

#include "base/file_util.h"
#include "base/logging.h"
#include "base/win/scoped_handle.h"
#include "syzygy/common/buffer_parser.h"
#include "syzygy/common/com_utils.h"
#include "syzygy/pe/pe_utils.h"

namespace pe {

using block_graph::BlockGraph;
using common::BinaryBufferParser;
using core::AbsoluteAddress;
using core::FileOffsetAddress;
using core::RelativeAddress;
using pe::ImageLayout;

namespace {

template <class Type>
bool UpdateReference(size_t start, Type new_value, std::vector<uint8>* data) {
  BinaryBufferParser parser(&data->at(0), data->size());

  Type* ref_ptr = NULL;
  if (!parser.GetAt(start, const_cast<const Type**>(&ref_ptr))) {
    LOG(ERROR) << "Reference data not in block";
    return false;
  }
  *ref_ptr = new_value;

  return true;
}

// Returns the type of padding byte to use for a given section. Int3s will be
// used for executable sections, nulls for everything else.
uint8 GetSectionPaddingByte(const ImageLayout& image_layout,
                            size_t section_index) {
  const uint8 kZero = 0;
  const uint8 kInt3 = 0xCC;

  if (section_index == BlockGraph::kInvalidSectionId)
    return kZero;
  DCHECK_GT(image_layout.sections.size(), section_index);

  const ImageLayout::SectionInfo& section_info =
      image_layout.sections[section_index];
  bool is_executable =
      (section_info.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
  if (is_executable)
    return kInt3;
  return kZero;
}

// Returns the length of explicitly initialized data in a block.
// TODO(chrisha): Move this to block_util and unittest it.
size_t GetBlockInitializedDataSize(const BlockGraph::Block* block) {
  DCHECK(block != NULL);

  // All references contain initialized data so must be explicitly written.
  // Use the position and the size of the last offset as the initialized length.
  size_t length = 0;
  if (!block->references().empty()) {
    BlockGraph::Block::ReferenceMap::const_reverse_iterator ref_it =
        block->references().rbegin();
    length = ref_it->first + ref_it->second.size();
  }

  // Otherwise, we use the block data size.
  // TODO(chrisha): If we really wanted to, we could strip off trailing zeros
  //     from the block data, but that's maybe a little overkill.
  length = std::max(length, block->data_size());

  return length;
}

size_t GetSectionOffset(const ImageLayout& image_layout,
                        const RelativeAddress rel_addr,
                        size_t section_index) {
  if (section_index == BlockGraph::kInvalidSectionId)
    return rel_addr.value();

  DCHECK_GT(image_layout.sections.size(), section_index);
  const ImageLayout::SectionInfo& section_info =
      image_layout.sections[section_index];

  DCHECK_GE(rel_addr, section_info.addr);
  return rel_addr - section_info.addr;
}

}  // namespace

PEFileWriter::PEFileWriter(const ImageLayout& image_layout)
    : image_layout_(image_layout), nt_headers_(NULL) {
}

bool PEFileWriter::WriteImage(const base::FilePath& path) {
  // Start by attempting to open the destination file.
  base::ScopedFILE file(base::OpenFile(path, "wb"));
  if (file.get() == NULL) {
    LOG(ERROR) << "Unable to open " << path.value();
    return false;
  }

  if (!ValidateHeaders())
    return false;

  DCHECK(nt_headers_ != NULL);

  bool success = CalculateSectionRanges();
  if (success)
    success = WriteBlocks(file.get());

  nt_headers_ = NULL;

  // Close the file.
  file.reset();

  if (success)
    success = UpdateFileChecksum(path);

  return success;
}

bool PEFileWriter::UpdateFileChecksum(const base::FilePath& path) {
  // Open the image file for exclusive write.
  base::win::ScopedHandle image_handle(
      ::CreateFile(path.value().c_str(), GENERIC_READ | GENERIC_WRITE, 0,
                   NULL, OPEN_EXISTING, 0, NULL));

  if (!image_handle.IsValid()) {
    LOG(ERROR) << "Failed to open file " << path.value();
    return false;
  }

  size_t file_size = ::GetFileSize(image_handle.Get(), NULL);

  // Create an anonymous read/write mapping on the file.
  base::win::ScopedHandle image_mapping(::CreateFileMapping(image_handle.Get(),
                                                            NULL,
                                                            PAGE_READWRITE,
                                                            0,
                                                            0,
                                                            NULL));
  // Map the entire file read/write to memory.
  void* image_ptr = NULL;

  if (image_mapping.IsValid()) {
    image_ptr = ::MapViewOfFile(image_mapping.Get(),
                                FILE_MAP_WRITE,
                                0,
                                0,
                                file_size);
  }

  if (image_ptr == NULL) {
    LOG(ERROR) << "Failed to create image mapping.";
    return false;
  }

  // Calculate the image checksum.
  DWORD original_checksum = 0;
  DWORD new_checksum = 0;
  IMAGE_NT_HEADERS* nt_headers = ::CheckSumMappedFile(image_ptr,
                                                      file_size,
                                                      &original_checksum,
                                                      &new_checksum);

  if (nt_headers == NULL) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "CheckSumMappedFile failed: " << common::LogWe(error);
  }

  // On success, we write the checksum back to the file header.
  if (nt_headers != NULL) {
    nt_headers->OptionalHeader.CheckSum = new_checksum;
  }
  CHECK(::UnmapViewOfFile(image_ptr));

  return nt_headers != NULL;
}

bool PEFileWriter::ValidateHeaders() {
  DCHECK(nt_headers_ == NULL);

  // Get the DOS header block.
  BlockGraph::Block* dos_header_block =
      image_layout_.blocks.GetBlockByAddress(RelativeAddress(0));
  if (dos_header_block == NULL) {
    LOG(ERROR) << "No DOS header in image.";
    return false;
  }
  if (!IsValidDosHeaderBlock(dos_header_block)) {
    LOG(ERROR) << "Invalid DOS header in image.";
    return false;
  }
  BlockGraph::Block* nt_headers_block =
      GetNtHeadersBlockFromDosHeaderBlock(dos_header_block);
  DCHECK(nt_headers_block != NULL);

  const IMAGE_NT_HEADERS* nt_headers =
      reinterpret_cast<const IMAGE_NT_HEADERS*>(nt_headers_block->data());
  DCHECK(nt_headers != NULL);

  nt_headers_ = nt_headers;

  return true;
}

bool PEFileWriter::CalculateSectionRanges() {
  DCHECK(nt_headers_ != NULL);
  DCHECK_EQ(0u, section_file_range_map_.size());
  DCHECK_EQ(0u, section_index_space_.size());

  size_t section_alignment = nt_headers_->OptionalHeader.SectionAlignment;
  size_t file_alignment = nt_headers_->OptionalHeader.FileAlignment;

  // Keep track of the end of each section, both in memory and on disk.
  RelativeAddress previous_section_end =
      RelativeAddress(nt_headers_->OptionalHeader.SizeOfHeaders).AlignUp(
          section_alignment);
  FileOffsetAddress previous_section_file_end =
      FileOffsetAddress(nt_headers_->OptionalHeader.SizeOfHeaders).AlignUp(
          file_alignment);

  // This first range is for the header and doesn't correspond to any section.
  CHECK(section_file_range_map_.insert(
      std::make_pair(BlockGraph::kInvalidSectionId,
                     FileRange(FileOffsetAddress(0),
                               previous_section_file_end.value()))).second);

  // Validate the number of sections in the headers.
  if (nt_headers_->FileHeader.NumberOfSections !=
          image_layout_.sections.size()) {
    LOG(ERROR) << "NT headers section count mismatch.";
    return false;
  }

  // The remainder of the mappings are for the sections. While we run through
  // and calculate the section ranges, we also make sure they're sane by
  // checking that:
  //  - they're arranged sequentially,
  //  - there are no gaps between sections,
  //  - that they don't run into one another.

  IMAGE_SECTION_HEADER* section_header = IMAGE_FIRST_SECTION(nt_headers_);
  for (size_t i = 0; i < image_layout_.sections.size(); ++i, ++section_header) {
    const ImageLayout::SectionInfo& section = image_layout_.sections[i];
    RelativeAddress section_start(section.addr);
    size_t section_size = section.size;

    // Calculate the file offset start for this section.
    FileOffsetAddress section_file_start =
        previous_section_file_end.AlignUp(file_alignment);
    size_t section_file_size = section.data_size;

    // Validate that the section doesn't overlap in memory or on disk.
    if (section_start < previous_section_end ||
        section_file_start < previous_section_file_end) {
      LOG(ERROR) << "Section " << section.name <<
          " runs into previous section (or header).";
      return false;
    }

    // Validate the alignment of the section start addresses in memory and on
    // disk.
    if ((section_start.value() % section_alignment) != 0 ||
        (section_file_start.value() % file_alignment) != 0) {
      LOG(ERROR) << "Section " << section.name <<
          " has incorrect alignment.";
      return false;
    }

    // Make sure there are no unexpected gaps between sections (the packing
    // should be as tight as possible).
    if ((section_start - previous_section_end >
            static_cast<ptrdiff_t>(section_alignment)) ||
        (section_file_start - previous_section_file_end >
            static_cast<ptrdiff_t>(file_alignment))) {
      LOG(ERROR) << "Section " << section.name <<
          " leaves a gap from previous section.";
      return false;
    }

    // Ok, it all passes inspection so far. Record the mapping.
    FileRange section_file_range(section_file_start, section_file_size);
    CHECK(section_file_range_map_.insert(
        std::make_pair(i, section_file_range)).second);

    CHECK(section_index_space_.Insert(
        SectionIndexSpace::Range(section_start, section_size), i, NULL));

    // Validate that the NT section headers match what we calculate.
    if (section_header->VirtualAddress != section_start.value() ||
        section_header->SizeOfRawData != section_file_size ||
        section_header->PointerToRawData != section_file_start.value() ||
        section_header->Misc.VirtualSize != section_size) {
      LOG(ERROR) << "NT section headers are inconsistent with image layout.";
      return false;
    }

    previous_section_end = section_start + section_size;
    previous_section_file_end = section_file_start + section_file_size;
  }

  return true;
}

bool PEFileWriter::WriteBlocks(FILE* file) {
  DCHECK(file != NULL);

  AbsoluteAddress image_base(nt_headers_->OptionalHeader.ImageBase);

  // Create the output buffer, reserving enough room for the whole file.
  DCHECK(!image_layout_.sections.empty());
  size_t last_section_index = image_layout_.sections.size() - 1;
  size_t image_size = section_file_range_map_[last_section_index].end().value();
  std::vector<uint8> buffer;
  buffer.reserve(image_size);

  // Iterate through all blocks in the address space writing them as we go.
  BlockGraph::AddressSpace::RangeMap::const_iterator block_it(
      image_layout_.blocks.address_space_impl().ranges().begin());
  BlockGraph::AddressSpace::RangeMap::const_iterator block_end(
      image_layout_.blocks.address_space_impl().ranges().end());

  // Write all of the blocks. We take care of writing the padding at the
  // end of each section. Note that the section index is not the same thing as
  // the section_id stored in the block; the section IDs are relative to the
  // section data stored in the block-graph, not the ordered section infos
  // stored in the image layout.
  BlockGraph::SectionId section_id = BlockGraph::kInvalidSectionId;
  size_t section_index = BlockGraph::kInvalidSectionId;
  for (; block_it != block_end; ++block_it) {
    BlockGraph::Block* block = const_cast<BlockGraph::Block*>(block_it->second);

    // If we're jumping to a new section output the necessary padding.
    if (block->section() != section_id) {
      FlushSection(section_index, &buffer);
      section_id = block->section();
      section_index++;
      DCHECK_GT(image_layout_.sections.size(), section_index);
    }

    if (!WriteOneBlock(image_base, section_index, block, &buffer)) {
      LOG(ERROR) << "Failed to write block \"" << block->name() << "\".";
      return false;
    }
  }

  FlushSection(last_section_index, &buffer);
  DCHECK_EQ(image_size, buffer.size());

  // Write the whole image to disk in one go.
  if (::fwrite(&buffer[0], sizeof(buffer[0]), buffer.size(), file) !=
          buffer.size()) {
    LOG(ERROR) << "Failed to write image to file.";
    return false;
  }

  return true;
}

void PEFileWriter::FlushSection(size_t section_index,
                                std::vector<uint8>* buffer) {
  DCHECK(buffer != NULL);

  size_t section_file_end =
      section_file_range_map_[section_index].end().value();

  // We've already sanity checked this in CalculateSectionFileRanges, so this
  // should be true.
  DCHECK_GE(section_file_end, buffer->size());
  if (section_file_end == buffer->size())
    return;

  uint8 padding_byte = GetSectionPaddingByte(image_layout_, section_index);
  buffer->resize(section_file_end, padding_byte);

  return;
}

bool PEFileWriter::WriteOneBlock(AbsoluteAddress image_base,
                                 size_t section_index,
                                 const BlockGraph::Block* block,
                                 std::vector<uint8>* buffer) {
  // This function walks through the data referred by the input block, and
  // patches it to reflect the addresses and offsets of the blocks
  // referenced before writing the block's data to the file.
  DCHECK(block != NULL);
  DCHECK(buffer != NULL);

  RelativeAddress addr;
  if (!image_layout_.blocks.GetAddressOf(block, &addr)) {
    LOG(ERROR) << "All blocks must have an address.";
    return false;
  }

  // Get the start address of the section containing this block as well as the
  // padding byte we need to use.
  RelativeAddress section_start(0);
  RelativeAddress section_end(image_layout_.sections[0].addr);
  uint8 padding_byte = GetSectionPaddingByte(image_layout_, section_index);
  if (section_index != BlockGraph::kInvalidSectionId) {
    const ImageLayout::SectionInfo& section_info =
        image_layout_.sections[section_index];
    section_start = RelativeAddress(section_info.addr);
    section_end = section_start + section_info.size;
  }

  const FileRange& section_file_range = section_file_range_map_[section_index];

  // The block should lie entirely within the section.
  if (addr < section_start || addr + block->size() > section_end) {
    LOG(ERROR) << "Block lies outside of section.";
    return false;
  }

  // Calculate the offset from the start of the section to
  // the start of the block, and the block's file offset.
  BlockGraph::Offset section_offs = addr - section_start;
  FileOffsetAddress file_offs = section_file_range.start() + section_offs;

  // We shouldn't have written anything to the spot where the block belongs.
  // This is only a DCHECK because the address space of the image layout and
  // the consistency of the sections guarantees this for us.
  DCHECK_LE(buffer->size(), file_offs.value());

  size_t inited_data_size = GetBlockInitializedDataSize(block);

  // If this block is entirely in the virtual portion of the section, skip it.
  if (file_offs >= section_file_range.end()) {
    if (inited_data_size != 0) {
      LOG(ERROR) << "Block contains explicit data or references but is in "
                 << "virtual portion of section.";
      return false;
    }

    return true;
  }

  // The initialized portion of data for this block must lie entirely within the
  // initialized data for this section (this includes references to be filled in
  // and the explicit block data).
  if (file_offs + inited_data_size > section_file_range.end()) {
    LOG(ERROR) << "Initialized portion of block data lies outside of section.";
    return false;
  }

  // Add any necessary padding to get us to the block offset.
  if (buffer->size() < file_offs.value())
    buffer->resize(file_offs.value(), padding_byte);

  // Copy the block data into the buffer.
  buffer->insert(buffer->end(),
                 block->data(),
                 block->data() + block->data_size());

  // We now want to append zeros for the implicit portion of the block data.
  size_t trailing_zeros = block->size() - block->data_size();
  if (trailing_zeros > 0) {
    // It is possible for a block to be laid out at the end of a section such
    // that part of its data lies within the virtual portion of the section.
    // Since padding between blocks can be non-zero we explicitly write out any
    // trailing zeros here. So use the section size to determine how much we are
    // supposed to write.
    FileOffsetAddress block_file_end = file_offs + block->size();
    if (block_file_end > section_file_range.end()) {
      size_t implicit_trailing_zeros =
          block_file_end - section_file_range.end();
      DCHECK_LE(implicit_trailing_zeros, trailing_zeros);
      trailing_zeros -= implicit_trailing_zeros;
    }

    // Write the implicit trailing zeros.
    buffer->insert(buffer->end(), trailing_zeros, 0);
  }

  // Patch up all the references.
  BlockGraph::Block::ReferenceMap::const_iterator ref_it(
      block->references().begin());
  BlockGraph::Block::ReferenceMap::const_iterator ref_end(
      block->references().end());
  for (; ref_it != ref_end; ++ref_it) {
    BlockGraph::Offset start = ref_it->first;
    const BlockGraph::Reference& ref = ref_it->second;
    BlockGraph::Block* dst = ref.referenced();

    RelativeAddress src_addr(addr + start);
    RelativeAddress dst_addr;
    if (!image_layout_.blocks.GetAddressOf(dst, &dst_addr)) {
      LOG(ERROR) << "All blocks must have an address.";
      return false;
    }
    dst_addr += ref.offset();

    // Compute the new value of the reference.
    uint32 value = 0;
    switch (ref.type()) {
      case BlockGraph::ABSOLUTE_REF:
        value = image_base.value() + dst_addr.value();
        break;

      case BlockGraph::PC_RELATIVE_REF:
        value = dst_addr - (src_addr + ref.size());
        break;

      case BlockGraph::RELATIVE_REF:
        value = dst_addr.value();
        break;

      case BlockGraph::FILE_OFFSET_REF: {
        // Get the index of the section containing the destination block.
        SectionIndexSpace::const_iterator section_index_space_it =
            section_index_space_.FindContaining(
                SectionIndexSpace::Range(dst_addr, 1));
        DCHECK(section_index_space_it != section_index_space_.end());
        size_t dst_section_index = section_index_space_it->second;

        // Get the offset of the block in its section, as well as the range of
        // the section on disk. Validate that the referred location is
        // actually directly represented on disk (not in implicit virtual data).
        const FileRange& file_range =
            section_file_range_map_[dst_section_index];
        size_t section_offset = GetSectionOffset(image_layout_,
                                                 dst_addr,
                                                 dst_section_index);
        if (section_offset >= file_range.size()) {
          LOG(ERROR) << "Encountered file offset reference that refers to "
                     << "a location outside of the explicit section data.";
          return false;
        }

        // Finally, calculate the value of the file offset.
        value = file_range.start().value() + section_offset;
        break;
      }

      default:
        LOG(ERROR) << "Impossible reference type";
        return false;
    }

    // Now store the new value.
    BlockGraph::Offset ref_offset = file_offs.value() + start;
    switch (ref.size()) {
      case sizeof(uint8):
        if (!UpdateReference(ref_offset, static_cast<uint8>(value), buffer))
          return false;
        break;

      case sizeof(uint16):
        if (!UpdateReference(ref_offset, static_cast<uint16>(value), buffer))
          return false;
        break;

      case sizeof(uint32):
        if (!UpdateReference(ref_offset, static_cast<uint32>(value), buffer))
          return false;
        break;

      default:
        LOG(ERROR) << "Unsupported reference size.";
        return false;
    }
  }

  return true;
}

}  // namespace pe
