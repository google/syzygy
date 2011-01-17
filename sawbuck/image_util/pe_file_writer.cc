// Copyright 2010 Google Inc.
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
#include "sawbuck/image_util/pe_file_writer.h"

#include <windows.h>
#include <winnt.h>
#include "base/file_util.h"
#include "base/logging.h"
#include "sawbuck/log_lib/buffer_parser.h"

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

}  // namespace

namespace image_util {

PEFileWriter::PEFileWriter(const BlockGraph::AddressSpace& image,
                           const PEFileParser::PEHeader& header)
    : image_(image), header_(header) {
}

bool PEFileWriter::WriteImage(const FilePath& path) {
  // Start by attempting to open the destination file.
  file_util::ScopedFILE file(file_util::OpenFile(path, "wb"));
  if (file.get() == NULL) {
    LOG(ERROR) << "Unable to open " << path.value().c_str();
    return false;
  }

  // TODO(siggi): Sanity check the headers:
  //    Check that the DOS header starts at zero and has the right length.
  //    Check that there's a DOS stub, and its length.
  //    Check that the NT headers start at the right offset.
  //    Check that the section headers start immediately after the NT headers.
  if (!InitializeSectionAddressSpace())
    return false;

  if (!WriteBlocks(file.get()))
    return false;

  return true;
}

bool PEFileWriter::InitializeSectionAddressSpace() {
  // Retrieve the NT headers.
  const IMAGE_NT_HEADERS* nt_headers = GetNTHeaders();
  if (nt_headers == NULL) {
    LOG(ERROR) << "Missing or corrupt NT headers";
    return false;
  }

  // And the section headers.
  const IMAGE_SECTION_HEADER* section_headers = GetSectionHeaders();
  if (section_headers == NULL) {
    LOG(ERROR) << "Missing or corrupt image section headers";
    return false;
  }

  // Now set up the address mappings from RVA to disk offset for the entire
  // image. The first mapping starts at zero, and coveres the header(s).
  SectionAddressSpace::Range header_range(
      RelativeAddress(0), nt_headers->OptionalHeader.SizeOfHeaders);
  section_offsets_.Insert(header_range, FileOffsetAddress(0));

  // The remainder of the mappings are for the sections. While we run through
  // and set up the section mappings, we also make sure they're sane by
  // checking that:
  //  - they're arranged sequentially,
  //  - there are no gaps between sections,
  //  - that they don't run into one another.
  RelativeAddress previous_section_end(
      header_range.start() + header_range.size());
  FileOffsetAddress previous_section_file_end(previous_section_end.value());

  for (size_t i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i) {
    RelativeAddress section_start(section_headers[i].VirtualAddress);
    size_t section_size = section_headers[i].Misc.VirtualSize;
    FileOffsetAddress section_file_start(section_headers[i].PointerToRawData);
    size_t section_file_size = section_headers[i].SizeOfRawData;

    if (section_start < previous_section_end ||
        section_file_start < previous_section_file_end) {
      LOG(ERROR) << "Section " << section_headers[i].Name <<
          " runs into previous section (or header).";
      return false;
    }

    if ((section_start.value() %
            nt_headers->OptionalHeader.SectionAlignment) != 0 ||
        (section_file_start.value() %
            nt_headers->OptionalHeader.FileAlignment) != 0) {
      LOG(ERROR) << "Section " << section_headers[i].Name <<
          " has incorrect alignment.";
      return false;
    }

    if ((section_start - previous_section_end > static_cast<ptrdiff_t>(
            nt_headers->OptionalHeader.SectionAlignment)) ||
        (section_file_start - previous_section_file_end >
            static_cast<ptrdiff_t>(nt_headers->OptionalHeader.FileAlignment))) {
      LOG(ERROR) << "Section " << section_headers[i].Name <<
          " leaves a gap from previous section.";
      return false;
    }

    // Ok, it all passes inspection so far, record the mapping.
    SectionAddressSpace::Range range(section_start, section_size);
    section_offsets_.Insert(range, section_file_start);

    previous_section_end = section_start + section_size;
    previous_section_file_end = section_file_start + section_file_size;
  }

  return true;
}

bool PEFileWriter::WriteBlocks(FILE* file) {
  // Retrieve the NT headers, we need the image base to
  // correctly rewrite absolute references.
  const IMAGE_NT_HEADERS* nt_headers = GetNTHeaders();
  if (nt_headers == NULL) {
    LOG(ERROR) << "Missing or corrupt NT headers";
    return false;
  }

  AbsoluteAddress image_base(nt_headers->OptionalHeader.ImageBase);

  // Iterate through all blocks in the address space.
  BlockGraph::AddressSpace::RangeMap::const_iterator it(
      image_.address_space_impl().ranges().begin());
  BlockGraph::AddressSpace::RangeMap::const_iterator end(
      image_.address_space_impl().ranges().end());

  for (; it != end; ++it) {
    BlockGraph::Block* block = const_cast<BlockGraph::Block*>(it->second);

    if (!WriteOneBlock(image_base, block, file)) {
      LOG(ERROR) << "Failed to write block " << block->name();
      return false;
    }
  }

  // Now round the file to the required size.
  const IMAGE_SECTION_HEADER* section_headers = GetSectionHeaders();
  if (section_headers == NULL) {
    LOG(ERROR) << "Missing or corrupt image section headers";
    return false;
  }

  const IMAGE_SECTION_HEADER* last_section =
      &section_headers[nt_headers->FileHeader.NumberOfSections - 1];
  size_t file_size =
      last_section->PointerToRawData + last_section->SizeOfRawData;
  DCHECK((file_size % nt_headers->OptionalHeader.FileAlignment) == 0);
  if (last_section->SizeOfRawData > last_section->Misc.VirtualSize) {
    if (fseek(file, file_size - 1, SEEK_SET) != 0 ||
        fwrite("\0", 1, 1, file) != 1) {
      LOG(ERROR) << "Unable to round out file size.";
      return false;
    }
  }

  return true;
}

bool PEFileWriter::WriteOneBlock(AbsoluteAddress image_base,
                                 const BlockGraph::Block* block,
                                 FILE* file) {
  // This function walks through the data referred by the input block, and
  // patches it to reflect the addresses and offsets of the blocks
  // referenced before writing the block's data to the file.
  DCHECK(block != NULL);
  DCHECK(file != NULL);

  // If the block has no data, there's nothing to write.
  if (block->data() == NULL)
    return true;

  RelativeAddress addr;
  if (!image_.GetAddressOf(block, &addr)) {
    LOG(ERROR) << "All blocks must have an address.";
    return false;
  }

  // Find the section that contains this block.
  SectionAddressSpace::RangeMap::const_iterator it(
      section_offsets_.FindContaining(
          SectionAddressSpace::Range(addr, block->data_size())));
  if (it == section_offsets_.ranges().end()) {
    LOG(ERROR) << "Block outside defined sections at: " << addr;
    return false;
  }

  // Calculate the offset from the start of the section to
  // the start of the block, and the block's file offset.
  BlockGraph::Offset offs = addr - it->first.start();
  DCHECK(offs >= 0);
  FileOffsetAddress file_offs = it->second + offs;

  // Copy the block data.
  std::vector<uint8> data(block->data_size());
  std::copy(block->data(), block->data() + block->data_size(), data.begin());

  // Patch up all the references.
  BlockGraph::Block::ReferenceMap::const_iterator ref_it(
      block->references().begin());
  BlockGraph::Block::ReferenceMap::const_iterator ref_end(
      block->references().end());
  for (; ref_it != ref_end; ++ref_it) {
    BlockGraph::Offset start = ref_it->first;
    BlockGraph::Reference ref = ref_it->second;
    BlockGraph::Block* dst = ref.referenced();

    RelativeAddress src_addr(addr + start);
    RelativeAddress dst_addr;
    if (!image_.GetAddressOf(dst, &dst_addr)) {
      LOG(ERROR) << "All blocks must have an address";
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

      default:
        LOG(ERROR) << "Impossible reference type";
        return false;
        break;
    }

    // Now store the new value.
    switch (ref.size()) {
      case sizeof(uint8):
        if (!UpdateReference(start, static_cast<uint8>(value), &data))
          return false;
        break;

      case sizeof(uint32):
        if (!UpdateReference(start, static_cast<uint32>(value), &data))
          return false;
        break;

      default:
        LOG(ERROR) << "Unsupported reference size.";
        return false;
    }
  }

  if (fseek(file, file_offs.value(), SEEK_SET) != 0) {
    LOG(ERROR) << "Unable to seek file";
    return false;
  }
  if (fwrite(&data[0], sizeof(data[0]), data.size(), file) != data.size()) {
    LOG(ERROR) << "Unable to write block";
    return false;
  }
  return true;
}

const IMAGE_NT_HEADERS* PEFileWriter::GetNTHeaders() const {
  // Sanity check and retrieve the NT headers.
  BlockGraph::Block* block = header_.nt_headers;
  if (block == NULL || block->data() == NULL ||
      block->data_size() != block->size() ||
      block->data_size() != sizeof(IMAGE_NT_HEADERS)) {
    return NULL;
  }

  return reinterpret_cast<const IMAGE_NT_HEADERS*>(block->data());
}

const IMAGE_SECTION_HEADER* PEFileWriter::GetSectionHeaders() const {
  const IMAGE_NT_HEADERS* nt_headers = GetNTHeaders();
  if (nt_headers == NULL)
    return NULL;

  size_t expected_size =
      sizeof(IMAGE_SECTION_HEADER) * nt_headers->FileHeader.NumberOfSections;
  // Sanity check and retrieve the section headers.
  BlockGraph::Block* block = header_.image_section_headers;
  if (block == NULL || block->data() == NULL ||
      block->data_size() != block->size() ||
      block->data_size() != expected_size) {
    return NULL;
  }

  return reinterpret_cast<const IMAGE_SECTION_HEADER*>(block->data());
}

}  // namespace image_util
