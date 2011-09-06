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
#include "syzygy/pe/pe_file_builder.h"

#include <ctime>
#include <delayimp.h>

namespace {

// Reference to the associated .asm file that constructs the DOS stub.
extern "C" void begin_dos_stub();
extern "C" void end_dos_stub();


using core::BlockGraph;
using core::RelativeAddress;
typedef std::vector<uint8> ByteVector;

// A utility to align values to arbitrary boundaries
uint32 Align(uint32 value, uint32 boundary) {
  uint32 expanded = value + boundary - 1;
  return expanded - (expanded % boundary);
}

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

inline bool IsPowerOfTwo(uint32 n) {
  return n != 0 && (n & (n - 1)) == 0;
}

// TODO(rogerm): this functionality is duplicated!  Consolidate!
uint32 AlignUp(uint32 val, size_t alignment) {
  DCHECK(IsPowerOfTwo(alignment));
  return static_cast<uint32>((val + (alignment - 1)) & ~(alignment - 1));
}

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

}  // namespace

namespace pe {

PEFileBuilder::PEFileBuilder(BlockGraph* block_graph)
    : next_section_address_(kDefaultSectionAlignment),
      address_space_(block_graph),
      dos_header_block_(NULL),
      nt_headers_block_(NULL) {

  memset(&nt_headers_, 0, sizeof(nt_headers_));

  nt_headers_.Signature = IMAGE_NT_SIGNATURE;
  nt_headers_.FileHeader.Machine = IMAGE_FILE_MACHINE_I386;
  nt_headers_.FileHeader.TimeDateStamp = static_cast<uint32>(time(NULL));
  nt_headers_.FileHeader.SizeOfOptionalHeader =
      sizeof(nt_headers_.OptionalHeader);
  nt_headers_.FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE |
      IMAGE_FILE_32BIT_MACHINE | IMAGE_FILE_DLL;

  nt_headers_.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;

  // TODO(siggi): These should reflect Syzygy version.
  // Imagehlp.dll does not like major linker version less than 3 for
  // some reason. It refuses to bind or rebase images unless the
  // linker major version is better than 3. Seven is arbitrarily chosen.
  nt_headers_.OptionalHeader.MajorLinkerVersion = 7;
  nt_headers_.OptionalHeader.MinorLinkerVersion = 0;

  nt_headers_.OptionalHeader.ImageBase = kDefaultImageBase;
  nt_headers_.OptionalHeader.SectionAlignment = kDefaultSectionAlignment;
  nt_headers_.OptionalHeader.FileAlignment = kDefaultFileAlignment;
  nt_headers_.OptionalHeader.MajorOperatingSystemVersion = 5;
  nt_headers_.OptionalHeader.MinorOperatingSystemVersion = 0;
  nt_headers_.OptionalHeader.MajorImageVersion = 0;
  nt_headers_.OptionalHeader.MinorImageVersion = 0;
  nt_headers_.OptionalHeader.MajorSubsystemVersion = 5;
  nt_headers_.OptionalHeader.MinorSubsystemVersion = 0;
  nt_headers_.OptionalHeader.Win32VersionValue = 0;
  nt_headers_.OptionalHeader.SizeOfHeaders = kDefaultHeaderSize;

  nt_headers_.OptionalHeader.CheckSum = 0;
  nt_headers_.OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;

  nt_headers_.OptionalHeader.DllCharacteristics =
      IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE |
      IMAGE_DLLCHARACTERISTICS_NX_COMPAT;

  // These values reflect the defaults seen from the VC9 linker.
  nt_headers_.OptionalHeader.SizeOfStackReserve = 0x100000;
  nt_headers_.OptionalHeader.SizeOfStackCommit = 0x1000;
  nt_headers_.OptionalHeader.SizeOfHeapReserve = 0x100000;
  nt_headers_.OptionalHeader.SizeOfHeapCommit = 0x1000;
  nt_headers_.OptionalHeader.LoaderFlags = 0;
  nt_headers_.OptionalHeader.NumberOfRvaAndSizes =
      IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
}

RelativeAddress PEFileBuilder::AddSegment(const char* name,
                                          size_t size,
                                          size_t data_size,
                                          uint32 characteristics) {
  DCHECK_NE(0U, size);

  data_size = AlignUp(data_size, nt_headers_.OptionalHeader.FileAlignment);
  RelativeAddress section_base = next_section_address_;
  IMAGE_SECTION_HEADER new_header = { 0 };
  strncpy(reinterpret_cast<char*>(new_header.Name),
          name,
          arraysize(new_header.Name));
  new_header.Misc.VirtualSize = size;
  new_header.VirtualAddress = section_base.value();
  new_header.SizeOfRawData = data_size;
  if (section_headers_.empty()) {
    new_header.PointerToRawData = nt_headers_.OptionalHeader.SizeOfHeaders;
  } else {
    IMAGE_SECTION_HEADER& last = section_headers_.back();
    new_header.PointerToRawData = last.PointerToRawData + last.SizeOfRawData;
  }
  new_header.Characteristics = characteristics;
  section_headers_.push_back(new_header);

  next_section_address_ +=
      AlignUp(size, nt_headers_.OptionalHeader.SectionAlignment);

  return section_base;
}

bool PEFileBuilder::SetDataDirectoryEntry(size_t entry_index,
                                          BlockGraph::Block* block) {
  DCHECK_LT(entry_index, static_cast<size_t>(IMAGE_NUMBEROF_DIRECTORY_ENTRIES));
  DCHECK(block != NULL);

  BlockGraph::Reference ref(BlockGraph::RELATIVE_REF,
                            sizeof(RelativeAddress),
                            block,
                            0);
  return SetDataDirectoryEntry(entry_index, ref, block->size());
}

bool PEFileBuilder::SetDataDirectoryEntry(size_t entry_index,
                                          const BlockGraph::Reference& entry,
                                          size_t entry_size) {
  DCHECK_LT(entry_index, static_cast<size_t>(IMAGE_NUMBEROF_DIRECTORY_ENTRIES));
  DCHECK(IsValidReference(address_space_, entry));
  DCHECK_EQ(BlockGraph::RELATIVE_REF, entry.type());
  DCHECK(entry_size != NULL);

  data_directory_[entry_index].ref_ = entry;
  data_directory_[entry_index].size_ = entry_size;

  return true;
}

bool PEFileBuilder::CreateRelocsSection() {
  RelocWriter writer;

  // Iterate over all blocks in the address space, in the
  // order of increasing addresses.
  BlockGraph::AddressSpace::RangeMap::const_iterator it(
      address_space_.address_space_impl().ranges().begin());
  BlockGraph::AddressSpace::RangeMap::const_iterator end(
      address_space_.address_space_impl().ranges().end());

  for (; it != end; ++it) {
    const BlockGraph::Block* block = it->second;
    RelativeAddress block_addr;
    CHECK(address_space_.GetAddressOf(block, &block_addr));

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

  // Create a new image segment for the relocs.
  const uint32 kRelocCharacteristics = IMAGE_SCN_CNT_INITIALIZED_DATA |
      IMAGE_SCN_MEM_DISCARDABLE | IMAGE_SCN_MEM_READ;
  size_t relocs_file_size =
      AlignUp(relocs.size(), nt_headers_.OptionalHeader.FileAlignment);
  RelativeAddress section_base = AddSegment(".reloc",
                                            relocs.size(),
                                            relocs_file_size,
                                            kRelocCharacteristics);
  DCHECK_NE(RelativeAddress(0), section_base);

  // And add a corresponding block referring the data to the address space.
  BlockGraph::Block* block =
      address_space_.AddBlock(BlockGraph::DATA_BLOCK,
                              section_base,
                              relocs.size(),
                              ".relocs");
  if (block == NULL || block->CopyData(relocs.size(), &relocs.at(0)) == NULL) {
    LOG(ERROR) << "Failed to add relocs block to image";
    return false;
  }

  // Store the new data directory entry.
  return SetDataDirectoryEntry(IMAGE_DIRECTORY_ENTRY_BASERELOC, block);
}

bool PEFileBuilder::FinalizeHeaders() {
  // The DOS header should not be set at this point.
  DCHECK(dos_header_block_ == NULL);
  if (!CreateDosHeader()) {
    LOG(ERROR) << "Unable to create DOS header";
    return false;
  }
  DCHECK(dos_header_block_ != NULL);

  nt_headers_.FileHeader.NumberOfSections = section_headers_.size();

  // Iterate through our sections to initialize the code/data fields.
  for (size_t i = 0; i < section_headers_.size(); ++i) {
    const IMAGE_SECTION_HEADER& hdr = section_headers_[i];

    if (hdr.Characteristics & IMAGE_SCN_CNT_CODE) {
      nt_headers_.OptionalHeader.SizeOfCode += hdr.SizeOfRawData;
      if (nt_headers_.OptionalHeader.BaseOfCode == 0) {
        nt_headers_.OptionalHeader.BaseOfCode = hdr.VirtualAddress;
      }
    }
    if (hdr.Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) {
      nt_headers_.OptionalHeader.SizeOfInitializedData += hdr.SizeOfRawData;

      if (nt_headers_.OptionalHeader.BaseOfData == 0)
        nt_headers_.OptionalHeader.BaseOfData = hdr.VirtualAddress;
    }
    if (hdr.Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) {
      nt_headers_.OptionalHeader.SizeOfUninitializedData +=
          hdr.SizeOfRawData;
      if (nt_headers_.OptionalHeader.BaseOfData == 0)
        nt_headers_.OptionalHeader.BaseOfData = hdr.VirtualAddress;
    }
  }

  nt_headers_.OptionalHeader.SizeOfImage = next_section_address_.value();

  // Initialize the data directory entry sizes.
  for (size_t i = 0; i < arraysize(data_directory_); ++i) {
    nt_headers_.OptionalHeader.DataDirectory[i].Size = data_directory_[i].size_;
  }

  // Add the NT headers block.
  BlockGraph::Block* nt_headers_block =
      address_space_.AddBlock(BlockGraph::DATA_BLOCK,
          dos_header_block_->addr() + dos_header_block_->size(),
          sizeof(nt_headers_), "NT Headers");
  if (nt_headers_block == NULL ||
      !nt_headers_block->CopyData(sizeof(nt_headers_), &nt_headers_)) {
    LOG(ERROR) << "Unable to add NT headers block";
    return false;
  }

  // Insert the reference from the DOS headers to the NT header.
  BlockGraph::Reference ref(BlockGraph::RELATIVE_REF,
                            sizeof(WORD),
                            nt_headers_block,
                            0);
  dos_header_block_->SetReference(FIELD_OFFSET(IMAGE_DOS_HEADER, e_lfanew),
                                  ref);

  // Now add the references for the entry point and data
  // directory to the headers block.
  if (!nt_headers_block->SetReference(
      FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader.AddressOfEntryPoint),
      entry_point_)) {
    LOG(ERROR) << "Unable to add entry point reference";
    return false;
  }

  for (size_t i = 0; i < arraysize(data_directory_); ++i) {
    BlockGraph::Offset offs = FIELD_OFFSET(IMAGE_NT_HEADERS,
        OptionalHeader.DataDirectory[i].VirtualAddress);

    if (data_directory_[i].ref_.referenced() != NULL &&
        !nt_headers_block->SetReference(offs, data_directory_[i].ref_)) {
      LOG(ERROR) << "Unable to data directory entry reference";
      return false;
    }
  }

  // Now add the section headers block.
  BlockGraph::Block* section_headers_block =
      address_space_.AddBlock(BlockGraph::DATA_BLOCK,
          nt_headers_block->addr() + nt_headers_block->size(),
          sizeof(IMAGE_SECTION_HEADER) * section_headers_.size(),
          "Image Section Headers");
  if (section_headers_block == NULL ||
      !section_headers_block->CopyData(
          sizeof(IMAGE_SECTION_HEADER) * section_headers_.size(),
          &section_headers_.at(0))) {
    LOG(ERROR) << "Unable to add section headers block";
    return false;
  }

  nt_headers_block_ = nt_headers_block;

  // Verify there's room for the headers.
  // TODO(chrisha): The PE File Builder needs to be reworked. We can't
  //     determine where to lay out the sections until we know how big the
  //     headers are, and we don't know how big the headers are until we
  //     know how many sections there are. Layout needs to be two pass to
  //     support this, with most of the work in AddSegment happening as part
  //     of finalize headers.
  size_t header_size =
      section_headers_block->addr().value() + section_headers_block->size();
  if (header_size > nt_headers_.OptionalHeader.SizeOfHeaders) {
    LOG(ERROR) << "Insufficient room for new headers.";
    return false;
  }

  return true;
}

bool PEFileBuilder::CreateDosHeader() {
  const uint8* begin_dos_stub_ptr =
      reinterpret_cast<const uint8*>(&begin_dos_stub);
  const uint8* end_dos_stub_ptr =
      reinterpret_cast<const uint8*>(&end_dos_stub);

  // The DOS header has to be a multiple of 16 bytes for historic reasons.
  size_t dos_header_size = AlignUp(
      sizeof(IMAGE_DOS_HEADER) + end_dos_stub_ptr - begin_dos_stub_ptr, 16);

  BlockGraph::Block* dos_header =
      address_space_.AddBlock(BlockGraph::DATA_BLOCK,
                              RelativeAddress(0),
                              dos_header_size,
                              "DOS Header");
  if (dos_header == NULL) {
    LOG(ERROR) << "Unable to insert DOS header in image.";
    return false;
  }

  IMAGE_DOS_HEADER* dos_header_ptr =
      reinterpret_cast<IMAGE_DOS_HEADER*>(
          dos_header->AllocateData(dos_header_size));
  if (dos_header_ptr == NULL) {
    LOG(ERROR) << "Unable to allocate DOS header data.";
    return false;
  }

  memset(dos_header_ptr, 0, sizeof(*dos_header_ptr));
  memcpy(dos_header_ptr + 1,
         begin_dos_stub_ptr,
         end_dos_stub_ptr - begin_dos_stub_ptr);

  dos_header_ptr->e_magic = IMAGE_DOS_SIGNATURE;
  // Calculate the number of bytes used on the last DOS executable "page".
  dos_header_ptr->e_cblp = dos_header_size % 512;
  // Calculate the number of pages used by the DOS executable.
  dos_header_ptr->e_cp = dos_header_size / 512;
  // Count the last page if we didn't have an even multiple
  if (dos_header_ptr->e_cblp != 0)
    dos_header_ptr->e_cp++;

  // Header length in "paragraphs".
  dos_header_ptr->e_cparhdr = sizeof(*dos_header_ptr) / 16;

  // Set this to max allowed, just because.
  dos_header_ptr->e_maxalloc = 0xFFFF;

  // Location of relocs - our header has zero relocs, but we set this anyway.
  dos_header_ptr->e_lfarlc = sizeof(*dos_header_ptr);

  // Store the dos header block.
  dos_header_block_ = dos_header;
  return true;
}

}  // namespace pe
