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

#include "syzygy/pe/coff_file.h"

#include "base/file_util.h"
#include "base/logging.h"

namespace pe {

using core::FileOffsetAddress;

CoffFile::CoffFile()
    : symbols_(NULL),
      strings_(NULL),
      symbols_offset_(),
      symbols_size_(0),
      strings_offset_(),
      strings_size_(0),
      reloc_infos_() {
}

CoffFile::~CoffFile() {
}

bool CoffFile::Init(const base::FilePath& path) {
  PECoffFile::Init(path);

  base::ScopedFILE file(base::OpenFile(path, "rb"));
  if (file.get() == NULL) {
    LOG(ERROR) << "Failed to open file " << path.value() << ".";
    return false;
  }

  bool success = ReadCommonHeaders(file.get(), FileOffsetAddress(0));
  if (success)
    success = ReadSections(file.get());
  if (success)
    success = ReadNonSections(file.get());

  return success;
}

bool CoffFile::FileOffsetToSectionOffset(FileOffsetAddress addr,
                                         size_t* section_index,
                                         size_t* offset) const {
  DCHECK(section_index != NULL);
  DCHECK(offset != NULL);

  ImageAddressSpace::RangeMap::const_iterator it =
      image_data_.FindContaining(ImageAddressSpace::Range(addr, 1));
  if (it == image_data_.ranges().end())
    return false;
  if (it->second.id == kInvalidSection || addr >= it->first.end())
    return false;

  *section_index = it->second.id;
  *offset = addr - it->first.start();
  return true;
}

bool CoffFile::SectionOffsetToFileOffset(size_t section_index,
                                         size_t offset,
                                         FileOffsetAddress* addr) const {
  DCHECK(addr != NULL);

  if (section_index >= file_header_->NumberOfSections) {
    LOG(ERROR) << "Unknown section index " << section_index << ".";
    return false;
  }

  const IMAGE_SECTION_HEADER* header = &section_headers_[section_index];
  if (offset > header->SizeOfRawData) {
    LOG(ERROR) << "Section offset " << section_index << " out of bounds.";
    return false;
  }

  addr->set_value(header->PointerToRawData + offset);
  return true;
}

bool CoffFile::ReadNonSections(FILE* file) {
  DCHECK(file != NULL);
  DCHECK(file_header_ != NULL);

  // Map the symbol table into our address space.
  FileOffsetAddress symbols_start(file_header_->PointerToSymbolTable);
  size_t symbols_size = file_header_->NumberOfSymbols * sizeof(*symbols_);
  ImageAddressSpace::Range symbols_range(symbols_start, symbols_size);
  if (!InsertRangeReadAt(file, symbols_start, symbols_size, symbols_range))
    return false;

  // Get the pointer to our internal data range.
  CHECK(GetImageData(symbols_start, symbols_size, &symbols_));
  symbols_offset_ = symbols_start;
  symbols_size_ = symbols_size;

  // Map the string table into our address space.
  FileOffsetAddress strings_start(symbols_start + symbols_size);
  uint32 strings_size = 0;
  if (!ReadAt(file, strings_start.value(),
              &strings_size, sizeof(strings_size))) {
    LOG(ERROR) << "Unable to read string table size.";
    return false;
  }
  if (strings_size > 0) {
    ImageAddressSpace::Range strings_range(strings_start, strings_size);
    if (!InsertRangeReadAt(file, strings_start, strings_size, strings_range))
      return false;

    CHECK(GetImageData(strings_start, strings_size, &strings_));
  }
  strings_offset_ = strings_start;
  strings_size_ = strings_size;

  // Map relocation data for every section.
  size_t num_sections = file_header_->NumberOfSections;
  reloc_infos_.resize(num_sections);
  for (size_t i = 0; i < num_sections; ++i) {
    const IMAGE_SECTION_HEADER* header = section_header(i);
    FileOffsetAddress relocs_start(header->PointerToRelocations);

    size_t num_relocs = header->NumberOfRelocations;
    if ((header->Characteristics & IMAGE_SCN_LNK_NRELOC_OVFL) != 0) {
      DCHECK_EQ(num_relocs, 0xffffu);
      IMAGE_RELOCATION reloc;
      if (!ReadAt(file, header->PointerToRelocations,
                  &reloc, sizeof(reloc))) {
        LOG(ERROR) << "Unable to read extended relocation count.";
        return false;
      }
      num_relocs = reloc.VirtualAddress;
    }

    if (num_relocs == 0)
      continue;
    size_t relocs_size = num_relocs * sizeof(IMAGE_RELOCATION);

    ImageAddressSpace::Range relocs_range(relocs_start, relocs_size);
    if (!InsertRangeReadAt(file, relocs_start, relocs_size, relocs_range))
      return false;

    // Save section relocation info to avoid recomputing pointer and
    // size from headers.
    CHECK(GetImageData(relocs_start, relocs_size, &reloc_infos_[i].relocs_));
    reloc_infos_[i].num_relocs_ = num_relocs;
  }

  return true;
}

void CoffFile::DecodeRelocs(RelocMap* reloc_map) const {
  DCHECK(file_header_ != NULL);
  DCHECK(symbols_ != NULL);

  size_t num_sections = file_header_->NumberOfSections;
  for (size_t i = 0; i < num_sections; ++i) {
    CHECK(DecodeSectionRelocs(i, reloc_map));
  }
}

bool CoffFile::DecodeSectionRelocs(size_t section_index,
                                   RelocMap* reloc_map) const {
  DCHECK(file_header_ != NULL);
  DCHECK(symbols_ != NULL);

  const IMAGE_SECTION_HEADER* header = section_header(section_index);
  if (header == NULL)
    return false;

  IMAGE_RELOCATION* relocs = reloc_infos_[section_index].relocs_;
  size_t num_relocs = reloc_infos_[section_index].num_relocs_;

  for (size_t i = 0; i < num_relocs; ++i) {
    size_t offset = relocs[i].VirtualAddress - header->VirtualAddress;
    FileOffsetAddress addr(header->PointerToRawData + offset);
    reloc_map->insert(std::make_pair(addr, &relocs[i]));
  }

  return true;
}

bool CoffFile::IsSectionMapped(size_t section_index) const {
  DCHECK(section_headers_ != NULL);

  const IMAGE_SECTION_HEADER* header = section_header(section_index);
  return header != NULL &&
      (CoffAddressSpaceTraits::GetSectionAddress(*header) !=
       CoffAddressSpaceTraits::invalid_address());
}

const char* CoffFile::GetSymbolName(size_t symbol_index) const {
  DCHECK(symbols_ != NULL);

  IMAGE_SYMBOL* symbol = &symbols_[symbol_index];
  if (symbol->N.Name.Short != 0)
    return reinterpret_cast<const char*>(&symbol->N.ShortName);
  else
    return string(symbol->N.Name.Long);
}

}  // namespace pe
