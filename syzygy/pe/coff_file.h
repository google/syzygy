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

// COFF file reading and support for COFF-specific features, such as
// symbol and string tables and COFF relocations.

#ifndef SYZYGY_PE_COFF_FILE_H_
#define SYZYGY_PE_COFF_FILE_H_

#include <windows.h>
#include <winnt.h>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "base/files/file_path.h"
#include "syzygy/core/address.h"
#include "syzygy/core/address_space.h"
#include "syzygy/core/serialization.h"
#include "syzygy/pe/pe_coff_file.h"
#include "syzygy/pe/pe_file.h"

namespace pe {

// Traits of the COFF address space.
struct CoffAddressSpaceTraits {
  // Native addresses for COFF files: physical file offsets.
  typedef core::FileOffsetAddress AddressType;

  // Native sizes for COFF files.
  typedef size_t SizeType;

  // @returns an address different from all valid addresses for the
  //     specified address type.
  static const AddressType invalid_address() {
    return AddressType::kInvalidAddress;
  }

  // @returns the address of the header range, which is always zero
  //     for COFF files.
  static AddressType header_address() {
    return AddressType(0);
  }

  // Return the file offset of the section data on disk.
  //
  // @param header the section header.
  // @returns the offset of the section.
  static AddressType GetSectionAddress(const IMAGE_SECTION_HEADER& header) {
    if ((header.Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) != 0 &&
        header.PointerToRawData == 0) {
      // Unmapped BSS section.
      return invalid_address();
    }
    return AddressType(header.PointerToRawData);
  }

  // Return the number of bytes occupied by the section data on disk.
  //
  // @param header the section header.
  // @returns the file size of the section.
  static SizeType GetSectionSize(const IMAGE_SECTION_HEADER& header) {
    return SizeType(header.SizeOfRawData);
  }
};

// A raw, sparse, representation of a COFF file. It offers a view of
// the contents of the file as is present in the object file, on disk.
class CoffFile : public PECoffFile<CoffAddressSpaceTraits> {
 public:
  typedef core::FileOffsetAddress FileOffsetAddress;

  // A map of the decoded relocation information, where each pair in
  // the map associates a location containing the address to relocate
  // with a pointer to the IMAGE_RELOCATION structure describing the
  // relocation.
  typedef std::map<FileOffsetAddress, const IMAGE_RELOCATION*> RelocMap;

  // Construct a CoffFile object not yet bound to any file.
  CoffFile();

  // Destroy this CoffFile object, invalidating all pointers obtained
  // through GetImageData(), or headers returned by corresponding
  // accessor methods.
  ~CoffFile();

  // Read in the image file at @p path, making its data
  // available. A COFF file reader may only read a single file.
  //
  // @param path the path to the file to read.
  // @returns true on success, false on error.
  bool Init(const base::FilePath& path);

  // Translate a file offset to a pair of section index and relative
  // offset.
  //
  // @param addr the file offset to translate.
  // @param section_index where to put the section index.
  // @param offset where to put the section-relative offset.
  // @returns true on success, false if @p addr does not refer to
  //     section data.
  bool FileOffsetToSectionOffset(FileOffsetAddress addr,
                                 size_t* section_index,
                                 size_t* offset) const;

  // Translate a pair of section index and relative offset to a file
  // offset.
  //
  // @param section_index the section index.
  // @param offset the section-relative offset.
  // @param addr where to put the translated address.
  // @returns true on success, false if the pair does not refer to
  //     section data.
  bool SectionOffsetToFileOffset(size_t section_index, size_t offset,
                                 FileOffsetAddress* addr) const;

  // Decode relocations for all sections, inserting the results into
  // @p reloc_map.
  //
  // @param reloc_map the map to which relocation--target pairs are to
  //     be added.
  void DecodeRelocs(RelocMap* reloc_map) const;

  // Decode relocation information for the specified section,
  // inserting the result into @p reloc_map.
  //
  // @param section_index the index of the section to decode
  //     relocations for.
  // @param reloc_map the map to which relocation--target pairs are to
  //     be added.
  // @returns true on success, false on error.
  bool DecodeSectionRelocs(size_t section_index, RelocMap* reloc_map) const;

  // Test whether the specified section is mapped into the address
  // space of this object. BSS sections are not mapped and must be
  // handled specially.
  //
  // @param section_index the index of the section.
  // @returns true if the section is mapped, false otherwise.
  bool IsSectionMapped(size_t section_index) const;

  // Retrieve the symbol name at the specified index, handling both
  // short and long symbol names, reading from the string table if
  // necessary.
  //
  // @param symbol_index the index of the symbol.
  // @returns the name of the symbol, or NULL if the index is invalid.
  const char* GetSymbolName(size_t symbol_index) const;

  // @returns a pointer to the symbol table of this COFF file.
  const IMAGE_SYMBOL* symbols() const {
    return symbols_;
  }

  // Retrieve a pointer to the symbol entry at index @p symbol_index.
  //
  // @param symbol_index the index of the symbol.
  // @returns a pointer to the symbol structure.
  const IMAGE_SYMBOL* symbol(size_t symbol_index) const {
    if (symbol_index >= file_header_->NumberOfSymbols) {
      return NULL;
    }
    return &symbols_[symbol_index];
  }

  // @returns a pointer to the string table of this COFF file.
  const char* strings() const {
    return strings_;
  }

  // Retrieve a pointer to the string at offset @p string_offset,
  // relative to the beginning of the string table.
  //
  // @param string_offset the offset of the string.
  // @returns a pointer to the zero-terminated string, or NULL if
  //     @p string_offset does not refer to the beginning of
  //     a string.
  const char* string(size_t string_offset) const {
    if (string_offset >= strings_size_) {
      return NULL;
    }
    return strings_ + string_offset;
  }

  // @returns the address of the symbol table.
  FileOffsetAddress symbols_address() const {
    return symbols_offset_;
  }

  // @returns the size of the symbol table.
  size_t symbols_size() const {
    return symbols_size_;
  }

  // @returns the address of the string table.
  FileOffsetAddress strings_address() const {
    return strings_offset_;
  }

  // @returns the size of the string table.
  size_t strings_size() const {
    return strings_size_;
  }

 private:
  // Information on the relocation table of a given section.
  struct SectionRelocInfo {
    // A pointer to the internal relocation data.
    IMAGE_RELOCATION* relocs_;

    // The number of relocations in the table pointed to by relocs_.
    size_t num_relocs_;
  };

  // Add data outside of sections (relocations, symbols, strings) to
  // the address space.
  //
  // @param file the input file stream.
  // @returns true on success, false on error.
  bool ReadNonSections(FILE* file);

  // A pointer to the internal symbol table data.
  IMAGE_SYMBOL* symbols_;

  // A pointer to the internal string table data.
  char* strings_;

  // The offset to the symbol table in the file.
  FileOffsetAddress symbols_offset_;
  // The size in bytes of the symbol table.
  size_t symbols_size_;

  // The offset to the string table in the file.
  FileOffsetAddress strings_offset_;
  // The size in bytes of the string table.
  size_t strings_size_;

  // A vector containing relocation information for every sections,
  // indexed by the section index.
  std::vector<SectionRelocInfo> reloc_infos_;

  DISALLOW_COPY_AND_ASSIGN(CoffFile);
};

}  // namespace pe

#endif  // SYZYGY_PE_COFF_FILE_H_
