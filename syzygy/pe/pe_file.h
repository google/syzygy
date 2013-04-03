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

#ifndef SYZYGY_PE_PE_FILE_H_
#define SYZYGY_PE_PE_FILE_H_

#include <windows.h>
#include <winnt.h>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "base/files/file_path.h"
#include "sawbuck/sym_util/types.h"
#include "syzygy/core/address.h"
#include "syzygy/core/address_space.h"
#include "syzygy/core/serialization.h"

namespace pe {

// This duplicates a similar constant in the core namespace, declared by
// block_graph.h. We duplicate it here so as not to add an uneccessary
// dependency.
// Header data and other data not from a regular section is considered as
// being from an invalid section.
extern const size_t kInvalidSection;

class PEFile {
 public:
  // Used for storing the signature of a PE file.
  struct Signature;

  typedef core::AbsoluteAddress AbsoluteAddress;
  typedef core::FileOffsetAddress FileOffsetAddress;
  typedef core::RelativeAddress RelativeAddress;

  // Contains relocation addresses.
  typedef std::set<RelativeAddress> RelocSet;

  // Contains the decoded relocation information, where each item
  // in the map is the address and value of a relocatable entry.
  typedef std::map<RelativeAddress, AbsoluteAddress> RelocMap;

  // Information about a single export.
  struct ExportInfo;
  typedef std::vector<ExportInfo> ExportInfoVector;

  // Information about a single import.
  struct ImportInfo;
  typedef std::vector<ImportInfo> ImportInfoVector;

  // Information about all imports for a given DLL.
  struct ImportDll;
  typedef std::vector<ImportDll> ImportDllVector;

  PEFile();
  ~PEFile();

  const base::FilePath& path() const { return path_; }

  // Read in the image file at path.
  bool Init(const base::FilePath& path);

  // Populates a signature object with the signature of this PE file. This
  // is only valid if called after Init.
  void GetSignature(Signature* signature) const;

  // Decodes the relocation information from the image to relocs.
  // TODO(siggi): Consider folding this member into ReadRelocs.
  bool DecodeRelocs(RelocSet* relocs) const;
  // Reads all reloc values from the image.
  bool ReadRelocs(const RelocSet& relocs, RelocMap* reloc_values) const;

  // Decodes the import information in the image.
  bool DecodeImports(ImportDllVector* imports) const;

  // Decodes the export information in the image.
  bool DecodeExports(ExportInfoVector* exports) const;

  // @{
  // Translate between relative and absolute addresses.
  bool Translate(RelativeAddress rel, AbsoluteAddress* abs) const;
  bool Translate(AbsoluteAddress abs, RelativeAddress* rel) const;
  bool Translate(FileOffsetAddress offs, RelativeAddress* rel) const;
  bool Translate(RelativeAddress rel, FileOffsetAddress* offs) const;
  // @}

  // Read len bytes from image at offset offs to data.
  bool ReadImage(RelativeAddress rel, void* data, size_t len) const;
  bool ReadImage(AbsoluteAddress abs, void* data, size_t len) const;

  // Read a zero-terminated string from offs into str.
  bool ReadImageString(RelativeAddress rel, std::string* str) const;
  bool ReadImageString(AbsoluteAddress abs, std::string* str) const;

  // Get a pointer to the image at addr, provided the image contains data
  // for [addr, addr + len)
  const uint8* GetImageData(RelativeAddress rel, size_t len) const;
  const uint8* GetImageData(AbsoluteAddress abs, size_t len) const;
  uint8* GetImageData(RelativeAddress rel, size_t len);
  uint8* GetImageData(AbsoluteAddress abs, size_t len);

  // Check whether or not a given address range is inside the
  // address space of the PE image.
  bool Contains(RelativeAddress rel, size_t len) const;
  bool Contains(AbsoluteAddress abs, size_t len) const;

  // Returns the section index associated with a given address. Returns
  // kInvalidSection if the address does not lie within a section.
  size_t GetSectionIndex(RelativeAddress rel, size_t len) const;
  size_t GetSectionIndex(AbsoluteAddress abs, size_t len) const;

  // Returns a pointer to the section header associated with a given address.
  // Returns NULL if the address does not lie within a section.
  const IMAGE_SECTION_HEADER* GetSectionHeader(RelativeAddress rel,
                                               size_t len) const;
  const IMAGE_SECTION_HEADER* GetSectionHeader(AbsoluteAddress rel,
                                               size_t len) const;

  // Returns the section index associated with the given name. Returns
  // kInvalidSection if no section with that name is found.
  size_t GetSectionIndex(const char* name) const;

  // Returns the section header associated with the given name. Returns
  // kInvalidSection if no section with the name is found.
  const IMAGE_SECTION_HEADER* GetSectionHeader(const char* name) const;

  // Helper to stringify the name of a section.
  std::string GetSectionName(size_t section_index) const;
  static std::string GetSectionName(const IMAGE_SECTION_HEADER& section);

  // Accessors.
  const IMAGE_DOS_HEADER* dos_header() const {
    return dos_header_;
  }

  const IMAGE_NT_HEADERS* nt_headers() const {
    return nt_headers_;
  }

  const IMAGE_SECTION_HEADER* section_headers() const {
    return section_headers_;
  }

  const IMAGE_SECTION_HEADER* section_header(size_t num_section) const {
    if (nt_headers_ != NULL &&
        num_section < nt_headers_->FileHeader.NumberOfSections)
      return section_headers_ + num_section;

    return NULL;
  }

 private:
  bool ReadHeaders(FILE* file);
  bool ReadSections(FILE* file);

  base::FilePath path_;
  const IMAGE_DOS_HEADER* dos_header_;
  const IMAGE_NT_HEADERS* nt_headers_;
  const IMAGE_SECTION_HEADER* section_headers_;

  typedef std::vector<uint8> SectionBuffer;
  struct SectionInfo {
    SectionInfo() : id(kInvalidSection) {
    }
    size_t id;
    SectionBuffer buffer;
  };
  typedef core::AddressSpace<RelativeAddress, size_t, SectionInfo>
      ImageAddressSpace;

  // Contains all data in the image. The address space has a range defined
  // for the header and each section in the image, with its associated
  // SectionBuffer as the data.
  ImageAddressSpace image_data_;

  DISALLOW_COPY_AND_ASSIGN(PEFile);
};

// This structure holds a PE file signature.
struct PEFile::Signature {
  Signature() : module_size(0), module_time_date_stamp(0), module_checksum(0) {
  }

  explicit Signature(const sym_util::ModuleInformation& module_info)
      : path(module_info.image_file_name),
        base_address(module_info.base_address),
        module_size(module_info.module_size),
        module_time_date_stamp(module_info.time_date_stamp),
        module_checksum(module_info.image_checksum) {
  }

  // The original path is kept for convenience. This should always be an
  // absolute path.
  // TODO(chrisha): Check that the path is absolute at all sites where this
  //     path is used.
  std::wstring path;

  // The signature consists of the following 4 fields.
  AbsoluteAddress base_address;
  size_t module_size;
  uint32 module_time_date_stamp;
  uint32 module_checksum;

  // Compares this signature to another one. The paths do not have to match.
  bool IsConsistent(const Signature& signature) const;

  // Compares this signature to another one.
  // The paths and the checksum do not have to match.
  bool IsConsistentExceptForChecksum(const Signature& signature) const;

  // We need an equality operator for serialization unittests.
  bool operator==(const Signature& signature) const {
    return path == signature.path && IsConsistent(signature);
  }

  // For serialization.
  bool Save(core::OutArchive* out_archive) const;
  bool Load(core::InArchive* in_archive);
};

// Information about a single export.
struct PEFile::ExportInfo {
  // Address of the exported function.
  RelativeAddress function;

  // Name of the export, if any.
  std::string name;

  // Export forward string, if any.
  std::string forward;

  // Export ordinal.
  uint16 ordinal;
};

// Information about a single import.
struct PEFile::ImportInfo {
  ImportInfo(uint16 h, uint16 o, const char* n)
      : hint(h),
        ordinal(o),
        function(n) {
  }

  explicit ImportInfo(const char* function_name)
      : hint(0),
        ordinal(0),
        function(function_name) {
  }
  explicit ImportInfo(uint16 function_ordinal)
      : hint(0),
        ordinal(function_ordinal) {
  }
  ImportInfo() : hint(0), ordinal(0) {
  }

  bool operator==(const ImportInfo& o) const {
    return hint == o.hint && ordinal == o.ordinal && function == o.function;
  }

  // The loader ordinal hint for this import.
  uint16 hint;

  // The ordinal of the function if function.empty().
  uint16 ordinal;

  // If non-empty, the name of the function.
  std::string function;
};

// Information about all imports for a given DLL.
struct PEFile::ImportDll {
  ImportDll() {
    memset(&desc, 0, sizeof(desc));
    desc.ForwarderChain = -1;
  }

  // The import descriptor.
  IMAGE_IMPORT_DESCRIPTOR desc;

  // Name of the DLL imported.
  std::string name;

  // One entry for each imported function.
  ImportInfoVector functions;
};

}  // namespace pe

#endif  // SYZYGY_PE_PE_FILE_H_
