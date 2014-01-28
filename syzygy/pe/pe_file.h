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

#include "base/file_util.h"
#include "base/logging.h"
#include "base/files/file_path.h"
#include "sawbuck/sym_util/types.h"
#include "syzygy/core/address.h"
#include "syzygy/core/address_space.h"
#include "syzygy/core/serialization.h"
#include "syzygy/pe/pe_coff_file.h"

namespace pe {

// Traits of the PE address space.
struct PEAddressSpaceTraits {
  // Native addresses for PE files: relative virtual addresses (RVAs).
  typedef core::RelativeAddress AddressType;

  // Native sizes for PE files.
  typedef size_t SizeType;

  // @returns an address different from all valid addresses for the
  // specified address type.
  static const AddressType invalid_address() {
    return AddressType::kInvalidAddress;
  }

  // @returns the address at which to insert global headers.
  static const AddressType header_address() {
    return AddressType(0);
  }

  // Return the RVA to which the section will be mapped when the
  // program is loaded.
  //
  // @param header the section header.
  // @returns the RVA of the section.
  static AddressType GetSectionAddress(const IMAGE_SECTION_HEADER& header) {
    return AddressType(header.VirtualAddress);
  }

  // Return the number of bytes that will be occupied by the section
  // when the program is loaded, including any run-time padding.
  //
  // @param header the section header.
  // @returns the run-time size of the section.
  static SizeType GetSectionSize(const IMAGE_SECTION_HEADER& header) {
    return SizeType(header.Misc.VirtualSize);
  }
};

// A raw, sparse, representation of a PE file. It offers a view of the
// contents of the file as would be mapped into memory, if the program
// were loaded.
template <typename ImageNtHeaders, DWORD MagicValidation>
class PEFileBase : public PECoffFile<PEAddressSpaceTraits> {
 public:
  struct Signature;

  typedef core::AbsoluteAddress AbsoluteAddress;
  typedef core::FileOffsetAddress FileOffsetAddress;
  typedef core::RelativeAddress RelativeAddress;

  // A set of locations in the RVA address space where an address is
  // present and needs to be relocated.
  typedef std::set<RelativeAddress> RelocSet;

  // A map from locations in the RVA address space where an address is
  // present and needs to be relocated, to the absolute addresses they
  // refer to.
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

  // Allow overloading of the following functions inherited from
  // PECoffFile.
  using PECoffFile<PEAddressSpaceTraits>::ReadImage;
  using PECoffFile<PEAddressSpaceTraits>::ReadImageString;
  using PECoffFile<PEAddressSpaceTraits>::GetImageData;
  using PECoffFile<PEAddressSpaceTraits>::Contains;
  using PECoffFile<PEAddressSpaceTraits>::GetSectionIndex;
  using PECoffFile<PEAddressSpaceTraits>::GetSectionHeader;

  // Construct a PEFileBase object not yet bound to any file.
  PEFileBase() : dos_header_(NULL), nt_headers_(NULL) {}

  // Destroy this PEFileBase object, invalidating all pointers obtained
  // through GetImageData(), or headers returned by corresponding
  // accessor methods.
  ~PEFileBase() {}

  // Read in the image file at @p path, making its data
  // available. A PE file reader may only read a single file.
  //
  // @param path the path to the file to read.
  // @returns true on success, false on error.
  bool Init(const base::FilePath& path);

  // Retrieve the signature of this PE file. May only be called after
  // a file has been read with Init().
  //
  // @param signature the object to copy the signature to.
  void GetSignature(Signature* signature) const;

  // Decode relocation information from the image, inserting the
  // results into @p relocs.
  //
  // TODO(siggi): Consider folding this member into ReadRelocs.
  //
  // @param relocs the set to which relocations are to be added.
  // @returns true on success, false on error.
  bool DecodeRelocs(RelocSet* relocs) const;

  // Retrieve relocation target addresses for the specified set of
  // relocations.
  //
  // @param relocs the set of relocations to look up.
  // @param reloc_values the map to which relocation--target pairs are
  // to be added.
  // @returns true on success, false on error.
  bool ReadRelocs(const RelocSet& relocs, RelocMap* reloc_values) const;

  // Decode import information from the image.
  //
  // @param imports where to place the decoded imports.
  // @returns true on success, false on error.
  bool DecodeImports(ImportDllVector* imports) const;

  // Decode export information from the image.
  //
  // @param exports where to place the decoded exports.
  // @returns true on success, false on error.
  bool DecodeExports(ExportInfoVector* exports) const;

  // Translate a relative address to an absolute address, based on the
  // preferred loading address of this PE file.
  //
  // @param rel the address to translate.
  // @param abs where to place the resulting address.
  // @returns true on success, false on error.
  bool Translate(RelativeAddress rel, AbsoluteAddress* abs) const;

  // Translate an absolute address to a relative address, based on the
  // preferred loading address of this PE file.
  //
  // @param abs the address to translate.
  // @param rel where to place the resulting address.
  // @returns true on success, false on error.
  bool Translate(AbsoluteAddress abs, RelativeAddress* rel) const;

  // Translate a file offset present in the on-disk file to the
  // relative address it maps to at run-time.
  //
  // @param offs the file offset to translate.
  // @param rel where to place the resulting address.
  // @returns true on success, false on error.
  bool Translate(FileOffsetAddress offs, RelativeAddress* rel) const;

  // Translate a relative address to the file offset it is mapped from
  // in the on-disk file.
  //
  // @param rel the address to translate.
  // @param offs where to place the resulting address.
  // @returns true on success, false on error.
  bool Translate(RelativeAddress rel, FileOffsetAddress* offs) const;

  // Absolute address wrappers around the same-named methods from
  // PECoffFile, which deal with relative addresses. Each of the
  // following method is equivalent to applying Translate() to the
  // absolute address then calling the corresponding RVA-based method.
  //
  // @see pe::PECoffFile @{
  bool ReadImage(AbsoluteAddress addr, void* data, size_t len) const;
  bool ReadImageString(AbsoluteAddress addr, std::string* str) const;
  const uint8* GetImageData(AbsoluteAddress addr, size_t len) const;
  uint8* GetImageData(AbsoluteAddress addr, size_t len);
  bool Contains(AbsoluteAddress addr, size_t len) const;
  size_t GetSectionIndex(AbsoluteAddress addr, size_t len) const;
  const IMAGE_SECTION_HEADER* GetSectionHeader(AbsoluteAddress addr,
                                               size_t len) const;
  // @}

  // Retrieve the index of the first section with the specified name.
  //
  // @param name the name of the section to look up.
  // @returns the index of the section, or kInvalidSection if none is
  // found.
  size_t GetSectionIndex(const char* name) const;

  // Retrieve a pointer to the header structure of the first section
  // with the specified name.
  //
  // @param name the name of the section to look up.
  // @returns a pointer to the header structure of the section, or
  // NULL if none is found.
  const IMAGE_SECTION_HEADER* GetSectionHeader(const char* name) const;

  // @returns a pointer to the DOS header structure of this PE file.
  const IMAGE_DOS_HEADER* dos_header() const;

  // @returns a pointer to the NT headers structure of this PE file.
  const ImageNtHeaders* nt_headers() const;

  // Subtract the preferred loading address of this PE file from the
  // specified displacement.
  //
  // @param abs_disp the value to translate.
  // @returns the new offset, relative to the preferred loading
  // address.
  size_t AbsToRelDisplacement(size_t abs_disp) const;

 private:
  // Read all NT headers, including common COFF headers. Insert
  // a range covering all headers.
  //
  // @param file the input file stream.
  // @returns true on success, false on error.
  bool ReadHeaders(FILE* file);

  const IMAGE_DOS_HEADER* dos_header_;
  const ImageNtHeaders* nt_headers_;

  DISALLOW_COPY_AND_ASSIGN(PEFileBase);
};

// A parsed PE file signature; a signature describes some module. It
// offers access to the exploded components of the PE signature,
// comparison, and serialization.
template<class ImageNtHeaders, DWORD MagicValidation>
struct PEFileBase<ImageNtHeaders, MagicValidation>::Signature {
  // Construct a default all-zero signature.
  Signature() : module_size(0), module_time_date_stamp(0), module_checksum(0) {
  }

  // Construct a signature from the specified module information.
  //
  // @param module_info the module information from which to extract
  // signature data.
  explicit Signature(const sym_util::ModuleInformation& module_info)
      : path(module_info.image_file_name),
        base_address(module_info.base_address),
        module_size(module_info.module_size),
        module_time_date_stamp(module_info.time_date_stamp),
        module_checksum(module_info.image_checksum) {
  }

  // The original module path, kept for convenience. This should
  // always be an absolute path.
  //
  // TODO(chrisha): Check that the path is absolute at all sites where this
  //     path is used.
  std::wstring path;

  // The four signature components.
  // @{
  // The preferred loading address of the module.
  AbsoluteAddress base_address;

  // The on-disk size in bytes of the module file.
  size_t module_size;

  // The on-disk modification time of the module file.
  uint32 module_time_date_stamp;

  // A 32-bit checksum of the module file.
  uint32 module_checksum;
  // @}

  // Compare the specified signature with this one. Signatures are
  // consistent with one another if their four components match; paths
  // may differ.
  //
  // @param signature the signature to compare to.
  // @returns true if the signatures are consistent, false otherwise.
  bool IsConsistent(const Signature& signature) const;

  // Compare the specified signature with this one in the same way as
  // IsConsistent(), except that in addition signatures may differ.
  //
  // @param signature the signature to compare to.
  // @returns true if the signatures are consistent except possibly
  // for the signature, false otherwise.
  bool IsConsistentExceptForChecksum(const Signature& signature) const;

  // Compare the specified signature with this one. Signatures are
  // equal if their paths are the same and they are consistent.
  //
  // @param signature the signature to compare to.
  // @returns true if the signatures are equal, false otherwise.
  // @note We need an equality operator for serialization unittests.
  bool operator==(const Signature& signature) const;

  // Serialize this signature to @p out_archive.
  //
  // @param out_archive the archive to serialize to.
  // @returns true on success, false on error.
  bool Save(core::OutArchive* out_archive) const;

  // Deserializea a signature from @p in_archive, replacing the
  // contents of this structure.
  //
  // @param in_archive the archive to deserialize from.
  // @returns true on success, false on error.
  bool Load(core::InArchive* in_archive);
};

// A structure exposing information about a single export.
template<class ImageNtHeaders, DWORD MagicValidation>
struct PEFileBase<ImageNtHeaders, MagicValidation>::ExportInfo {
  // The address of the exported function.
  RelativeAddress function;

  // The name of the export, if any.
  std::string name;

  // The export forward string, if any.
  std::string forward;

  // The export ordinal.
  uint16 ordinal;
};

// A structure exposing information about a single import.
template<class ImageNtHeaders, DWORD MagicValidation>
struct PEFileBase<ImageNtHeaders, MagicValidation>::ImportInfo {
  // Construct an ImportInfo structure from its components.
  //
  // @param h the ordinal hint.
  // @param o the function ordinal.
  // @param n the function name.
  ImportInfo(uint16 h, uint16 o, const char* n)
      : hint(h),
        ordinal(o),
        function(n) {
  }

  // Construct an ImportInfo structure for a named function with no
  // ordinal information.
  //
  // @param function_name the function name.
  explicit ImportInfo(const char* function_name)
      : hint(0),
        ordinal(0),
        function(function_name) {
  }

  // Construct an ImportInfo structure for a function referenced by
  // ordinal.
  //
  // @param function_ordinal the function ordinal.
  explicit ImportInfo(uint16 function_ordinal)
      : hint(0),
        ordinal(function_ordinal) {
  }

  // Construct a default all-zero ImportInfo structure.
  ImportInfo() : hint(0), ordinal(0) {
  }

  // Compare the specified structure with this one. ImportInfo
  // structures are equal if their components are equal.
  //
  // @param o the structure to compare to.
  // @returns true if the signatures are equal, false otherwise.
  bool operator==(const ImportInfo& o) const {
    return hint == o.hint && ordinal == o.ordinal && function == o.function;
  }

  // The loader ordinal hint for this import.
  uint16 hint;

  // The ordinal of the function if the function field is empty.
  uint16 ordinal;

  // The name of the function, or the empty string for imports by
  // ordinal.
  std::string function;
};

// A structure holding information about all imports from a given DLL.
template<class ImageNtHeaders, DWORD MagicValidation>
struct PEFileBase<ImageNtHeaders, MagicValidation>::ImportDll {
  // Construct a default empty ImportDll structure.
  ImportDll() {
    memset(&desc, 0, sizeof(desc));
    desc.ForwarderChain = -1;
  }

  // The import descriptor.
  IMAGE_IMPORT_DESCRIPTOR desc;

  // Name of the DLL imported.
  std::string name;

  // A vector of ImportInfo structures, one for each imported
  // function.
  ImportInfoVector functions;
};

typedef PEFileBase<IMAGE_NT_HEADERS32, IMAGE_NT_OPTIONAL_HDR32_MAGIC> PEFile;

// Please note that 64-bit PE File support is only currently tested for
// manipulation of imports.
typedef PEFileBase<IMAGE_NT_HEADERS64, IMAGE_NT_OPTIONAL_HDR64_MAGIC> PEFile64;

}  // namespace pe

#include "syzygy/pe/pe_file_impl.h"

#endif  // SYZYGY_PE_PE_FILE_H_
