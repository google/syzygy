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
#ifndef SAWBUCK_CALL_TRACE_PE_IMAGE_FILE_H_
#define SAWBUCK_CALL_TRACE_PE_IMAGE_FILE_H_

#include <windows.h>
#include <winnt.h>
#include <delayimp.h>
#include <map>
#include <set>

#include "base/file_path.h"

// Represents a PE image.
// This class allows reading an image from disk, mutating it in memory,
// in various ways, while maintaining the image self-consistent, and
// ultimately writing a new, mutated image back to disk.
class PEImageFile {
 public:
  enum AddressType {
    kRelativeAddressType,
    kAbsoluteAddressType,
    kFileOffsetAddressType,
  };

  // Forward declaration.
  template <AddressType type> class AddressImpl;
  template <AddressType type> class AddressRefImpl;

  // These types represent the different addressing formats used in PE images.
  // A virtual address relative to the image base, often termed
  // RVA in documentation and in data structure comments.
  typedef AddressImpl<kRelativeAddressType> RelativeAddress;
  // An absolute address.
  typedef AddressImpl<kAbsoluteAddressType> AbsoluteAddress;
  // A disk offset within the image file.
  typedef AddressImpl<kFileOffsetAddressType> FileOffsetAddress;

  // These types are used when translating addresses residing in
  // a PE image structure.
  typedef AddressRefImpl<kRelativeAddressType> Relative;
  typedef AddressRefImpl<kAbsoluteAddressType> Absolute;
  typedef AddressRefImpl<kFileOffsetAddressType> FileOffset;

  // Forward declaration.
  class AddressTransformer;

  PEImageFile();
  ~PEImageFile();

  // Read in the image file at path.
  bool Read(const FilePath& path);

  // Write the image file to path.
  bool Write(const FilePath& path);

  // Contains relocation addresses.
  typedef std::set<RelativeAddress> RelocSet;

  // Decodes the relocation information from the image to relocs.
  bool DecodeRelocSection(RelocSet* relocs) const;
  // Writes a relocation section, resizes the image to suit.
  bool WriteRelocSection(const RelocSet& relocs);

  // Contains the decoded relocation information, where each item
  // in the map is the address and value of a relocatable entry.
  typedef std::map<RelativeAddress, AbsoluteAddress> RelocMap;

  // Reads all reloc values from the image.
  bool ReadRelocs(const RelocSet& relocs, RelocMap* reloc_values);
  // Write the information from relocs to the image.
  bool WriteRelocs(const RelocMap& relocs);

  // Rebases the image to new_base.
  bool RebaseImage(uint8 new_base);

  // Information about a single import.
  struct ImportInfo {
    explicit ImportInfo(const char* function_name)
        : hint(0), function(function_name) {
    }
    ImportInfo() : hint(0) {
    }

    // The loader ordinal hint for this import.
    uint16 hint;
    // Name of the function or #ordinal.
    std::string function;
  };
  typedef std::vector<ImportInfo> ImportInfoVector;

  // Information about all imports for a given DLL.
  struct ImportDll {
    ImportDll() {
      memset(&desc, 0, sizeof(desc));
      desc.ForwarderChain = -1;
    }

    // The import descriptor.
    IMAGE_IMPORT_DESCRIPTOR desc;

    // Name of the DLL imported.
    std::string name;

    // One entry for each imported function.
    ImportInfoVector imports;
  };

  typedef std::vector<ImportDll> ImportDllVector;
  bool DecodeImportSection(ImportDllVector* imports);

  // Translate between relative and absolute addresses.
  bool Translate(RelativeAddress in, AbsoluteAddress* out) const;
  bool Translate(AbsoluteAddress in, RelativeAddress* out) const;

  // Writes imports to a new imports table. Grows the image as necessary.
  bool WriteImportSection(ImportDllVector* imports);

  // Read len bytes from image at offset offs to data.
  bool ReadImage(RelativeAddress addr, void* data, size_t len) const;
  bool ReadImage(AbsoluteAddress addr, void* data, size_t len) const;

  // Read a zero-terminated string from offs into str.
  bool ReadImageString(RelativeAddress addr, std::string* str) const;
  bool ReadImageString(AbsoluteAddress addr, std::string* str) const;

  // Write len bytes from data to offs.
  bool WriteImage(RelativeAddress addr, const void* data, size_t len);
  bool WriteImage(AbsoluteAddress addr, const void* data, size_t len);

  // Get a pointer to the image at addr, provided the image contains data
  // for [addr, addr + len]
  const uint8* GetImageData(RelativeAddress addr, size_t len) const;
  const uint8* GetImageData(AbsoluteAddress addr, size_t len) const;
  uint8* GetImageData(RelativeAddress addr, size_t len);
  uint8* GetImageData(AbsoluteAddress addr, size_t len);

  // Resize section_no to new_size, which must be larger than the current size.
  // Note: This will grow the section data in the image and zero-fill the new
  //      backing data.
  bool ResizeSection(size_t section_no, uint32 new_size);

  typedef std::vector<uint8> SectionBuffer;
  typedef std::vector<SectionBuffer> SectionBufferVector;

  static const size_t kNoSection = -1;

  // Locate section for an RVA.
  size_t FindSectionForOffset(RelativeAddress offs) const;
  size_t FindSectionForOffset(AbsoluteAddress offs) const;

  // Locate section with all attrib.
  size_t FindSectionWithAttributes(DWORD attrib) const;

  // Accessors.
  IMAGE_DOS_HEADER* dos_header() const {
    return dos_header_;
  }

  IMAGE_NT_HEADERS* nt_headers() const {
    return nt_headers_;
  }

  IMAGE_SECTION_HEADER* section_headers() const {
    return section_headers_;
  }

  const SectionBufferVector& sections() const {
    return sections_;
  }

 private:
  bool ReadHeaders(FILE* file);
  bool ReadSections(FILE* file);
  bool WriteHeaders(FILE* file);
  bool WriteSections(FILE* file);

  // Fixup functions. Each of these rights a section after one or
  // more module sections have been moved, as per transformer.
  bool FixupExports(const AddressTransformer& transformer);
  bool FixupImports(const AddressTransformer& transformer);
  bool FixupResourceDirectory(const AddressTransformer& transformer,
                              RelativeAddress resource_base,
                              RelativeAddress directory);
  bool FixupResourceDirectory(const AddressTransformer& transformer);
  bool FixupRelocations(const AddressTransformer& transformer);
  bool FixupDebugDirectory(const AddressTransformer& transformer);
  bool FixupImportThunks(const AddressTransformer& transformer,
                         RelativeAddress thunk);
  bool FixupTls(const AddressTransformer& transformer);
  bool FixupLoadConfig(const AddressTransformer& transformer);
  bool FixupDelayImports(const AddressTransformer& transformer);
  bool FixupBoundImports(const AddressTransformer& transformer);

  IMAGE_DOS_HEADER* dos_header_;
  IMAGE_NT_HEADERS* nt_headers_;
  IMAGE_SECTION_HEADER* section_headers_;

  // Contains the header data, dos_headers_, nt_headers_ and
  // section_headers_ point into this buffer.
  SectionBuffer header_;

  // Contains one SectionBuffer entry for each section.
  SectionBufferVector sections_;

  DISALLOW_COPY_AND_ASSIGN(PEImageFile);
};

// This class implements an address in a PE image file.
// Addresses are of three varieties:
// - Relative addresses are relative to the base of the image, and thus do not
//   change when the image is relocated. Bulk of the addresses in the PE image
//   format itself are of this variety, and that's where relative addresses
//   crop up most frequently.
// - Absolute addresses are as the name indicates absolute, and those change
//   when an image is relocated. Absolute addresses mostly occur in initialized
//   data, and for each absolute datum in an image file, there will be a
//   relocation entry calling out its location in the image.
// - File offset addresses occur only in the debug data directory that I'm
//   aware of, where the debug data is referred to both by a relative address
//   and (presumably for convenience) by a file offset address.
// This class is a lightweight wrapper for an integer, which can be freely
// copied. The different address types are deliberately assignment
// incompatible, which helps avoding mistakes in implementation.
template <PEImageFile::AddressType type>
class PEImageFile::AddressImpl {
 public:
  AddressImpl() : value_(0) {
  }
  explicit AddressImpl(uint32 value) : value_(value) {
  }
  AddressImpl(const AddressImpl<type>& other)  // NOLINT
      : value_(other.value_) {
  }

  bool operator<(const AddressImpl<type>& other) const {
    return value_ < other.value_;
  }
  bool operator>=(const AddressImpl<type>& other) const {
    return value_ >= other.value_;
  }

  bool operator==(const AddressImpl<type>& other) const {
    return value_ == other.value_;
  }
  bool operator!=(const AddressImpl<type>& other) const {
    return value_ != other.value_;
  }

  void operator=(const AddressImpl<type>& other) {
    value_ = other.value_;
  }
  void operator+=(size_t offset) {
    value_ += offset;
  }

  AddressImpl<type> operator+(size_t offset) const {
    return AddressImpl<type>(value() + offset);
  }

  size_t operator-(const AddressImpl<type>& other) const {
    return value_ - other.value_;
  }

  uint32 value() const { return value_; }
  void set_value(uint32 value) {
    value_ = value;
  }

 private:
  uint32 value_;
};

// This class wraps a pointer to a typed address field in a PE image.
// The field is declared as one of the PE Image address types we deal in, by
// virtue of being wrapped in one of those instances.
// Example usage:
//   IMAGE_DEBUG_DIRECTORY debug_dir = {};
//    transformer.Transform(&Relative(debug_dir.AddressOfRawData));
//    mover.Transform(&FileOffset(debug_dir.PointerToRawData));
template <PEImageFile::AddressType type>
class PEImageFile::AddressRefImpl {
 public:
  template <class T> AddressRefImpl(T& value)
      : ptr_(reinterpret_cast<uint32*>(&value)) {
    COMPILE_ASSERT(sizeof(value) == sizeof(uint32),
        address_ref_values_must_be_4_byte);
  }

  uint32* ptr() const { return ptr_; }

 private:
  uint32* ptr_;
};

// An address transformer can, given the state of an image file pre-mutation
// and the state post-mutation, compute the post-mutation address for any
// address read from the image file pre-mutation.
// Mutation here means either resizing one ore more image sections or changing
// the image base address (or both). This class specifically cannot cope with
// mutations that reorder image sections or such.
class PEImageFile::AddressTransformer {
 public:
  // Creates an uninitialized address transformer.
  AddressTransformer();

  // Copies the original image information.
  void SetOriginalImageFile(const PEImageFile& old_image);

  // Copies the new image information and completes initialization.
  // Returns true iff the new image is homogenous with the new image, e.g.
  // it has the same number of image sections, and the sections are
  // in the same order.
  bool SetNewImageFile(const PEImageFile& new_image);

  // Transforms a single address, returns true iff the address changed.
  // Note: it's a programming error to relocate addresses before
  //    the instance is initialized.
  bool Transform(AbsoluteAddress* addr) const;
  bool Transform(RelativeAddress* addr) const;
  bool Transform(FileOffsetAddress* addr) const;

  // Transforms a single address, passed by reference to a structure.
  bool Transform(Relative* addr_ref) const;
  bool Transform(Absolute* addr_ref) const;
  bool Transform(FileOffset* addr_ref) const;

  bool initialized() const { return initialized_; }

 private:
  typedef std::vector<IMAGE_SECTION_HEADER> HeaderVector;
  bool initialized_;
  AbsoluteAddress original_image_base_;
  HeaderVector original_section_headers_;

  AbsoluteAddress new_image_base_;
  HeaderVector new_section_headers_;
};

#endif  // SAWBUCK_CALL_TRACE_PE_IMAGE_FILE_H_
