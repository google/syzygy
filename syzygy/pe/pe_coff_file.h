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

// Common definitions and helper routines for reading both PE and COFF
// file formats.

#ifndef SYZYGY_PE_PE_COFF_FILE_H_
#define SYZYGY_PE_PE_COFF_FILE_H_

#include <windows.h>
#include <winnt.h>
#include <map>
#include <string>
#include <vector>

#include "base/files/file_path.h"
#include "syzygy/core/address.h"
#include "syzygy/core/address_space.h"
#include "syzygy/core/serialization.h"

namespace pe {

// This duplicates a similar constant in the core namespace, declared by
// block_graph.h. We duplicate it here so as not to add an uneccessary
// dependency.
// Header data and other data not from a regular section is considered as
// being from an invalid section.
const size_t kInvalidSection = -1;

// Base class for PE and COFF file readers, parameterized with an
// address and a size type, wrapped in a traits class. The base class
// defines an address space, in which data ranges from the input file
// should be mapped. The template address and size types define the
// resulting address space.
//
// PECoffFile observes the following address range separation rules:
// - All headers live in a single range.
// - Each section lives in its own data range.
// - Other data may be added by child classes, and live in ranges
//   different from the above.
//
// The address traits class @p AddressSpaceTraits should define the
// following members:
//
// @code
// struct AddressSpaceTraits {
//   // The type of addresses native to the address space of the reader.
//   typedef ... AddressType;
//   // The type of sizes native to the address space of the reader.
//   typedef ... SizeType;
//
//   // Return an address different from all valid addresses for the
//   // specified address type.
//   static const AddressType invalid_address();
//
//   // Return the address at which to insert global headers.
//   static const AddressType header_address();
//
//   // Return the address where the corresponding section should be
//   // mapped, or invalid_address() if the section should not be mapped.
//   static AddressType GetSectionAddress(const IMAGE_SECTION_HEADER& header);
//
//   // Return the number of bytes of the corresponding section to map
//   // to the resulting address space.
//   static SizeType GetSectionSize(const IMAGE_SECTION_HEADER& header);
// };
// @endcode
//
// @tparam AddressSpaceTraits traits describing the types of the
// resulting address map.
// address map.
template <typename AddressSpaceTraits>
class PECoffFile {
 public:
  // The type of addresses native to this reader.
  typedef typename AddressSpaceTraits::AddressType AddressType;

  // The type of sizes native to this reader.
  typedef typename AddressSpaceTraits::SizeType SizeType;

  // The type of addresses referring to the on-disk file.
  typedef core::FileOffsetAddress FileOffsetAddress;

  // Return the address where the header is expected to be found,
  // after a successful call to Init().
  //
  // @returns the address of the header range.
  static AddressType header_address() {
    return AddressSpaceTraits::header_address();
  }

  // @returns the path of the input file read, if any.
  const base::FilePath& path() const { return path_; }

  // Copy mapped data to buffer. The specified range to read must be
  // contained within the image, and cannot cross data ranges from the
  // original file; in particular, sections with no gaps between them
  // must still be read separately.
  //
  // @param addr the address where the data is mapped.
  // @param data the buffer to write the data to.
  // @param len the number of bytes to copy.
  // @returns true on success, false on error.
  bool ReadImage(AddressType addr, void* data, SizeType len) const;

  // Copy mapped zero-terminated string data to string object.
  //
  // @param addr the address where the data is mapped.
  // @param str the string to write the data to.
  // @returns true on success, false on error.
  bool ReadImageString(AddressType addr, std::string* str) const;

  // Retrieve a pointer to the internal buffer containing mapped
  // data. The specified range to read must be contained within the
  // image, and cannot cross data ranges from the original file; in
  // particular, sections with no gaps between them must still be read
  // separately.
  //
  // @param addr the address where the data is mapped.
  // @param len the number of bytes that will be accessed through the
  // returned pointer.
  // @returns a pointer into the internal buffer for the data.
  const uint8* GetImageData(AddressType addr, SizeType len) const;

  // @copydoc GetImageData(AddressType,SizeType)
  // The resulting buffer is mutable.
  uint8* GetImageData(AddressType addr, SizeType len);

  // Retrieve a pointer to the internal buffer containing mapped
  // data assumed to be of type @p ItemType.
  //
  // @tparam ItemType the type of items to cast to.
  // @param addr the address where the data is mapped.
  // @param len the number of bytes that will be accessed through the
  // returned pointer.
  // @param item_ptr a pointer to the retrieved result.
  // @returns true on success, false on error.
  // @see GetImageData(AddressType,SizeType)
  template <typename ItemType> bool GetImageData(
      AddressType addr, SizeType len, const ItemType** item_ptr) const;

  // @copydoc GetImageData()
  // The resulting buffer is mutable.
  template <typename ItemType> bool GetImageData(
      AddressType addr, SizeType len, ItemType** item_ptr);

  // Test whether an address range is entirely mapped.
  //
  // @param addr the start of the address range.
  // @param len the length of the address range.
  // @returns true if the range is mapped, false otherwise.
  bool Contains(AddressType addr, SizeType len) const;

  // Retrieve the index of the section containing the specified range.
  //
  // @param addr the start of the address range.
  // @param len the length of the address range.
  // @returns the section index, or kInvalidSection if none is found.
  size_t GetSectionIndex(AddressType addr, SizeType len) const;

  // Retrieve the section header structure of the section containing
  // the specified range.
  //
  // @param addr the start of the address range.
  // @param len the length of the address range.
  // @returns the section header, or NULL if none is found.
  const IMAGE_SECTION_HEADER* GetSectionHeader(AddressType addr,
                                               SizeType len) const;

  // Retrieve the short name of a section from its index.
  //
  // @param section_index the index of the section.
  // @returns the name of the section.
  std::string GetSectionName(size_t section_index) const;

  // Read the short name embedded in @p section.
  //
  // @param section the section header to read.
  // @returns the short name of the section.
  static std::string GetSectionName(const IMAGE_SECTION_HEADER& section);

  // @returns the COFF file header.
  const IMAGE_FILE_HEADER* file_header() const {
    return file_header_;
  }

  // @returns an array of all section headers.
  // @note Use in combination with the NumberOfSections field of the
  // COFF file header.
  const IMAGE_SECTION_HEADER* section_headers() const {
    return section_headers_;
  }

  // Retrieve the section header structure of a section from its index.
  //
  // @param num_section the index of the section.
  // @returns a pointer to the header structure.
  const IMAGE_SECTION_HEADER* section_header(size_t num_section) const {
    if (file_header_ != NULL && num_section < file_header_->NumberOfSections)
      return section_headers_ + num_section;
    return NULL;
  }

 protected:
  typedef std::vector<uint8> SectionBuffer;

  struct SectionInfo {
    SectionInfo() : id(kInvalidSection) {
    }
    size_t id;
    SectionBuffer buffer;
  };

  typedef core::AddressSpace<AddressType, SizeType, SectionInfo>
      ImageAddressSpace;

  // Protected constructor, for derived classes only.
  PECoffFile()
      : file_header_(NULL),
        section_headers_(NULL) {
  }

  ~PECoffFile() {
  }

  // Set the file path.
  //
  // @param path the path to the input file.
  void Init(const base::FilePath& path);

  // Read headers common to both PE and COFF. Insert a range covering
  // all headers, including unread headers; the range spans from the
  // beginning of the file to the end of the known fixed headers (the
  // section table).
  //
  // @param file the input file stream.
  // @param file_header_start the offset where the COFF file header
  // (IMAGE_FILE_HEADER) starts.
  // @returns true on success, false on error.
  bool ReadCommonHeaders(FILE* file, FileOffsetAddress file_header_start);

  // Read section headers and insert a range for each section.
  //
  // @param file the input file stream.
  // @returns true on success, false on error.
  bool ReadSections(FILE* file);

  // Insert a range into the address map, populated by data read from
  // @p file.
  //
  // @param file the input file stream.
  // @param start the file offset to start reading at.
  // @param size the number of bytes to read.
  // @param range the range to insert.
  // @returns true on success, false on error.
  bool InsertRangeReadAt(FILE* file, FileOffsetAddress start, size_t size,
                         const typename ImageAddressSpace::Range& range);

  // Read bytes from @p file into the specified buffer.
  //
  // @param file the input file stream.
  // @param pos the file offset to start reading at.
  // @param buf the buffer where to place data.
  // @param len the number of bytes to read.
  static bool ReadAt(FILE* file, size_t pos, void* buf, size_t len);

  base::FilePath path_;
  const IMAGE_FILE_HEADER* file_header_;
  const IMAGE_SECTION_HEADER* section_headers_;

  // Contains all data in the image. The address space has a range defined
  // for the header and each section in the image, with its associated
  // SectionBuffer as the data.
  ImageAddressSpace image_data_;

 private:
  DISALLOW_COPY_AND_ASSIGN(PECoffFile);
};

}  // namespace pe

#include "syzygy/pe/pe_coff_file_impl.h"

#endif  // SYZYGY_PE_PE_COFF_FILE_H_
