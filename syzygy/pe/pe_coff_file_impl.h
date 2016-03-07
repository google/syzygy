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

// Template implementation of common definitions and helper routines
// for reading both PE and COFF file formats.

#ifndef SYZYGY_PE_PE_COFF_FILE_IMPL_H_
#define SYZYGY_PE_PE_COFF_FILE_IMPL_H_

#include "base/files/file_util.h"

#include "syzygy/block_graph/block_graph.h"

namespace pe {

template <typename AddressSpaceTraits>
bool PECoffFile<AddressSpaceTraits>::Init(const base::FilePath& path) {
  path_ = path;
  // ReadFileToString doesn't like relative paths.
  if (!base::ReadFileToString(base::MakeAbsoluteFilePath(path), &image_data_))
    return false;
  parser_.SetData(image_data_.c_str(), image_data_.size());
  return true;
}

template <typename AddressSpaceTraits>
bool PECoffFile<AddressSpaceTraits>::Contains(AddressType addr,
                                              SizeType len) const {
  const ImageAddressSpace::Range range(addr, len);
  return address_space_.FindContaining(range) != address_space_.ranges().end();
}

template <typename AddressSpaceTraits>
size_t PECoffFile<AddressSpaceTraits>::GetSectionIndex(AddressType addr,
                                                       SizeType len) const {
  const ImageAddressSpace::Range range(addr, len);
  ImageAddressSpace::RangeMap::const_iterator it =
      address_space_.FindContaining(range);
  if (it == address_space_.ranges().end())
    return kInvalidSection;
  return it->second.id;
}

template <typename AddressSpaceTraits>
const IMAGE_SECTION_HEADER* PECoffFile<AddressSpaceTraits>::GetSectionHeader(
    AddressType addr, SizeType len) const {
  size_t id = GetSectionIndex(addr, len);
  if (id == kInvalidSection)
    return nullptr;
  DCHECK_LT(id, file_header_->NumberOfSections);
  return section_headers_ + id;
}

template <typename AddressSpaceTraits>
std::string PECoffFile<AddressSpaceTraits>::GetSectionName(
    const IMAGE_SECTION_HEADER& section) {
  const char* name = reinterpret_cast<const char*>(section.Name);
  return std::string(name, strnlen(name, arraysize(section.Name)));
}

template <typename AddressSpaceTraits>
std::string PECoffFile<AddressSpaceTraits>::GetSectionName(
    size_t section_index) const {
  DCHECK_LT(section_index, file_header_->NumberOfSections);

  const IMAGE_SECTION_HEADER* section = section_headers_ + section_index;
  return GetSectionName(*section);
}

template <typename AddressSpaceTraits>
bool PECoffFile<AddressSpaceTraits>::ReadCommonHeaders(
    FileOffsetAddress file_header_start) {
  // Test for unsupported object files.
  const uint16_t* obj_sig = nullptr;
  if (!parser_.GetCountAt(0, 2, &obj_sig))
    return false;
  if (obj_sig[0] == 0 && obj_sig[1] == 0xFFFF) {
    LOG(ERROR) << "Unsupported anonymous object file.";
    return false;
  }

  // Read the COFF file header.
  if (!parser_.GetAt(file_header_start.value(), &file_header_))
    return false;

  // Compute size of all headers, from the beginning of the file to
  // the end of the section table.
  FileOffsetAddress opt_header_start(file_header_start.value() +
                                     sizeof(IMAGE_FILE_HEADER));
  FileOffsetAddress section_table_start(opt_header_start +
                                        file_header_->SizeOfOptionalHeader);
  SizeType section_table_size(file_header_->NumberOfSections *
                              sizeof(IMAGE_SECTION_HEADER));
  FileOffsetAddress header_end(section_table_start + section_table_size);

  // Read the section headers.
  if (!parser_.GetCountAt(section_table_start.value(),
                          file_header_->NumberOfSections,
                          &section_headers_)) {
    return false;
  }

  SizeType header_size = header_end.value();
  if (file_header_->SizeOfOptionalHeader != 0) {
    const IMAGE_OPTIONAL_HEADER* opt_header = nullptr;
    if (!parser_.GetAt(opt_header_start.value(), &opt_header))
      return false;
    // In a sane world the stated header size will match that manually
    // calculated by walking the headers and aligning up by the file alignment.
    // However, this is not necessary for the PE file to be valid, and there may
    // be a gap between the two.
    header_size = opt_header->SizeOfHeaders;
  }

  // We now know how large the headers are, so create a range for them.
  ImageAddressSpace::Range header_range(header_address(), header_size);
  if (!InsertSection(kInvalidSection, FileOffsetAddress(0), header_size,
                     header_range)) {
    return false;
  }

  return true;
}

template <typename AddressSpaceTraits>
bool PECoffFile<AddressSpaceTraits>::ReadSections() {
  DCHECK(file_header_ != nullptr);
  DCHECK(section_headers_ != nullptr);

  size_t num_sections = file_header_->NumberOfSections;
  for (size_t i = 0; i < num_sections; ++i) {
    const IMAGE_SECTION_HEADER* hdr = section_headers_ + i;

    // Construct address in the new address space; FromSectionHeader()
    // returns header_address() if unmapped.
    AddressType addr = AddressSpaceTraits::GetSectionAddress(*hdr);

    // Ignore unmapped sections, as those, by definition, have no
    // address to map to within our address space. They need to be
    // handled separately during decomposition.
    if (addr == AddressSpaceTraits::invalid_address())
      continue;

    // Empty sections are ignored at this level of the parsing.
    size_t section_size = AddressSpaceTraits::GetSectionSize(*hdr);
    if (section_size == 0)
      continue;

    // Insert the range for the new section.
    ImageAddressSpace::Range section_range(addr, section_size);
    FileOffsetAddress off(hdr->PointerToRawData);
    if (!InsertSection(i, off, hdr->SizeOfRawData, section_range)) {
      LOG(ERROR) << "Unable to insert range for section " << hdr->Name << ".";
      return false;
    }
  }

  return true;
}

template <typename AddressSpaceTraits>
bool PECoffFile<AddressSpaceTraits>::InsertSection(
    size_t id,
    FileOffsetAddress start,
    size_t size,
    const typename ImageAddressSpace::Range& range) {
  const void* section_data = nullptr;
  if (!parser_.GetAt(start.value(), size, &section_data))
    return false;
  SectionInfo section_info(id, section_data, size);

  ImageAddressSpace::RangeMap::iterator it;
  bool inserted = address_space_.Insert(range, section_info, &it);
  if (!inserted) {
    LOG(ERROR) << "Unable to create new range in address space.";
    return false;
  }

  return true;
}

template <typename AddressSpaceTraits>
bool PECoffFile<AddressSpaceTraits>::ReadAt(size_t offset,
                                            void* destination,
                                            size_t size) const {
  // TODO(chrisha): Use BinaryBufferParser::CopyAt when that's available.
  const void* data = nullptr;
  if (!parser_.GetAt(offset, size, &data))
    return false;
  ::memcpy(destination, data, size);
  return true;
}

template <typename AddressSpaceTraits>
const uint8_t* PECoffFile<AddressSpaceTraits>::GetImageData(
    AddressType addr,
    SizeType len) const {
  ImageAddressSpace::Range range(addr, len);
  ImageAddressSpace::RangeMap::const_iterator it(
      address_space_.FindContaining(range));

  if (it == address_space_.ranges().end())
    return nullptr;

  ptrdiff_t offs = addr - it->first.start();
  DCHECK_GE(offs, 0);
  const uint8_t* data = nullptr;
  if (!it->second.parser.GetCountAt(offs, len, &data))
    return nullptr;

  return data;
}

template <typename AddressSpaceTraits>
uint8_t* PECoffFile<AddressSpaceTraits>::GetImageData(AddressType addr,
                                                      SizeType len) {
  return const_cast<uint8_t*>(
      static_cast<const PECoffFile*>(this)->GetImageData(addr, len));
}

template <typename AddressSpaceTraits>
template <typename ItemType>
bool PECoffFile<AddressSpaceTraits>::GetImageData(
    AddressType addr, SizeType len, const ItemType** item_ptr) const {
  const uint8_t* ptr = GetImageData(addr, len);
  if (ptr == nullptr)
    return false;
  *item_ptr = reinterpret_cast<const ItemType*>(ptr);
  return true;
}

template <typename AddressSpaceTraits>
template <typename ItemType>
bool PECoffFile<AddressSpaceTraits>::GetImageData(
    AddressType addr, SizeType len, ItemType** item_ptr) {
  uint8_t* ptr = GetImageData(addr, len);
  if (ptr == nullptr)
    return false;
  *item_ptr = reinterpret_cast<ItemType*>(ptr);
  return true;
}

template <typename AddressSpaceTraits>
bool PECoffFile<AddressSpaceTraits>::ReadImage(AddressType addr,
                                               void* data, SizeType len) const {
  DCHECK(data != nullptr);
  // TODO(chrisha): Make this use BinaryBufferParser::CopyAt when it's ready.
  const uint8_t* buf = GetImageData(addr, len);
  if (buf == nullptr)
    return false;
  ::memcpy(data, buf, len);
  return true;
}

template <typename AddressSpaceTraits>
bool PECoffFile<AddressSpaceTraits>::ReadImageString(AddressType addr,
                                                     std::string* str) const {
  DCHECK(file_header_ != nullptr);
  str->clear();

  // Locate the range that contains the first byte of the string.
  ImageAddressSpace::Range range(addr, 1);
  ImageAddressSpace::RangeMap::const_iterator it(
      address_space_.FindContaining(range));
  if (it == address_space_.ranges().end())
    return false;

  ptrdiff_t offs = addr - it->first.start();
  DCHECK_GE(offs, 0);
  size_t length = 0;
  const char* data = nullptr;
  if (!it->second.parser.GetStringAt(offs, &data, &length))
    return false;

  str->assign(data, length);
  return true;
}

template <typename AddressSpaceTraits>
const uint8_t* PECoffFile<AddressSpaceTraits>::GetImageDataByFileOffset(
    FileOffsetAddress addr,
    SizeType len) const {
  const uint8_t* data = nullptr;
  if (!parser_.GetCountAt(addr.value(), len, &data))
    return nullptr;
  return data;
}

}  // namespace pe

#endif  // SYZYGY_PE_PE_COFF_FILE_IMPL_H_
