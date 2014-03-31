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

namespace pe {

template <typename AddressSpaceTraits>
void PECoffFile<AddressSpaceTraits>::Init(const base::FilePath& path) {
  path_ = path;
}

template <typename AddressSpaceTraits>
bool PECoffFile<AddressSpaceTraits>::Contains(AddressType addr,
                                              SizeType len) const {
  const ImageAddressSpace::Range range(addr, len);
  return image_data_.FindContaining(range) != image_data_.ranges().end();
}

template <typename AddressSpaceTraits>
size_t PECoffFile<AddressSpaceTraits>::GetSectionIndex(AddressType addr,
                                                       SizeType len) const {
  const ImageAddressSpace::Range range(addr, len);
  ImageAddressSpace::RangeMap::const_iterator it =
      image_data_.FindContaining(range);
  if (it == image_data_.ranges().end())
    return kInvalidSection;
  return it->second.id;
}

template <typename AddressSpaceTraits>
const IMAGE_SECTION_HEADER* PECoffFile<AddressSpaceTraits>::GetSectionHeader(
    AddressType addr, SizeType len) const {
  size_t id = GetSectionIndex(addr, len);
  if (id == kInvalidSection)
    return NULL;
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
    FILE* file, FileOffsetAddress file_header_start) {
  // Test for unsupported object files.
  uint16 obj_sig[2];
  if (!ReadAt(file, 0, obj_sig, sizeof(obj_sig))) {
    LOG(ERROR) << "Unable to read first 4 bytes from object file.";
    return false;
  }
  if (obj_sig[0] == 0 && obj_sig[1] == 0xFFFF) {
    LOG(ERROR) << "Unsupported anonymous object file.";
    return false;
  }

  // Read the COFF file header.
  IMAGE_FILE_HEADER file_header = {};
  if (!ReadAt(file, file_header_start.value(),
              &file_header, sizeof(file_header))) {
    LOG(ERROR) << "Unable to read COFF file header.";
    return false;
  }

  // Compute size of all headers, from the beginning of the file to
  // the end of the section table.
  FileOffsetAddress opt_header_start(file_header_start.value() +
                                     sizeof(file_header));
  FileOffsetAddress section_table_start(opt_header_start +
                                        file_header.SizeOfOptionalHeader);
  SizeType section_table_size(
      file_header.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
  FileOffsetAddress header_end(section_table_start + section_table_size);
  SizeType header_size = header_end.value();
  if (file_header.SizeOfOptionalHeader != 0) {
    IMAGE_OPTIONAL_HEADER opt_header = {};
    if (!ReadAt(file, opt_header_start.value(),
                &opt_header, sizeof(opt_header))) {
      LOG(ERROR) << "Unable to read optional header.";
      return false;
    }
    // In a sane world the stated header size will match that manually
    // calculated by walking the headers and aligning up by the file alignment.
    // However, this is not necessary for the PE file to be valid, and there may
    // be a gap between the two.
    header_size = opt_header.SizeOfHeaders;
  }

  // We now know how large the headers are, so create a range for them.
  ImageAddressSpace::Range header_range(header_address(), header_size);
  if (!InsertRangeReadAt(file, FileOffsetAddress(0), header_size,
                         header_range)) {
    return false;
  }

  bool success = GetImageData(header_address() + file_header_start.value(),
                              SizeType(sizeof(*file_header_)),
                              &file_header_);
  DCHECK(success);
  success = GetImageData(header_address() + section_table_start.value(),
                         section_table_size,
                         &section_headers_);
  DCHECK(success);

  return success;
}

template <typename AddressSpaceTraits>
bool PECoffFile<AddressSpaceTraits>::ReadSections(FILE* file) {
  DCHECK(file_header_ != NULL);
  DCHECK(section_headers_ != NULL);

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
    ImageAddressSpace::RangeMap::iterator it;
    if (!image_data_.Insert(section_range, SectionInfo(), &it)) {
      LOG(ERROR) << "Unable to insert range for section " << hdr->Name << ".";
      return false;
    }

    it->second.id = i;
    SectionBuffer& buf = it->second.buffer;
    if (hdr->SizeOfRawData == 0)
      continue;

    buf.resize(hdr->SizeOfRawData);
    if (!ReadAt(file, hdr->PointerToRawData, &buf.at(0), hdr->SizeOfRawData)) {
      LOG(ERROR) << "Unable to read data for section " << hdr->Name << ".";
      return false;
    }
  }

  return true;
}

template <typename AddressSpaceTraits>
bool PECoffFile<AddressSpaceTraits>::InsertRangeReadAt(
    FILE* file, FileOffsetAddress start, size_t size,
    const typename ImageAddressSpace::Range& range) {
  ImageAddressSpace::RangeMap::iterator it;
  bool inserted = image_data_.Insert(range, SectionInfo(), &it);
  if (!inserted) {
    LOG(ERROR) << "Unable to create new range in address space.";
    return false;
  }

  SectionBuffer& buffer = it->second.buffer;
  buffer.resize(size);
  if (!ReadAt(file, start.value(), &buffer[0], size)) {
    LOG(ERROR) << "Unable to file data.";
    return false;
  }

  return true;
}

template <typename AddressSpaceTraits>
bool PECoffFile<AddressSpaceTraits>::ReadAt(FILE* file, size_t pos,
                                            void* buf, size_t len) {
  if (fseek(file, pos, SEEK_SET) != 0)
    return false;

  size_t read = fread(buf, 1, len, file);
  if (read != len)
    return false;

  return true;
}

template <typename AddressSpaceTraits>
const uint8* PECoffFile<AddressSpaceTraits>::GetImageData(AddressType addr,
                                                          SizeType len) const {
  ImageAddressSpace::Range range(addr, len);
  ImageAddressSpace::RangeMap::const_iterator it(
      image_data_.FindContaining(range));

  if (it != image_data_.ranges().end()) {
    ptrdiff_t offs = addr - it->first.start();
    DCHECK_GE(offs, 0);

    const SectionBuffer& buf = it->second.buffer;
    if (offs + len <= buf.size())
      return &buf.at(offs);
  }

  return NULL;
}

template <typename AddressSpaceTraits>
uint8* PECoffFile<AddressSpaceTraits>::GetImageData(AddressType addr,
                                                    SizeType len) {
  return const_cast<uint8*>(
      static_cast<const PECoffFile*>(this)->GetImageData(addr, len));
}

template <typename AddressSpaceTraits>
template <typename ItemType>
bool PECoffFile<AddressSpaceTraits>::GetImageData(
    AddressType addr, SizeType len, const ItemType** item_ptr) const {
  const uint8* ptr = GetImageData(addr, len);
  if (ptr == NULL)
    return false;
  *item_ptr = reinterpret_cast<const ItemType*>(ptr);
  return true;
}

template <typename AddressSpaceTraits>
template <typename ItemType>
bool PECoffFile<AddressSpaceTraits>::GetImageData(
    AddressType addr, SizeType len, ItemType** item_ptr) {
  uint8* ptr = GetImageData(addr, len);
  if (ptr == NULL)
    return false;
  *item_ptr = reinterpret_cast<ItemType*>(ptr);
  return true;
}

template <typename AddressSpaceTraits>
bool PECoffFile<AddressSpaceTraits>::ReadImage(AddressType addr,
                                               void* data, SizeType len) const {
  DCHECK(data != NULL);
  const uint8* buf = GetImageData(addr, len);
  if (buf == NULL)
    return false;

  memcpy(data, buf, len);
  return true;
}

template <typename AddressSpaceTraits>
bool PECoffFile<AddressSpaceTraits>::ReadImageString(AddressType addr,
                                                     std::string* str) const {
  DCHECK(file_header_ != NULL);
  str->clear();

  // Locate the range that contains the first byte of the string.
  ImageAddressSpace::Range range(addr, 1);
  ImageAddressSpace::RangeMap::const_iterator it(
      image_data_.FindContaining(range));

  if (it != image_data_.ranges().end()) {
    ptrdiff_t offs = addr - it->first.start();
    DCHECK_GE(offs, 0);
    // Stash the start position.
    const SectionBuffer& buf = it->second.buffer;
    const char* begin = reinterpret_cast<const char*>(&buf.at(offs));
    // And loop through until we find a zero-terminating byte,
    // or run off the end.
    for (; static_cast<size_t>(offs) < buf.size() && buf.at(offs); ++offs) {
      // Intentionally empty.
    }

    if (static_cast<size_t>(offs) == buf.size())
      return false;

    str->assign(begin);
    return true;
  }

  return false;
}

}  // namespace  pe

#endif  // SYZYGY_PE_PE_COFF_FILE_IMPL_H_
