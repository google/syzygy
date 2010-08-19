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
#include "sawbuck/call_trace/pe_image_file.h"
#include "base/file_util.h"
#include "base/logging.h"
#include "base/pe_image.h"
#include "base/string_util.h"

namespace {

COMPILE_ASSERT(sizeof(PEImageFile::RelativeAddress) == sizeof(uint32),
               relative_address_must_be_4_byte);
COMPILE_ASSERT(sizeof(PEImageFile::AbsoluteAddress) == sizeof(uint32),
               absolute_address_must_be_4_byte);
COMPILE_ASSERT(sizeof(PEImageFile::FileOffsetAddress) == sizeof(uint32),
               file_offset_must_be_4_byte);

const uint32 kPageShift = 12;
const uint32 kPageSize = 1 << kPageShift;
const uint32 kPageMask = kPageSize - 1;

// Return the smallest multiple of m which is >= x.
// Note: m must be a power of two.
uint32 RoundUp(uint32 x, uint32 m) {
  return (x + m - 1) & ~(m - 1);
}

// Returns size_or_offset rounded up to neareast page size.
uint32 PageRoundUp(uint32 size_or_offset) {
  return RoundUp(size_or_offset, kPageSize);
}

uint32 PageRoundDown(uint32 size_or_offset) {
  return size_or_offset & ~kPageMask;
}

bool WriteAt(FILE* file, size_t pos, void* buf, size_t len) {
  if (fseek(file, pos, SEEK_SET) != 0)
    return false;

  size_t written = fwrite(buf, 1, len, file);
  if (written != len)
    return false;

  return true;
}

bool ReadAt(FILE* file, size_t pos, void* buf, size_t len) {
  if (fseek(file, pos, SEEK_SET) != 0)
    return false;

  size_t read = fread(buf, 1, len, file);
  if (read != len)
    return false;

  return true;
}

// Find a section by relative address.
const IMAGE_SECTION_HEADER* FindSection(
    PEImageFile::RelativeAddress addr,
    const IMAGE_SECTION_HEADER* section_headers,
    size_t num_sections) {
  for (size_t i = 0; i != num_sections; ++i) {
    const IMAGE_SECTION_HEADER& header = section_headers[i];
    if (addr.value() >= header.VirtualAddress &&
        addr.value() < header.VirtualAddress + header.Misc.VirtualSize)
      return section_headers + i;
  }

  return NULL;
}

// Find a section by file offset address.
const IMAGE_SECTION_HEADER* FindSection(
    PEImageFile::FileOffsetAddress addr,
    const IMAGE_SECTION_HEADER* section_headers,
    size_t num_sections) {
  for (size_t i = 0; i != num_sections; ++i) {
    const IMAGE_SECTION_HEADER& header = section_headers[i];
    if (addr.value() >= header.PointerToRawData &&
        addr.value() < header.PointerToRawData + header.SizeOfRawData)
      return section_headers + i;
  }

  return NULL;
}

}  // namespace


PEImageFile::AddressTransformer::AddressTransformer()
    : initialized_(false) {
}

void PEImageFile::AddressTransformer::SetOriginalImageFile(
    const PEImageFile& original_image) {
  DCHECK(!initialized_);
  // Copy the image base and section headers from the image.
  original_image_base_.set_value(
      original_image.nt_headers()->OptionalHeader.ImageBase);
  size_t num_sections =
      original_image.nt_headers()->FileHeader.NumberOfSections;

  original_section_headers_.assign(
      original_image.section_headers(),
      original_image.section_headers() + num_sections);
}

bool PEImageFile::AddressTransformer::SetNewImageFile(
    const PEImageFile& new_image) {
  DCHECK(!initialized_);

  size_t num_sections = new_image.nt_headers()->FileHeader.NumberOfSections;
  if (original_section_headers_.size() != num_sections)
    return false;
  // TODO(siggi): verify that the images are homogenous.

  new_image_base_.set_value(
      new_image.nt_headers()->OptionalHeader.ImageBase);
  new_section_headers_.assign(new_image.section_headers(),
                              new_image.section_headers() + num_sections);

  initialized_ = true;

  return true;
}

bool PEImageFile::AddressTransformer::Transform(RelativeAddress* addr) const {
  DCHECK(initialized_);
  DCHECK(addr != NULL);

  // Check for the zero relative address as a special case.
  // This address can never move, and occurs frequently in
  // unused RVA fields.
  if (addr->value() == 0)
    return false;

  const IMAGE_SECTION_HEADER* original_section_header =
      FindSection(*addr,
                  &original_section_headers_[0],
                  original_section_headers_.size());

  if (original_section_header == NULL) {
    DCHECK(false) << "addr is outside the image sections.";
    return false;
  }

  size_t section_no = original_section_header - &original_section_headers_[0];
  const IMAGE_SECTION_HEADER* new_section_header =
      &new_section_headers_[section_no];

  if (original_section_header->VirtualAddress ==
      new_section_header->VirtualAddress) {
    return false;
  }

  addr->set_value(addr->value() -
      original_section_header->VirtualAddress +
      new_section_header->VirtualAddress);

  return true;
}

bool PEImageFile::AddressTransformer::Transform(AbsoluteAddress* addr) const {
  DCHECK(initialized_);
  DCHECK(addr != NULL);

  // Never try and offset and translate NULL.
  if (addr->value() == 0)
    return false;

  RelativeAddress relative_addr(addr->value() - original_image_base_.value());
  if (!Transform(&relative_addr) &&
      original_image_base_ == new_image_base_)
    return false;

  addr->set_value(relative_addr.value() + new_image_base_.value());
  return true;
}

bool PEImageFile::AddressTransformer::Transform(
    FileOffsetAddress* addr) const {
  DCHECK(initialized_);
  DCHECK(addr != NULL);

  const IMAGE_SECTION_HEADER* original_section_header =
      FindSection(*addr,
                  &original_section_headers_[0],
                  original_section_headers_.size());

  if (original_section_header == NULL) {
    DCHECK(false) << "addr is outside the image sections.";
    return false;
  }

  size_t section_no = original_section_header - &original_section_headers_[0];
  const IMAGE_SECTION_HEADER* new_section_header =
      &new_section_headers_[section_no];

  if (original_section_header->PointerToRawData ==
      new_section_header->PointerToRawData) {
    return false;
  }

  addr->set_value(addr->value() -
      original_section_header->PointerToRawData +
      new_section_header->PointerToRawData);

  return true;
}

namespace {
template <class AddressType, class AddressRefType>
bool TranslateImpl(const PEImageFile::AddressTransformer* transformer,
                  AddressRefType* addr_ref) {
  AddressType addr(*addr_ref->ptr());
  if (!transformer->Transform(&addr))
    return false;

  *addr_ref->ptr() = addr.value();

  return true;
}

}  // namespace


bool PEImageFile::AddressTransformer::Transform(Relative* addr_ref) const {
  return TranslateImpl<RelativeAddress, Relative>(this, addr_ref);
}

bool PEImageFile::AddressTransformer::Transform(Absolute* addr_ref) const {
  return TranslateImpl<AbsoluteAddress, Absolute>(this, addr_ref);
}

bool PEImageFile::AddressTransformer::Transform(FileOffset* addr_ref) const {
  return TranslateImpl<FileOffsetAddress, FileOffset>(this, addr_ref);
}

PEImageFile::PEImageFile() : dos_header_(NULL), nt_headers_(NULL),
  section_headers_(NULL) {
}

PEImageFile::~PEImageFile() {
}

bool PEImageFile::Read(const FilePath& path) {
  FILE* file = file_util::OpenFile(path, "rb");
  if (file == NULL)
    return false;

  bool success = ReadHeaders(file) && ReadSections(file);

  file_util::CloseFile(file);

  return success;
}

bool PEImageFile::Write(const FilePath& path) {
  FILE* file = file_util::OpenFile(path, "wb");
  if (file == NULL)
    return false;

  bool success = WriteHeaders(file) && WriteSections(file);

  file_util::CloseFile(file);

  return success;
}

bool PEImageFile::WriteHeaders(FILE* file) {
  if (!WriteAt(file, 0, &header_[0], header_.size()))
    return false;

  return true;
}

bool PEImageFile::WriteSections(FILE* file) {
  for (size_t i = 0; i < sections_.size(); ++i) {
    if (!WriteAt(file,
                 section_headers_[i].PointerToRawData,
                 &sections_[i][0],
                 sections_[i].size())) {
      return false;
    }
  }

  return true;
}

bool PEImageFile::ReadHeaders(FILE* file) {
  DCHECK_EQ(0U, header_.size());

  // Read the DOS header.
  IMAGE_DOS_HEADER dos_header = {};
  if (!ReadAt(file, 0, &dos_header, sizeof(dos_header)))
    return false;

  // And the NT headers.
  IMAGE_NT_HEADERS nt_headers = {};
  size_t pos = dos_header.e_lfanew;
  if (!ReadAt(file, pos, &nt_headers, sizeof(nt_headers)))
    return false;

  // We now know how large the headers are, so read them all.
  header_.resize(nt_headers.OptionalHeader.SizeOfHeaders);
  if (!ReadAt(file, 0, &header_[0], header_.size()))
    return false;

  dos_header_ = reinterpret_cast<IMAGE_DOS_HEADER*>(&header_[0]);
  nt_headers_ =
      reinterpret_cast<IMAGE_NT_HEADERS*>(&header_[dos_header_->e_lfanew]);
  section_headers_ = IMAGE_FIRST_SECTION(nt_headers_);

  return true;
}

bool PEImageFile::ReadSections(FILE* file) {
  DCHECK(section_headers_ != NULL);
  DCHECK(sections_.empty());

  std::vector<SectionBuffer> sections;
  for (size_t i = 0; i < nt_headers_->FileHeader.NumberOfSections; ++i) {
    sections.push_back(SectionBuffer());
    SectionBuffer& buf = sections.back();
    IMAGE_SECTION_HEADER* hdr = section_headers_ + i;
    buf.resize(hdr->SizeOfRawData);
    if (!ReadAt(file, hdr->PointerToRawData, &buf[0], hdr->SizeOfRawData))
      return false;
  }

  sections_.swap(sections);
  return true;
}

// TODO(siggi): Perhaps break relocs out to a separate class.
// Contains the decoded relocation information, where each item
// in the map is the address and value of a relocatable entry.
bool PEImageFile::DecodeRelocSection(RelocSet* relocs) const {
  DCHECK(relocs != NULL);

  // Walk the relocs.
  IMAGE_DATA_DIRECTORY dir = nt_headers_->OptionalHeader.
      DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
  RelativeAddress offs(dir.VirtualAddress);
  RelativeAddress end(offs + dir.Size);

  IMAGE_BASE_RELOCATION hdr = {};
  for (; offs < end; offs += hdr.SizeOfBlock) {
    // Read the header.
    if (!ReadImage(offs, &hdr, sizeof(hdr)))
      return false;

    // Read the entries.
    size_t num_relocs = (hdr.SizeOfBlock - sizeof(hdr)) / sizeof(WORD);
    std::vector<WORD> reloc_block(num_relocs);
    if (!ReadImage(offs + sizeof(hdr),
                   &reloc_block[0],
                   hdr.SizeOfBlock - sizeof(hdr))) {
      return false;
    }

    // Walk the entries.
    for (size_t i = 0; i < num_relocs; ++i) {
      uint8 type = reloc_block[i] >> 12;
      uint16 offs = reloc_block[i] & 0xFFF;
      DCHECK(type == IMAGE_REL_BASED_HIGHLOW ||
          type == IMAGE_REL_BASED_ABSOLUTE);

      if (type == IMAGE_REL_BASED_HIGHLOW) {
        // Record the entry.
        relocs->insert(RelativeAddress(hdr.VirtualAddress + offs));
      }
    }
  }

  return true;
}

namespace {

size_t CalculateRelocSectionSize(const PEImageFile::RelocSet& relocs) {
  // The size of the transformer entries is:
  // -  a word for each entry, plus
  // - a header for every page named.
  PEImageFile::RelocSet::const_iterator it(relocs.begin());
  PEImageFile::RelativeAddress page;
  size_t size = 0;
  for (; it != relocs.end(); ++it) {
    PEImageFile::RelativeAddress rounded(PageRoundUp(it->value()));
    if (*it != page) {
      page = rounded;
      size += sizeof(IMAGE_BASE_RELOCATION);
    }

    size += sizeof(WORD);
  }

  return size;
}

}  // namespace

bool PEImageFile::WriteRelocSection(const RelocSet& relocs) {
  IMAGE_DATA_DIRECTORY& dir = nt_headers_->OptionalHeader.
      DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
  RelativeAddress offs(dir.VirtualAddress);
  RelativeAddress end(offs + dir.Size);

  size_t section_no = FindSectionForOffset(offs);
  if (section_no == kNoSection)
    return false;

  size_t new_size = CalculateRelocSectionSize(relocs);
  IMAGE_SECTION_HEADER hdr = section_headers_[section_no];

  // Two cases:
  //  - either the current reloc entries go right to the end of the section,
  //    in which case we overwrite them and extend the section as
  //    necessary. This is the image format we see MSVS generate.
  //  - or else we append the reloc entries to the current section,
  //    as we don't want to bother with trying to relocate such a reloc
  //    section tail.
  RelativeAddress start_offs;
  RelativeAddress section_end(hdr.VirtualAddress + hdr.Misc.VirtualSize);
  if (end == section_end) {
    start_offs = offs;
  } else {
    start_offs = section_end;
  }

  RelativeAddress reloc_offs = start_offs;
  AddressTransformer transformer;
  transformer.SetOriginalImageFile(*this);

  if (!ResizeSection(section_no,
                     start_offs.value() - hdr.VirtualAddress + new_size)) {
    return false;
  }

  if (!transformer.SetNewImageFile(*this))
    return false;

  RelocSet::const_iterator it(relocs.begin());
  while (it != relocs.end()) {
    // Find the end entry for the page we're covering.
    RelativeAddress next_page(PageRoundDown(it->value()) + kPageSize);
    RelocSet::const_iterator page_end(relocs.lower_bound(next_page));

    IMAGE_BASE_RELOCATION hdr = {};
    hdr.VirtualAddress = PageRoundDown(it->value());
    hdr.SizeOfBlock = sizeof(hdr) + sizeof(WORD) * std::distance(it, page_end);
    if (!WriteImage(reloc_offs, &hdr, sizeof(hdr)))
      return false;

    reloc_offs += sizeof(hdr);

    for (; it != page_end; ++it) {
      WORD entry = static_cast<WORD>(it->value() - hdr.VirtualAddress);
      if (!WriteImage(reloc_offs, &entry, sizeof(entry)))
        return false;

      reloc_offs += sizeof(entry);
    }
  }

  dir.VirtualAddress = start_offs.value();
  dir.Size = reloc_offs.value() - start_offs.value();

  return true;
}

bool PEImageFile::ReadRelocs(const RelocSet& relocs, RelocMap* reloc_values) {
  RelocSet::const_iterator it(relocs.begin());
  for (; it != relocs.end(); ++it) {
    AbsoluteAddress addr;
    if (!ReadImage(*it, &addr, sizeof(addr)))
      return false;

    reloc_values->insert(std::make_pair(*it, addr));
  }

  return true;
}

bool PEImageFile::WriteRelocs(const RelocMap& relocs) {
  // Walk the relocs and rewrite the image.
  RelocMap::const_iterator it(relocs.begin());
  for (; it != relocs.end(); ++it) {
    RelativeAddress offs(it->first);
    AbsoluteAddress addr(it->second);

    if (!WriteImage(offs, &addr, sizeof(addr)))
      return false;
  }

  return true;
}

// Rebases the image to new_base.
// The image must be consistent.
bool PEImageFile::RebaseImage(uint8 new_base) {
  uint32 old_base = nt_headers_->OptionalHeader.ImageBase;
  RelocSet relocs;
  if (!DecodeRelocSection(&relocs))
    return false;

  RelocMap reloc_values;
  if (!ReadRelocs(relocs, &reloc_values))
    return false;

  // Patch up the relocated values.
  RelocMap::iterator it(reloc_values.begin());
  for (; it != reloc_values.end(); ++it)
    it->second = AbsoluteAddress(it->second.value() - old_base + new_base);

  // And write them back.
  if (!WriteRelocs(reloc_values))
    return false;

  // Write the new image base.
  nt_headers_->OptionalHeader.ImageBase = new_base;

  return true;
}

// Information about a single import.
struct ImportInfo {
  // The loader ordinal hint for this import.
  uint16 hint;
  // Name of the function or #ordinal.
  std::string function;
};

// Information about all imports for a given DLL.
struct ImportDll {
  // RVAs for Import Name and Import Address tables.
  uint32 int_start;
  uint32 iat_start;

  // Name of DLL imported.
  std::string name;

  // One entry for each imported function.
  std::vector<ImportInfo> imports;
};

bool PEImageFile::DecodeImportSection(ImportDllVector* imports) {
  DCHECK(imports != NULL);

  // Walk the import thunks.
  IMAGE_DATA_DIRECTORY dir = nt_headers_->OptionalHeader.
      DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  RelativeAddress offs(dir.VirtualAddress);
  RelativeAddress end(offs + dir.Size);

  IMAGE_IMPORT_DESCRIPTOR import_desc = {};
  for (; offs < end; offs += sizeof(import_desc)) {
    if (!ReadImage(offs, &import_desc, sizeof(import_desc)))
      return false;

    if (import_desc.Characteristics == 0 && import_desc.FirstThunk == 0) {
      // This is the last chunk, bail the loop.
      break;
    }

    std::string dll_name;
    if (!ReadImageString(RelativeAddress(import_desc.Name), &dll_name))
      return false;

    // Iterate the Import Name Table and the Import Address Table
    // concurrently. They will yield, respectively, the name of the
    // function and the address of the entry.
    RelativeAddress int_offs(import_desc.OriginalFirstThunk);
    RelativeAddress iat_offs(import_desc.FirstThunk);

    imports->push_back(ImportDll());
    ImportDll& dll = imports->back();
    dll.name = dll_name;
    dll.desc = import_desc;

    while (true) {
      IMAGE_THUNK_DATA int_thunk = {};
      IMAGE_THUNK_DATA iat_thunk = {};

      if (!ReadImage(int_offs, &int_thunk, sizeof(int_thunk)) ||
          !ReadImage(iat_offs, &iat_thunk, sizeof(iat_thunk)))
        return false;

      // Are we at the end of the table?
      if (int_thunk.u1.Function == 0) {
        DCHECK_EQ(0U, iat_thunk.u1.Function);
        break;
      }

      uint16 hint = 0;
      std::string function_name;
      if (int_thunk.u1.AddressOfData & IMAGE_ORDINAL_FLAG32) {
        // It's an ordinal.
        function_name =
            StringPrintf("#%d", IMAGE_ORDINAL32(int_thunk.u1.Ordinal));
      } else {
        // Read the hint word, followed by the function name.
        RelativeAddress import_name(int_thunk.u1.AddressOfData);
        if (!ReadImage(import_name, &hint, sizeof(hint)) ||
            !ReadImageString(import_name + sizeof(hint), &function_name))
          return false;
      }

      dll.imports.push_back(ImportInfo());
      ImportInfo& info = dll.imports.back();
      info.function = function_name;
      info.hint = hint;

      int_offs += sizeof(int_thunk);
      iat_offs += sizeof(iat_thunk);
    }
  }

  return true;
}

namespace {

// Calculates the additional sizes necessry to write the import descriptors,
// thunks and names, respectively for the given imports. Assumes reuse for
// any given thunks, names etc.
void CalculateAdditionalImportSectionSizes(
    PEImageFile::ImportDllVector* imports, size_t* import_desc_size,
    size_t* import_thunk_size, size_t* name_size) {
  DCHECK(import_desc_size != NULL && *import_desc_size == 0);
  DCHECK(import_thunk_size != NULL && *import_thunk_size == 0);
  DCHECK(name_size != NULL && *name_size == 0);

  // Start by accounting for the import descriptors we'll always write.
  *import_desc_size = sizeof(IMAGE_IMPORT_DESCRIPTOR) * (imports->size() + 1);

  PEImageFile::ImportDllVector::iterator it(imports->begin());
  for (; it != imports->end(); ++it) {
    if (it->desc.OriginalFirstThunk == 0 || it->desc.FirstThunk == 0) {
      // Account for both the INT and IAT, note that
      // each has an ending sentinel.
      *import_thunk_size += 2 * sizeof(IMAGE_THUNK_DATA) *
          (it->imports.size() + 1);

      // Account for each IMPORT_NAME_DESCRIPTOR we're going to write.
      PEImageFile::ImportInfoVector::const_iterator jt(it->imports.begin());
      for (; jt != it->imports.end(); ++jt)
        *name_size += sizeof(jt->hint) + jt->function.size() + 1;
    }

    // Account for the name.
    if (it->desc.Name == 0)
      *name_size += it->name.size() + 1;
  }
}

}  // namespace

bool PEImageFile::Translate(RelativeAddress in, AbsoluteAddress* out) const {
  // TODO(siggi): Validate the input address.
  out->set_value(in.value() + nt_headers_->OptionalHeader.ImageBase);
  return true;
}

bool PEImageFile::Translate(AbsoluteAddress in, RelativeAddress* out) const {
  // TODO(siggi): Validate the input address.
  out->set_value(in.value() - nt_headers_->OptionalHeader.ImageBase);
  return true;
}

bool PEImageFile::WriteImportSection(ImportDllVector* imports) {
  DCHECK(imports != NULL);

  size_t import_desc_size = 0;
  size_t import_thunk_size = 0;
  size_t name_size = 0;
  CalculateAdditionalImportSectionSizes(imports,
                                        &import_desc_size,
                                        &import_thunk_size,
                                        &name_size);

  size_t section_no = FindSectionWithAttributes(IMAGE_SCN_MEM_WRITE);
  if (section_no == kNoSection)
    return false;

  IMAGE_SECTION_HEADER& section_header = section_headers_[section_no];

  // Start writing at the old virtual size, rounded up to 16 bytes.
  RelativeAddress start_offset(section_header.VirtualAddress +
      RoundUp(section_header.Misc.VirtualSize, 16));

  // Compute where to start writing import descriptors.
  RelativeAddress import_desc_offset(start_offset);
  // Compute where to start writing import chunks.
  RelativeAddress thunk_offset(start_offset + import_desc_size);
  // Compute where to start writing names.
  RelativeAddress name_offset(thunk_offset + import_thunk_size);
  // Compute where to end writing.
  RelativeAddress end_offset(name_offset + name_size);

  // Grow the image and affect any fixups that may result.
  AddressTransformer transformer;
  transformer.SetOriginalImageFile(*this);

  size_t new_size = end_offset.value() - section_header.VirtualAddress;
  if (!ResizeSection(section_no, new_size))
    return false;

  if (!transformer.SetNewImageFile(*this))
    return false;

  ImportDllVector::iterator it(imports->begin());
  for (; it != imports->end(); ++it) {
    // Do we need to create new INT and IAT?
    if (it->desc.OriginalFirstThunk == 0 || it->desc.FirstThunk == 0) {
      // Yups, start by writing the names.
      std::vector<IMAGE_THUNK_DATA> thunks;

      // TODO(siggi): account for ordinals.
      ImportInfoVector::const_iterator jt(it->imports.begin());
      for (; jt != it->imports.end(); ++jt) {
        // Store this thunk.
        IMAGE_THUNK_DATA data = { name_offset.value() };
        thunks.push_back(data);

        // Write the hint.
        if (!WriteImage(name_offset, &jt->hint, sizeof(jt->hint)))
          return false;
        name_offset += sizeof(jt->hint);

        // Write the name string.
        if (!WriteImage(name_offset,
                        jt->function.c_str(),
                        jt->function.size() + 1)) {
          return false;
        }

        name_offset += jt->function.size() + 1;
      }

      // Add the thunk seninel.
      IMAGE_THUNK_DATA sentinel = {};
      thunks.push_back(sentinel);

      size_t thunk_size = sizeof(thunks[0]) * thunks.size();
      if (!WriteImage(thunk_offset, &thunks[0], thunk_size) ||
          !WriteImage(thunk_offset + thunk_size, &thunks[0], thunk_size))
        return false;

      it->desc.OriginalFirstThunk = thunk_offset.value();
      it->desc.FirstThunk = thunk_offset.value() + thunk_size;
      thunk_offset += thunk_size * 2;
    } else {
      // Pre-existing IAT and INT, relocate them if need be.
      transformer.Transform(&Relative(it->desc.OriginalFirstThunk));
      transformer.Transform(&Relative(it->desc.FirstThunk));
    }

    if (it->desc.Name == 0) {
      if (!WriteImage(name_offset, it->name.c_str(), it->name.size() + 1))
        return false;

      it->desc.Name = name_offset.value();
      name_offset += it->name.size() + 1;
    } else {
      // Pre-existing name, relocate it if need be.
      transformer.Transform(&Relative(it->desc.Name));
    }

    DCHECK(it->desc.OriginalFirstThunk != 0);
    DCHECK(it->desc.FirstThunk != 0);
    DCHECK(it->desc.Name != 0);

    if (!WriteImage(import_desc_offset, &it->desc, sizeof(it->desc)))
      return false;

    import_desc_offset += sizeof(it->desc);
  }

  // Write the tail sentinel.
  IMAGE_IMPORT_DESCRIPTOR sentinel = {};
  if (!WriteImage(import_desc_offset, &sentinel, sizeof(sentinel)))
    return false;
  import_desc_offset += sizeof(sentinel);

  // And we're done, record the location and size of the new
  // import directory.
  IMAGE_DATA_DIRECTORY& import_dir = nt_headers_->OptionalHeader.
      DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  import_dir.VirtualAddress = start_offset.value();
  import_dir.Size = import_desc_offset - start_offset;

  return true;
}

bool PEImageFile::ReadImage(RelativeAddress addr,
                            void* data, size_t len) const {
  const uint8* image_data = GetImageData(addr, len);
  if (image_data == NULL)
    return false;

  memcpy(data, image_data, len);

  return true;
}

bool PEImageFile::ReadImage(AbsoluteAddress addr,
                            void* data, size_t len) const {
  RelativeAddress rel;
  return Translate(addr, &rel) && ReadImage(rel, data, len);
}

bool PEImageFile::ReadImageString(RelativeAddress addr,
                                  std::string* str) const {
  str->clear();
  size_t section = FindSectionForOffset(addr);
  if (section == kNoSection)
    return false;

  IMAGE_SECTION_HEADER& header = section_headers_[section];
  // Adjust the offset to within the section.
  size_t offs = addr.value() - header.VirtualAddress;
  DCHECK(offs < header.Misc.VirtualSize);

  const SectionBuffer& buf = sections_[section];
  const char* begin = reinterpret_cast<const char*>(&buf[offs]);
  for (; offs < buf.size() && buf[offs]; ++offs) {
    // This loop intentionally empty.
  }

  if (offs == buf.size())
    return false;

  str->assign(begin);

  return true;
}

bool PEImageFile::ReadImageString(AbsoluteAddress addr,
                                  std::string* str) const {
  RelativeAddress rel;
  return Translate(addr, &rel) && ReadImageString(rel, str);
}

bool PEImageFile::WriteImage(RelativeAddress addr,
                             const void* data,
                             size_t len) {
  uint8* image_data = GetImageData(addr, len);
  if (image_data == NULL)
    return false;

  memcpy(image_data, data, len);

  return true;
}

bool PEImageFile::WriteImage(AbsoluteAddress addr,
                             const void* data,
                             size_t len) {
  RelativeAddress rel;
  return Translate(addr, &rel) && WriteImage(rel, data, len);
}

const uint8* PEImageFile::GetImageData(
    RelativeAddress addr, size_t len) const {
 DCHECK(nt_headers_ != NULL);

  size_t section = FindSectionForOffset(addr);
  if (section == kNoSection) {
    // See whether the request fits the header.
    if (addr.value() + len < nt_headers_->OptionalHeader.SizeOfHeaders)
      return &header_[addr.value()];
  } else {
    IMAGE_SECTION_HEADER& header = section_headers_[section];
    // Adjust the offset to within the section.
    size_t offs = addr.value() - header.VirtualAddress;
    DCHECK(offs < header.Misc.VirtualSize);
    if (offs + len > header.SizeOfRawData)
      return NULL;

    const SectionBuffer& buf = sections_[section];
    DCHECK_EQ(header.SizeOfRawData, buf.size());
    return &buf[offs];
  }

  return NULL;
}

const uint8* PEImageFile::GetImageData(
    AbsoluteAddress addr, size_t len) const {
  RelativeAddress rel;
  if (!Translate(addr, &rel))
    return NULL;

  return GetImageData(rel, len);
}

uint8* PEImageFile::GetImageData(RelativeAddress addr, size_t len) {
  return const_cast<uint8*>(
      const_cast<const PEImageFile*>(this)->GetImageData(addr, len));
}

uint8* PEImageFile::GetImageData(AbsoluteAddress addr, size_t len) {
  return const_cast<uint8*>(
      const_cast<const PEImageFile*>(this)->GetImageData(addr, len));
}

namespace {

bool DataDirectoryIsEmpty(const PEImageFile& image, size_t dir) {
  const IMAGE_DATA_DIRECTORY& hdr =
      image.nt_headers()->OptionalHeader.DataDirectory[dir];

  return hdr.VirtualAddress == 0 && hdr.Size == 0;
}

}  // namespace

// Resize section_no to new_size, which must be larger than the current size.
bool PEImageFile::ResizeSection(size_t section_no, uint32 new_size) {
  uint32 num_sections = nt_headers_->FileHeader.NumberOfSections;
  if (section_no >= num_sections)
    return false;

  IMAGE_SECTION_HEADER& to_resize = section_headers_[section_no];
  uint32 old_size = to_resize.Misc.VirtualSize;
  if (new_size < old_size)
    return false;

  // Grab the current image state.
  AddressTransformer transformer;
  transformer.SetOriginalImageFile(*this);

  to_resize.Misc.VirtualSize = new_size;

  // Do we need to grow the backing data?
  if (to_resize.SizeOfRawData != PageRoundUp(new_size)) {
    // Grow the backing data.
    uint32 new_data_size = PageRoundUp(new_size);
    uint32 move_data_by = new_data_size - to_resize.SizeOfRawData;

    to_resize.SizeOfRawData = new_data_size;
    sections_.at(section_no).resize(new_data_size);

    // Then move all following sections up.
    for (size_t i = section_no + 1; i < num_sections; ++i)
      section_headers_[i].PointerToRawData += move_data_by;
  }

  // We move sections by multiples of page size, figure out how many
  // pages worth we need to move.
  uint32 move_by = PageRoundUp(new_size) - PageRoundUp(old_size);
  if (move_by == 0)
    return true;

  // Move all following sections up.
  for (size_t i = section_no + 1; i < num_sections; ++i)
    section_headers_[i].VirtualAddress += move_by;

  // And grow the image size appropriately.
  nt_headers_->OptionalHeader.SizeOfImage += move_by;

  // If this was the last section, we're all done.
  if (section_no == num_sections - 1)
    return true;

  // Grab the new image section state for the transformer.
  if (!transformer.SetNewImageFile(*this))
    return false;

  // Fix up all header fields that refer to RVAs.
  transformer.Transform(
      &Relative(nt_headers_->FileHeader.PointerToSymbolTable));
  transformer.Transform(
      &Relative(nt_headers_->OptionalHeader.AddressOfEntryPoint));
  transformer.Transform(
      &Relative(nt_headers_->OptionalHeader.BaseOfCode));
  transformer.Transform(
      &Relative(nt_headers_->OptionalHeader.BaseOfData));

  // Fix up the data directory.
  const size_t kNumDataDirs =
      arraysize(nt_headers_->OptionalHeader.DataDirectory);
  for (size_t i = 0; i < kNumDataDirs; ++i) {
    transformer.Transform(&Relative(
        nt_headers_->OptionalHeader.DataDirectory[i].VirtualAddress));
  }

  // These are all the data directory entries we may need to relocate
  // IMAGE_DIRECTORY_ENTRY_EXPORT - Export Directory
  // IMAGE_DIRECTORY_ENTRY_IMPORT - Import Directory
  // IMAGE_DIRECTORY_ENTRY_RESOURCE - Resource Directory
  // IMAGE_DIRECTORY_ENTRY_EXCEPTION - Exception Directory
  // IMAGE_DIRECTORY_ENTRY_SECURITY - Security Directory
  // IMAGE_DIRECTORY_ENTRY_BASERELOC - Base Relocation Table
  // IMAGE_DIRECTORY_ENTRY_DEBUG - Debug Directory
  // IMAGE_DIRECTORY_ENTRY_COPYRIGHT - (X86 usage)
  // IMAGE_DIRECTORY_ENTRY_ARCHITECTURE - Architecture Specific Data
  // IMAGE_DIRECTORY_ENTRY_GLOBALPTR - RVA of GP
  // IMAGE_DIRECTORY_ENTRY_TLS - TLS Directory
  // IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG - Load Configuration Directory
  // IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT - Bound Import Directory in headers
  // IMAGE_DIRECTORY_ENTRY_IAT - Import Address Table
  // IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT - Delay Load Import Descriptors
  // IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR - COM Runtime descriptor

  // TODO(siggi): implement fixups for these.
  DCHECK(DataDirectoryIsEmpty(*this, IMAGE_DIRECTORY_ENTRY_EXCEPTION));
  DCHECK(DataDirectoryIsEmpty(*this, IMAGE_DIRECTORY_ENTRY_SECURITY));
  DCHECK(DataDirectoryIsEmpty(*this, 7 /* IMAGE_DIRECTORY_ENTRY_COPYRIGHT */));
  DCHECK(DataDirectoryIsEmpty(*this, IMAGE_DIRECTORY_ENTRY_ARCHITECTURE));
  DCHECK(DataDirectoryIsEmpty(*this, IMAGE_DIRECTORY_ENTRY_GLOBALPTR));
  DCHECK(DataDirectoryIsEmpty(*this, IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT));
  DCHECK(DataDirectoryIsEmpty(*this, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR));


  // Transform the image sections.
  // TODO(siggi): there's more, see the list above.
  if (!FixupExports(transformer) ||
      !FixupImports(transformer) ||
      !FixupResourceDirectory(transformer) ||
      !FixupDebugDirectory(transformer) ||
      !FixupRelocations(transformer) ||
      !FixupTls(transformer) ||
      !FixupLoadConfig(transformer) ||
      !FixupDelayImports(transformer))
    return false;

  // Read the fixed-up relocations, we may need to patch up the pointers.
  RelocSet relocs;
  if (!DecodeRelocSection(&relocs))
    return false;

  // Read all the relocation entries.
  RelocMap reloc_values;
  if (!ReadRelocs(relocs, &reloc_values))
    return false;

  // Transform each reloc entry and write them back as appropriate.
  RelocMap::iterator it(reloc_values.begin());
  bool need_write = false;
  for (; it != reloc_values.end(); ++it) {
    RelativeAddress addr(it->first);
    AbsoluteAddress value(it->second);

    // Adjust each, and write it back if it's modified.
    if (transformer.Transform(&value)) {
      if (!WriteImage(addr, &value, sizeof(value)))
        return false;
    }
  }

  return true;
}

bool PEImageFile::FixupResourceDirectory(const AddressTransformer& mover,
                                         RelativeAddress resource_base,
                                         RelativeAddress addr) {
  IMAGE_RESOURCE_DIRECTORY dir = {};
  if (!ReadImage(addr, &dir, sizeof(dir)))
    return false;

  size_t num_entries = dir.NumberOfNamedEntries + dir.NumberOfIdEntries;
  addr += sizeof(dir);
  IMAGE_RESOURCE_DIRECTORY_ENTRY entry;
  for (size_t i = 0; i < num_entries; ++i, addr += sizeof(entry)) {
    if (!ReadImage(addr, &entry, sizeof(entry)))
      return false;

    if (entry.DataIsDirectory) {
      if (!FixupResourceDirectory(
          mover, resource_base, resource_base + entry.OffsetToDirectory))
        return false;
    } else {
      IMAGE_RESOURCE_DATA_ENTRY data;
      if (!ReadImage(resource_base + entry.OffsetToData,
                     &data,
                     sizeof(data)))
        return false;

      if (mover.Transform(&Relative(data.OffsetToData)) &&
          !WriteImage(resource_base + entry.OffsetToData,
                      &data,
                      sizeof(data)))
        return false;
    }
  }

  return true;
}

bool PEImageFile::FixupResourceDirectory(const AddressTransformer& mover) {
  IMAGE_DATA_DIRECTORY dir = nt_headers_->OptionalHeader.
      DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
  RelativeAddress addr(dir.VirtualAddress);

  return FixupResourceDirectory(mover, addr, addr);
}

bool PEImageFile::FixupLoadConfig(const AddressTransformer& mover) {
  // The image load config directory contains absolute addresses that
  // have relocation entries, so there's no work to be done for this
  // section here.
  return true;
}

// Walk the relocation entries and rewrite them as necessary.
bool PEImageFile::FixupRelocations(const AddressTransformer& transformer) {
  IMAGE_DATA_DIRECTORY dir = nt_headers_->OptionalHeader.
      DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
  RelativeAddress addr(dir.VirtualAddress);
  RelativeAddress end(addr + dir.Size);

  IMAGE_BASE_RELOCATION hdr = {};
  for (; addr < end; addr += hdr.SizeOfBlock) {
    // Read the header.
    if (!ReadImage(addr, &hdr, sizeof(hdr)))
      return false;

    // Rewrite this entry if it's in our old section addresses.
    if (transformer.Transform(&Relative(hdr.VirtualAddress))) {
      if (!WriteImage(addr, &hdr, sizeof(hdr)))
        return false;
    }
  }

  return true;
}

bool PEImageFile::FixupTls(const AddressTransformer& transformer) {
  // The TLS directory contains absolute addresses that
  // have relocation entries, so there's no work to be
  // done for this section here.
  return true;
}

bool PEImageFile::FixupDebugDirectory(const AddressTransformer& mover) {
  IMAGE_DATA_DIRECTORY dir = nt_headers_->OptionalHeader.
      DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
  RelativeAddress offs(dir.VirtualAddress);
  RelativeAddress end = offs + dir.Size;

  IMAGE_DEBUG_DIRECTORY debug_dir = {};
  if (!ReadImage(offs, &debug_dir, sizeof(debug_dir)))
    return false;

  size_t section_no = FindSectionForOffset(offs);
  DCHECK(section_no != kNoSection);
  IMAGE_SECTION_HEADER& header = section_headers_[section_no];

  // The location of the debug directory is specified in terms of an RVA,
  // as well as in a file offset in the image. It appears debuggers make
  // use of the latter.
  if (mover.Transform(&Relative(debug_dir.AddressOfRawData)) +
      mover.Transform(&FileOffset(debug_dir.PointerToRawData))) {
    if (!WriteImage(offs, &debug_dir, sizeof(debug_dir)))
      return false;
  }

  return true;
}

bool PEImageFile::FixupImportThunks(const AddressTransformer& mover,
                                    RelativeAddress thunk_addr) {
  IMAGE_THUNK_DATA thunk = {};
  for (; true; thunk_addr += sizeof(thunk)) {
    if (!ReadImage(thunk_addr, &thunk, sizeof(thunk)))
      return false;

    // Are we at the end of the table?
    if (thunk.u1.Function == 0)
      break;

    // Don't relocate ordinal thunks.
    if (thunk.u1.AddressOfData & IMAGE_ORDINAL_FLAG32)
      continue;
    if (mover.Transform(&Relative(thunk.u1.AddressOfData))) {
      if (!WriteImage(thunk_addr, &thunk, sizeof(thunk)))
        return false;
    }
  }

  return true;
}

bool PEImageFile::FixupExports(const AddressTransformer& mover) {
  IMAGE_DATA_DIRECTORY dir = nt_headers_->OptionalHeader.
      DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
  RelativeAddress addr(dir.VirtualAddress);
  RelativeAddress end(addr + dir.Size);

  if (addr.value() == 0)
    return true;

  IMAGE_EXPORT_DIRECTORY export_dir = {};
  if (!ReadImage(addr, &export_dir, sizeof(export_dir)))
    return false;

  if (mover.Transform(&Relative(export_dir.AddressOfFunctions)) +
      mover.Transform(&Relative(export_dir.AddressOfNames)) +
      mover.Transform(&Relative(export_dir.AddressOfNameOrdinals))) {
    if (!WriteImage(addr, &export_dir, sizeof(export_dir)))
      return false;
  }

  RelativeAddress name_addr(export_dir.AddressOfNames);
  for (size_t i = 0; i < export_dir.NumberOfNames; ++i) {
    uint32 name = NULL;
    if (!ReadImage(name_addr + sizeof(name) * i, &name, sizeof(name)))
      return false;

    if (mover.Transform(&Relative(name)) &&
        !WriteImage(name_addr + sizeof(name) * i, &name, sizeof(name)))
      return false;
  }

  return true;
}

bool PEImageFile::FixupImports(const AddressTransformer& mover) {
  // Now relocate the imports table.
  // Walk the import thunks.
  IMAGE_DATA_DIRECTORY dir = nt_headers_->OptionalHeader.
      DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  RelativeAddress addr(dir.VirtualAddress);
  RelativeAddress end(addr + dir.Size);

  IMAGE_IMPORT_DESCRIPTOR import_desc = {};
  for (; addr < end; addr += sizeof(import_desc)) {
    if (!ReadImage(addr, &import_desc, sizeof(import_desc)))
      return false;

    if (import_desc.Characteristics == 0) {
      // This is the last chunk, bail the loop.
      break;
    }

    DCHECK(import_desc.ForwarderChain == -1 ||
        import_desc.ForwarderChain == 0);

    // Transform the import descriptor.
    if (mover.Transform(&Relative(import_desc.OriginalFirstThunk)) +
        mover.Transform(&Relative(import_desc.FirstThunk)) +
        mover.Transform(&Relative(import_desc.Name))) {
      if (!WriteImage(addr, &import_desc, sizeof(import_desc)))
        return false;
    }

    // Now relocate the INT.
    if (!FixupImportThunks(mover,
                           RelativeAddress(import_desc.OriginalFirstThunk))) {
      return false;
    }

    // And the IAT if it's unbound.
    if (import_desc.TimeDateStamp == 0) {
      if (!FixupImportThunks(mover,
                             RelativeAddress(import_desc.FirstThunk))) {
        return false;
      }
    }
  }

  return true;
}

bool PEImageFile::FixupDelayImports(const AddressTransformer& mover) {
  IMAGE_DATA_DIRECTORY dir = nt_headers_->OptionalHeader.
      DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
  RelativeAddress addr(dir.VirtualAddress);
  RelativeAddress end(addr + dir.Size);

  // Walk the delay import descriptors.
  ImgDelayDescr desc = {};
  for (; addr < end; addr += sizeof(desc)) {
    if (!ReadImage(addr, &desc, sizeof(desc)))
      return false;

    if (desc.rvaDLLName == 0 && desc.rvaIAT == 0) {
      // This is the last chunk, bail the loop.
      break;
    }

    // We don't deal in VS 6.0 delay descriptors.
    DCHECK(desc.grAttrs & dlattrRva);

    // Transform the delay descriptor - we add the Transform
    // output to make sure we transform them all and that we
    // write them back if any changes.
    if (mover.Transform(&Relative(desc.rvaDLLName)) +
        mover.Transform(&Relative(desc.rvaHmod)) +
        mover.Transform(&Relative(desc.rvaIAT)) +
        mover.Transform(&Relative(desc.rvaINT)) +
        mover.Transform(&Relative(desc.rvaBoundIAT)) +
        mover.Transform(&Relative(desc.rvaUnloadIAT))) {
      if (!WriteImage(addr, &desc, sizeof(desc)))
        return false;
    }

    // And the thunks, the IAT we don't touch, because that
    // never contains RVAs for delay imports.
    if (!FixupImportThunks(mover, RelativeAddress(desc.rvaINT)))
      return false;

    if (desc.dwTimeStamp == 0 && desc.rvaBoundIAT != 0) {
      if (!FixupImportThunks(mover, RelativeAddress(desc.rvaBoundIAT)))
        return false;
    }
  }

  return true;
}

size_t PEImageFile::FindSectionForOffset(RelativeAddress addr) const {
  const IMAGE_SECTION_HEADER* section_header =
      FindSection(addr,
                  section_headers_,
                  nt_headers_->FileHeader.NumberOfSections);

  if (section_header == NULL)
    return kNoSection;

  return section_header - section_headers_;
}

size_t PEImageFile::FindSectionWithAttributes(DWORD attrib) const {
  uint32 num_sections = nt_headers_->FileHeader.NumberOfSections;
  for (size_t i = 0; i != num_sections; ++i) {
    IMAGE_SECTION_HEADER& header = section_headers_[i];
    if ((header.Characteristics & attrib) == attrib)
      return i;
  }

  return kNoSection;
}
