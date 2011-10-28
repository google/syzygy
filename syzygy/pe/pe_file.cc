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
#include "syzygy/pe/pe_file.h"

#include "base/file_util.h"
#include "base/logging.h"

namespace {

bool ReadAt(FILE* file, size_t pos, void* buf, size_t len) {
  if (fseek(file, pos, SEEK_SET) != 0)
    return false;

  size_t read = fread(buf, 1, len, file);
  if (read != len)
    return false;

  return true;
}

}  // namespace

namespace pe {

const size_t kInvalidSection = -1;

using core::AbsoluteAddress;
using core::FileOffsetAddress;
using core::RelativeAddress;

PEFile::PEFile()
    : dos_header_(NULL),
      nt_headers_(NULL),
      section_headers_(NULL) {
}

PEFile::~PEFile() {
}

bool PEFile::Init(const FilePath& path) {
  path_ = path;
  FILE* file = file_util::OpenFile(path, "rb");
  if (file == NULL) {
    LOG(ERROR) << "Failed to open file " << path.value().c_str();
    return false;
  }

  bool success = ReadHeaders(file);
  if (success)
    success = ReadSections(file);

  file_util::CloseFile(file);

  return success;
}

void PEFile::GetSignature(Signature* signature) const {
  DCHECK(signature != NULL);
  DCHECK(nt_headers_ != NULL);

  // TODO(chrisha): Make GetSignature return a bool, and update all calling
  //     sites.
  FilePath abs_path(path_);
  CHECK(file_util::AbsolutePath(&abs_path));

  signature->path = abs_path.value();
  signature->base_address =
      AbsoluteAddress(nt_headers_->OptionalHeader.ImageBase);
  signature->module_size = nt_headers_->OptionalHeader.SizeOfImage;
  signature->module_time_date_stamp = nt_headers_->FileHeader.TimeDateStamp;
  signature->module_checksum = nt_headers_->OptionalHeader.CheckSum;
}

bool PEFile::Contains(RelativeAddress rel, size_t len) const {
  const ImageAddressSpace::Range range(rel, len);
  return image_data_.FindContaining(range) != image_data_.ranges().end();
}

bool PEFile::Contains(AbsoluteAddress abs, size_t len) const {
  RelativeAddress rel;
  return Translate(abs, &rel) && Contains(rel, len);
}

size_t PEFile::GetSectionIndex(RelativeAddress rel, size_t len) const {
  const ImageAddressSpace::Range range(rel, len);
  ImageAddressSpace::RangeMap::const_iterator it =
      image_data_.FindContaining(range);
  if (it == image_data_.ranges().end())
    return kInvalidSection;
  return it->second.id;
}

size_t PEFile::GetSectionIndex(AbsoluteAddress abs, size_t len) const {
  RelativeAddress rel;
  Translate(abs, &rel);
  return GetSectionIndex(rel, len);
}

const IMAGE_SECTION_HEADER* PEFile::GetSectionHeader(
    RelativeAddress rel, size_t len) const {
  size_t id = GetSectionIndex(rel, len);
  if (id == kInvalidSection)
    return NULL;
  DCHECK(id < nt_headers_->FileHeader.NumberOfSections);
  return section_headers_ + id;
}

const IMAGE_SECTION_HEADER* PEFile::GetSectionHeader(
    AbsoluteAddress abs, size_t len) const {
  RelativeAddress rel;
  Translate(abs, &rel);
  return GetSectionHeader(rel, len);
}

size_t PEFile::GetSectionIndex(const char* name) const {
  size_t section_count = nt_headers_->FileHeader.NumberOfSections;
  for (size_t i = 0; i < section_count; ++i) {
    const IMAGE_SECTION_HEADER* header = section_headers_ + i;
    if (strncmp(reinterpret_cast<const char*>(header->Name), name,
                IMAGE_SIZEOF_SHORT_NAME) == 0)
      return i;
  }
  return kInvalidSection;
}

std::string PEFile::GetSectionName(
    const IMAGE_SECTION_HEADER& section) {
  const char* name = reinterpret_cast<const char*>(section.Name);
  return std::string(name, strnlen(name, arraysize(section.Name)));
}

std::string PEFile::GetSectionName(size_t section_index) const {
  DCHECK_LT(section_index, nt_headers_->FileHeader.NumberOfSections);

  const IMAGE_SECTION_HEADER* section = section_headers_ + section_index;
  return GetSectionName(*section);
}

const IMAGE_SECTION_HEADER* PEFile::GetSectionHeader(const char* name) const {
  size_t id = GetSectionIndex(name);
  if (id == kInvalidSection)
    return NULL;
  return section_headers_ + id;
}

bool PEFile::ReadHeaders(FILE* file) {
  // Read the DOS header.
  IMAGE_DOS_HEADER dos_header = {};
  if (!ReadAt(file, 0, &dos_header, sizeof(dos_header))) {
    LOG(ERROR) << "Unable to read DOS header";
    return false;
  }

  // And the NT headers.
  IMAGE_NT_HEADERS nt_headers = {};
  size_t pos = dos_header.e_lfanew;
  if (!ReadAt(file, pos, &nt_headers, sizeof(nt_headers))) {
    LOG(ERROR) << "Unable to read NT headers";
    return false;
  }

  // We now know how large the headers are, so create a range for them.
  size_t header_size = nt_headers.OptionalHeader.SizeOfHeaders;
  ImageAddressSpace::Range header_range(RelativeAddress(0), header_size);
  ImageAddressSpace::RangeMap::iterator it;
  bool inserted = image_data_.Insert(header_range, SectionInfo(), &it);
  DCHECK(inserted);
  if (!inserted) {
    LOG(ERROR) << "Unable to create header range";
    return false;
  }

  SectionBuffer& header = it->second.buffer;
  header.resize(header_size);
  if (!ReadAt(file, 0, &header[0], header_size)) {
    LOG(ERROR) << "Unable to read header data";
    return false;
  }

  // TODO(siggi): Validate these pointers!
  dos_header_ = reinterpret_cast<IMAGE_DOS_HEADER*>(&header.at(0));
  nt_headers_ =
      reinterpret_cast<IMAGE_NT_HEADERS*>(&header.at(dos_header_->e_lfanew));
  section_headers_ = IMAGE_FIRST_SECTION(nt_headers_);

  return true;
}

bool PEFile::ReadSections(FILE* file) {
  DCHECK(nt_headers_ != NULL);
  DCHECK(section_headers_ != NULL);

  size_t num_sections = nt_headers_->FileHeader.NumberOfSections;
  for (size_t i = 0; i < num_sections; ++i) {
    const IMAGE_SECTION_HEADER* hdr = section_headers_ + i;
    // Insert the range for the new section.
    ImageAddressSpace::Range section_range(RelativeAddress(hdr->VirtualAddress),
                                           hdr->Misc.VirtualSize);
    ImageAddressSpace::RangeMap::iterator it;
    if (!image_data_.Insert(section_range, SectionInfo(), &it)) {
      LOG(ERROR) << "Unable to insert range for section " << hdr->Name;
      return false;
    }

    it->second.id = i;
    SectionBuffer& buf = it->second.buffer;
    if (hdr->SizeOfRawData == 0)
      continue;

    buf.resize(hdr->SizeOfRawData);
    if (!ReadAt(file, hdr->PointerToRawData, &buf.at(0), hdr->SizeOfRawData)) {
      LOG(ERROR) << "Unable to read data for section " << hdr->Name;
      return false;
    }
  }

  return true;
}

bool PEFile::Translate(RelativeAddress rel, AbsoluteAddress* abs) const {
  DCHECK(abs != NULL);
  abs->set_value(rel.value() + nt_headers_->OptionalHeader.ImageBase);
  return true;
}

bool PEFile::Translate(AbsoluteAddress abs, RelativeAddress* rel) const {
  DCHECK(rel != NULL);
  rel->set_value(abs.value() - nt_headers_->OptionalHeader.ImageBase);
  return true;
}

bool PEFile::Translate(FileOffsetAddress offs, RelativeAddress* rel) const {
  DCHECK(rel != NULL);

  // The first "previous section" is the headers.
  RelativeAddress previous_section_start(0);
  FileOffsetAddress previous_section_file_start(0);
  for (size_t i = 0; i < nt_headers_->FileHeader.NumberOfSections; ++i) {
    if (offs.value() < section_headers_[i].PointerToRawData) {
      size_t file_offs = offs - previous_section_file_start;
      *rel =  previous_section_start + file_offs;
      return true;
    }

    previous_section_start.set_value(section_headers_[i].VirtualAddress);
    previous_section_file_start.set_value(section_headers_[i].PointerToRawData);
  }

  return false;
}

const uint8* PEFile::GetImageData(RelativeAddress rel, size_t len) const {
  DCHECK(nt_headers_ != NULL);

  ImageAddressSpace::Range range(rel, len);
  ImageAddressSpace::RangeMap::const_iterator it(
      image_data_.FindContaining(range));

  if (it != image_data_.ranges().end()) {
    ptrdiff_t offs = rel - it->first.start();
    DCHECK_GE(offs, 0);

    const SectionBuffer& buf = it->second.buffer;
    if (offs + len <= buf.size())
      return &buf.at(offs);
  }

  return NULL;
}

const uint8* PEFile::GetImageData(AbsoluteAddress abs, size_t len) const {
  RelativeAddress rel;
  if (Translate(abs, &rel))
    return GetImageData(rel, len);

  return NULL;
}

uint8* PEFile::GetImageData(RelativeAddress rel, size_t len) {
  return const_cast<uint8*>(
      static_cast<const PEFile*>(this)->GetImageData(rel, len));
}

uint8* PEFile::GetImageData(AbsoluteAddress abs, size_t len) {
  return const_cast<uint8*>(
      static_cast<const PEFile*>(this)->GetImageData(abs, len));
}

bool PEFile::ReadImage(RelativeAddress rel, void* data, size_t len) const {
  DCHECK(data != NULL);
  const uint8* buf = GetImageData(rel, len);
  if (buf == NULL)
    return false;

  memcpy(data, buf, len);
  return true;
}

bool PEFile::ReadImage(AbsoluteAddress abs, void* data, size_t len) const {
  RelativeAddress rel;
  if (!Translate(abs, &rel))
    return false;

  return ReadImage(rel, data, len);
}

bool PEFile::ReadImageString(RelativeAddress rel, std::string* str) const {
  DCHECK(nt_headers_ != NULL);
  str->clear();

  // Locate the range that contains the first byte of the string.
  ImageAddressSpace::Range range(rel, 1);
  ImageAddressSpace::RangeMap::const_iterator it(
      image_data_.FindContaining(range));

  if (it != image_data_.ranges().end()) {
    ptrdiff_t offs = rel - it->first.start();
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

bool PEFile::ReadImageString(AbsoluteAddress abs, std::string* str) const {
  RelativeAddress rel;
  if (!Translate(abs, &rel))
    return false;

  return ReadImageString(rel, str);
}

bool PEFile::DecodeRelocs(RelocSet* relocs) const {
  DCHECK(nt_headers_ != NULL);
  DCHECK(relocs != NULL);

  // Walk the relocs.
  IMAGE_DATA_DIRECTORY dir =
      nt_headers_->OptionalHeader.DataDirectory[
          IMAGE_DIRECTORY_ENTRY_BASERELOC];
  RelativeAddress offs(dir.VirtualAddress);
  RelativeAddress end(offs + dir.Size);

  const IMAGE_BASE_RELOCATION* hdr = NULL;
  for (; offs < end; offs += hdr->SizeOfBlock) {
    // Read the next header.
    hdr = reinterpret_cast<const IMAGE_BASE_RELOCATION*>(
        GetImageData(offs, sizeof(hdr)));
    if (hdr == NULL) {
      LOG(ERROR) << "Failed to read relocation block header.";
      return false;
    }

    // Read the entries.
    size_t num_relocs = (hdr->SizeOfBlock - sizeof(*hdr)) / sizeof(WORD);
    const WORD* reloc_block = reinterpret_cast<const WORD*>(
        GetImageData(offs + sizeof(*hdr), sizeof(*reloc_block) * num_relocs));
    if (reloc_block == NULL) {
      LOG(ERROR) << "Failed to read relocation entries.";
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
        relocs->insert(RelativeAddress(hdr->VirtualAddress) + offs);
      }
    }
  }

  DCHECK(offs == end);
  return true;
}

bool PEFile::ReadRelocs(const RelocSet& relocs, RelocMap* reloc_values) const {
  RelocSet::const_iterator it(relocs.begin());
  for (; it != relocs.end(); ++it) {
    const AbsoluteAddress* abs = reinterpret_cast<const AbsoluteAddress*>(
        GetImageData(*it, sizeof(*abs)));
    if (abs == NULL) {
      LOG(ERROR) << "Failed to read reloc at " << it->value();
      return false;
    }

    reloc_values->insert(std::make_pair(*it, *abs));
  }

  return true;
}

bool PEFile::DecodeExports(ExportInfoVector* exports) const {
  DCHECK(exports != NULL);

  IMAGE_DATA_DIRECTORY dir = nt_headers_->OptionalHeader.
      DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
  RelativeAddress addr(dir.VirtualAddress);
  RelativeAddress end(addr + dir.Size);

  if (addr.value() == 0)
    return true;

  const IMAGE_EXPORT_DIRECTORY* export_dir =
      reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(
          GetImageData(addr, sizeof(export_dir)));
  if (export_dir == NULL) {
    LOG(ERROR) << "Unable to read export directory";
    return false;
  }

  const RelativeAddress* functions =
      reinterpret_cast<const RelativeAddress*>(
          GetImageData(RelativeAddress(export_dir->AddressOfFunctions),
                       sizeof(*functions) * export_dir->NumberOfFunctions));
  if (functions == NULL) {
    LOG(ERROR) << "Unable to read export functions.";
    return false;
  }

  const RelativeAddress* names =
      reinterpret_cast<const RelativeAddress*>(
          GetImageData(RelativeAddress(export_dir->AddressOfNames),
                       sizeof(*functions) * export_dir->NumberOfNames));
  if (names == NULL) {
    LOG(ERROR) << "Unable to read export names.";
    return false;
  }

  const WORD* name_ordinals =
      reinterpret_cast<const WORD*>(
          GetImageData(RelativeAddress(export_dir->AddressOfNameOrdinals),
                       sizeof(*functions) * export_dir->NumberOfNames));
  if (names == NULL) {
    LOG(ERROR) << "Unable to read name ordinals.";
    return false;
  }

  for (size_t index = 0; index < export_dir->NumberOfFunctions; ++index) {
    // Is it a blank entry?
    if (functions[index] != RelativeAddress(0)) {
      ExportInfo info;
      info.ordinal = index + 1;

      RelativeAddress function = functions[index];
      // Is it a forward?
      if (function >= addr && function < end) {
        if (!ReadImageString(function, &info.forward)) {
          LOG(ERROR) << "Unable to read export forward string";
          return false;
        }
      } else {
        info.function = function;
      }

      // Does it have a name?
      for (size_t i = 0; i < export_dir->NumberOfNames; ++i) {
        if (name_ordinals[i] == index) {
          if (!ReadImageString(names[i], &info.name)) {
            LOG(ERROR) << "Unable to read export name";
            return false;
          }
          break;
        }
      }

      exports->push_back(info);
    }
  }

  return true;
}

bool PEFile::DecodeImports(ImportDllVector* imports) const {
  DCHECK(imports != NULL);

  // Walk the import thunks.
  IMAGE_DATA_DIRECTORY dir = nt_headers_->OptionalHeader.
      DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  RelativeAddress offs(dir.VirtualAddress);
  RelativeAddress end(offs + dir.Size);

  const IMAGE_IMPORT_DESCRIPTOR* import_desc = NULL;
  for (; offs < end; offs += sizeof(*import_desc)) {
    import_desc = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(
        GetImageData(offs, sizeof(*import_desc)));
    if (import_desc == NULL) {
      LOG(ERROR) << "Unable to read import descriptor";
      return false;
    }

    if (import_desc->Characteristics == 0 && import_desc->FirstThunk == 0) {
      // This is the last chunk, bail the loop.
      break;
    }

    std::string dll_name;
    if (!ReadImageString(RelativeAddress(import_desc->Name), &dll_name)) {
      LOG(ERROR) << "Unable to read import descriptor name";
      return false;
    }

    // Iterate the Import Name Table and the Import Address Table
    // concurrently. They will yield, respectively, the name of the
    // function and the address of the entry.
    RelativeAddress int_offs(import_desc->OriginalFirstThunk);
    RelativeAddress iat_offs(import_desc->FirstThunk);

    imports->push_back(ImportDll());
    ImportDll& dll = imports->back();
    dll.name = dll_name;
    dll.desc = *import_desc;

    while (true) {
      IMAGE_THUNK_DATA int_thunk = {};
      IMAGE_THUNK_DATA iat_thunk = {};

      if (!ReadImage(int_offs, &int_thunk, sizeof(int_thunk)) ||
          !ReadImage(iat_offs, &iat_thunk, sizeof(iat_thunk))) {
        LOG(ERROR) << "Unable to read import name or address table thunk";
        return false;
      }

      // Are we at the end of the table?
      if (int_thunk.u1.Function == 0) {
        DCHECK_EQ(0U, iat_thunk.u1.Function);
        break;
      }

      uint16 hint = 0;
      uint16 ordinal = 0;
      std::string function_name;
      if (int_thunk.u1.AddressOfData & IMAGE_ORDINAL_FLAG32) {
        // It's an ordinal.
        ordinal = IMAGE_ORDINAL32(int_thunk.u1.Ordinal);
      } else {
        // Read the hint word, followed by the function name.
        RelativeAddress import_name(int_thunk.u1.AddressOfData);
        if (!ReadImage(import_name, &hint, sizeof(hint)) ||
            !ReadImageString(import_name + sizeof(hint), &function_name)) {
          LOG(ERROR) << "Unable to read import function hint or name";
          return false;
        }
      }

      dll.functions.push_back(ImportInfo());
      ImportInfo& info = dll.functions.back();
      info.function = function_name;
      info.ordinal = ordinal;
      info.hint = hint;

      int_offs += sizeof(int_thunk);
      iat_offs += sizeof(iat_thunk);
    }
  }

  return true;
}

bool PEFile::Signature::IsConsistent(const Signature& signature) const {
  return base_address == signature.base_address &&
      module_size == signature.module_size &&
      module_time_date_stamp == signature.module_time_date_stamp &&
      module_checksum == signature.module_checksum;
}

bool PEFile::Signature::Save(core::OutArchive* out_archive) const {
  return out_archive->Save(path) &&
      out_archive->Save(base_address) &&
      out_archive->Save(module_size) &&
      out_archive->Save(module_time_date_stamp) &&
      out_archive->Save(module_checksum);
}

bool PEFile::Signature::Load(core::InArchive* in_archive) {
  return in_archive->Load(&path) &&
      in_archive->Load(&base_address) &&
      in_archive->Load(&module_size) &&
      in_archive->Load(&module_time_date_stamp) &&
      in_archive->Load(&module_checksum);
}

}  // namespace pe
