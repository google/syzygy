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
#include "sawbuck/image_util/pe_file_parser.h"

namespace image_util {

using core::AbsoluteAddress;
using core::BlockGraph;
using core::FileOffsetAddress;
using core::RelativeAddress;

const char* kDirEntryNames[] = {
    "IMAGE_DIRECTORY_ENTRY_EXPORT",
    "IMAGE_DIRECTORY_ENTRY_IMPORT",
    "IMAGE_DIRECTORY_ENTRY_RESOURCE",
    "IMAGE_DIRECTORY_ENTRY_EXCEPTION",
    "IMAGE_DIRECTORY_ENTRY_SECURITY",
    "IMAGE_DIRECTORY_ENTRY_BASERELOC",
    "IMAGE_DIRECTORY_ENTRY_DEBUG",
    "IMAGE_DIRECTORY_ENTRY_ARCHITECTURE",
    "IMAGE_DIRECTORY_ENTRY_GLOBALPTR",
    "IMAGE_DIRECTORY_ENTRY_TLS",
    "IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG",
    "IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT",
    "IMAGE_DIRECTORY_ENTRY_IAT",
    "IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT",
    "IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR",
};

// This class represents a generic, untyped pointer with a fixed length,
// into a PE image at a particular address.
class PEFilePtr {
 public:
  PEFilePtr() : ptr_(NULL), len_(0) {
  }

  // Set the pointer to the address and data in @p block.
  bool Set(BlockGraph::Block* block) {
    return Set(block, block->addr());
  }

  // Set the pointer to the address @p addr, which must be contained
  // within @p block, and the corresponding data in @p block.
  bool Set(BlockGraph::Block* block, RelativeAddress addr) {
    const uint8* ptr = block->data();
    ptrdiff_t offs = addr - block->addr();
    if (ptr == NULL || offs < 0)
      return false;
    if (static_cast<size_t>(offs) >= block->data_size())
      return false;

    addr_ = addr;
    ptr_ = ptr + offs;
    len_ = block->data_size() - offs;

    return true;
  }

  // Set the pointer to the address @p addr, and length @p len,
  // iff the @p image contains that data.
  bool Read(const PEFile& image, RelativeAddress addr, size_t len) {
    const uint8* ptr = image.GetImageData(addr, len);
    if (ptr == NULL)
      return false;

    // Success - store the data we now point to.
    addr_ = addr;
    ptr_ = ptr;
    len_ = len;

    return true;
  }

  // Advance the pointer by @p len bytes iff the pointer points to at
  // least @len bytes.
  bool Advance(size_t len) {
    // Do we have enough remaining?
    if (len_ < len)
      return false;

    // Walk forward, and trim the remaining length.
    addr_ += len;
    ptr_ += len;
    len_ -= len;

    return true;
  }

  // Accessors.
  RelativeAddress addr() const { return addr_; }
  void set_addr(RelativeAddress addr) { addr_ = addr; }

  const uint8* ptr() const { return ptr_; }
  void set_ptr(const uint8* ptr) { ptr_ = ptr; }

  size_t len() const { return len_; }
  void set_len(size_t len) { len_ = len; }

 private:
  RelativeAddress addr_;
  const uint8* ptr_;
  size_t len_;
};

// Represents a typed pointer into a PE image at a given address.
// The data pointed to by a struct ptr is always at least sizeof(ItemType).
template <typename ItemType>
class PEFileStructPtr {
 public:
  PEFileStructPtr() {
  }

  // Set this pointer to the address and data in @p block.
  // @returns true iff successful.
  bool Set(BlockGraph::Block* block) {
    if (block->data_size() < sizeof(ItemType))
      return false;

    return ptr_.Set(block);
  }

  // Set this pointer to addr, which must be contained within @p block,
  // and the corresponding data in @p block.
  // @returns true iff successful.
  bool Set(BlockGraph::Block* block, RelativeAddress addr) {
    if (block->data_size() < sizeof(ItemType))
      return false;

    return ptr_.Set(block, addr);
  }

  // Read data from @p image at @p addr.
  bool Read(const PEFile& image, RelativeAddress addr) {
    return Read(image, addr, sizeof(ItemType));
  }

  // Read @p len data bytes from @p image at @p addr.
  // @note @p len must be greater or equal to sizeof(ItemType).
  bool Read(const PEFile& image, RelativeAddress addr, size_t len) {
    DCHECK(len >= sizeof(ItemType));
    return ptr_.Read(image, addr, len);
  }

  // @returns true iff this pointer is valid.
  bool IsValid() const {
    return ptr_.ptr() != NULL && ptr_.len() >= sizeof(ItemType);
  }

  // Advance our pointer by sizeof(ItemType) iff this would leave
  // this pointer valid.
  bool Next() {
    DCHECK(IsValid());

    // See whether there's enough room left for another full item.
    size_t new_len = ptr_.len() - sizeof(ItemType);
    if (new_len < sizeof(ItemType))
      return false;

    // Walk forward one item. We've already checked that there's
    // sufficient data left, so this must succeed.
    bool ret = ptr_.Advance(sizeof(ItemType));
    DCHECK(ret && IsValid());

    return true;
  }

  RelativeAddress addr() const { return ptr_.addr(); }
  void set_addr(RelativeAddress addr) { ptr.set_addr(addr); }

  const ItemType* ptr() const {
    return reinterpret_cast<const ItemType*>(ptr_.ptr());
  }

  const ItemType* operator->() const {
    return ptr();
  }

  // Returns the image address of the data at ptr.
  // @note ptr must be within the data we point to.
  RelativeAddress AddressOf(const void* ptr) const {
    DCHECK(IsValid());

    const uint8* tmp = reinterpret_cast<const uint8*>(ptr);
    DCHECK(tmp >= ptr_.ptr());
    ptrdiff_t offs = tmp - ptr_.ptr();
    DCHECK(offs >= 0 && static_cast<size_t>(offs) < ptr_.len());

    return ptr_.addr() + offs;
  }

  size_t len() const { return ptr_.len(); }

 private:
  PEFilePtr ptr_;

  DISALLOW_COPY_AND_ASSIGN(PEFileStructPtr);
};

PEFileParser::PEFileParser(const PEFile& image_file,
                           BlockGraph::AddressSpace* address_space,
                           AddReferenceCallback* add_reference)
    : image_file_(image_file),
      address_space_(address_space),
      add_reference_(add_reference) {
}

bool PEFileParser::ParseImageHeader(PEHeader* header) {
  // Get the start of the image headers.
  const uint8* header_start =
      image_file_.GetImageData(RelativeAddress(0), sizeof(IMAGE_DOS_HEADER));

  if (header_start == NULL) {
    LOG(ERROR) << "No DOS header in image";
    return false;
  }

  // Chunk out the DOS header.
  BlockGraph::Block* dos_header = AddBlock(BlockGraph::DATA_BLOCK,
                                           RelativeAddress(0),
                                           sizeof(IMAGE_DOS_HEADER),
                                           "DOS Header");
  if (dos_header == NULL) {
    LOG(ERROR) << "Unable to add DOS header block";
    return false;
  }

  // Calculate the address of the NT headers.
  RelativeAddress nt_headers_address(
      reinterpret_cast<const uint8*>(image_file_.nt_headers()) -
          header_start);

  DCHECK(nt_headers_address.value() > sizeof(IMAGE_DOS_HEADER));

  // Chunk the DOS Stub.
  RelativeAddress dos_stub_address(sizeof(IMAGE_DOS_HEADER));
  BlockGraph::Block* dos_stub = AddBlock(BlockGraph::CODE_BLOCK,
                                         dos_stub_address,
                                         nt_headers_address - dos_stub_address,
                                         "DOS Stub");
  if (dos_stub == NULL) {
    LOG(ERROR) << "Unable to add DOS stub block";
    return false;
  }

  PEFileStructPtr<IMAGE_NT_HEADERS> nt_headers_ptr;
  if (!nt_headers_ptr.Read(image_file_, nt_headers_address)) {
    LOG(ERROR) << "Unable to read NT headers";
    return false;
  }

  // Chunk the NT headers.
  BlockGraph::Block* nt_headers = AddBlock(BlockGraph::DATA_BLOCK,
                                           nt_headers_address,
                                           sizeof(IMAGE_NT_HEADERS),
                                           "NT Headers");
  if (nt_headers == NULL) {
    LOG(ERROR) << "Unable to add NT Headers block";
    return false;
  }

  if (!AddRelative(nt_headers_ptr,
                   &nt_headers_ptr->OptionalHeader.AddressOfEntryPoint,
                   "Entry Point")) {
    LOG(ERROR) << "Unable to add entry point reference";
    return false;
  }

  BlockGraph::Block* data_directory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES] = {0};
  size_t num_dir_entries = nt_headers_ptr->OptionalHeader.NumberOfRvaAndSizes;
  DCHECK(num_dir_entries == IMAGE_NUMBEROF_DIRECTORY_ENTRIES);
  for (size_t i = 0; i < num_dir_entries; ++i) {
    const IMAGE_DATA_DIRECTORY& dir =
        nt_headers_ptr->OptionalHeader.DataDirectory[i];

    if (!AddRelative(nt_headers_ptr, &dir.VirtualAddress, kDirEntryNames[i])) {
      LOG(ERROR) << "Unable to add data directory reference for "
          << kDirEntryNames[i];
      return false;
    }

    // Chunk the datum.
    RelativeAddress dir_entry_start(dir.VirtualAddress);
    if (dir_entry_start.value() != 0) {
      BlockGraph::Block* block = AddBlock(BlockGraph::DATA_BLOCK,
                                          dir_entry_start,
                                          dir.Size,
                                          kDirEntryNames[i]);
      if (block == NULL) {
        LOG(ERROR) << "Unable to add block for " << kDirEntryNames[i];
        return false;
      }

      data_directory[i] = block;
    }
  }

  // Chunk out the image section headers.
  RelativeAddress image_section_header_address(
      nt_headers_address + sizeof(IMAGE_NT_HEADERS));
  BlockGraph::Size image_section_header_size = sizeof(IMAGE_SECTION_HEADER) *
      nt_headers_ptr->FileHeader.NumberOfSections;
  if (image_file_.GetImageData(image_section_header_address,
                               image_section_header_size) == NULL) {
    LOG(ERROR) << "Unable to read image section headers";
    return false;
  }

  BlockGraph::Block* image_section_headers = AddBlock(
      BlockGraph::DATA_BLOCK, image_section_header_address,
      image_section_header_size, "Image section headers");

  if (image_section_headers == NULL) {
    LOG(ERROR) << "Unable to create image section headers block";
    return false;
  }

  if (header != NULL) {
    header->dos_header = dos_header;
    header->dos_stub = dos_stub;
    header->nt_headers = nt_headers;
    header->image_section_headers = image_section_headers;
    for (int i = 0; i < arraysize(data_directory); ++i)
      header->data_directory[i] = data_directory[i];
  }

  return true;
}

bool PEFileParser::AddReference(RelativeAddress src,
                                BlockGraph::ReferenceType type,
                                BlockGraph::Size size,
                                RelativeAddress dst,
                                const char* name) {
  add_reference_->Run(src, type, size, dst, name);
  return true;
}

BlockGraph::Block* PEFileParser::AddBlock(BlockGraph::BlockType type,
                                     RelativeAddress addr,
                                     BlockGraph::Size size,
                                     const char* name) {
  BlockGraph::Block* block = address_space_->AddBlock(type, addr, size, name);
  if (block != NULL) {
    const uint8* data = image_file_.GetImageData(addr, size);
    if (data != NULL) {
      block->set_data(data);
      block->set_data_size(size);
    }
  }

  return block;
}

template <typename ItemType>
bool PEFileParser::AddRelative(const PEFileStructPtr<ItemType>& structure,
                               const DWORD* item,
                               const char* name) {
  DCHECK(item != NULL);
  if (*item == 0)
    return true;

  return AddReference(structure.AddressOf(item),
                      BlockGraph::RELATIVE_REF,
                      sizeof(*item),
                      RelativeAddress(*item),
                      name);
}

template <typename ItemType>
bool PEFileParser::AddAbsolute(const PEFileStructPtr<ItemType>& structure,
                               const DWORD* item,
                               const char* name) {
  DCHECK(item != NULL);
  if (*item == 0)
    return true;

  AbsoluteAddress abs(*item);
  RelativeAddress rel;

  return image_file_.Translate(abs, &rel) &&
      AddReference(structure.AddressOf(item),
                   BlockGraph::ABSOLUTE_REF,
                   sizeof(*item),
                   rel,
                   name);
}

template <typename ItemType>
bool PEFileParser::AddFileOffset(const PEFileStructPtr<ItemType>& structure,
                                 const DWORD* item,
                                 const char* name) {
  DCHECK(item != NULL);
  if (*item == 0)
    return true;

  FileOffsetAddress offs(*item);
  RelativeAddress rel;

  return image_file_.Translate(offs, &rel) &&
      AddReference(structure.AddressOf(item),
                   BlockGraph::ABSOLUTE_REF,
                   sizeof(*item),
                   rel,
                   name);
}

bool PEFileParser::ParseExportDirectory(BlockGraph::Block* export_dir_block) {
  PEFileStructPtr<IMAGE_EXPORT_DIRECTORY> export_dir;
  if (!export_dir.Set(export_dir_block)) {
    LOG(ERROR) << "Unable to read export directory";
    return false;
  }

  // All the references in the export directory should point back into
  // the export directory, sanity check this.
  DCHECK_EQ(export_dir_block, address_space_->GetContainingBlock(
      RelativeAddress(export_dir->AddressOfFunctions),
      sizeof(RelativeAddress)));
  DCHECK_EQ(export_dir_block, address_space_->GetContainingBlock(
      RelativeAddress(export_dir->AddressOfNames),
      sizeof(RelativeAddress)));
  DCHECK_EQ(export_dir_block, address_space_->GetContainingBlock(
      RelativeAddress(export_dir->AddressOfNameOrdinals),
      sizeof(RelativeAddress)));

  // Add the export directory references.
  if (!AddRelative(export_dir,
                   &export_dir->AddressOfFunctions,
                   "Export Functions")) {
    LOG(ERROR) << "Unable to add export functions reference.";
    return false;
  }

  if (!AddRelative(export_dir,
                   &export_dir->AddressOfNames,
                   "Export Address Of Names")) {
    LOG(ERROR) << "Unable to add export address of names reference.";
    return false;
  }

  if (!AddRelative(export_dir,
                   &export_dir->AddressOfNameOrdinals,
                   "Export Address Of Name Ordinals")) {
    LOG(ERROR) << "Unable to add export address of ordinals reference.";
    return false;
  }

  PEFileStructPtr<DWORD> function;
  if (!function.Set(export_dir_block,
                    RelativeAddress(export_dir->AddressOfFunctions))) {
    LOG(ERROR) << "Unable to parse export function table";
    return false;
  }

  for (size_t i = 0; i < export_dir->NumberOfFunctions; ++i) {
    // TODO(siggi): This could be labeled with the exported function's
    //    name, if one is available.
    if (!AddRelative(function, function.ptr(), "Exported Function")) {
      LOG(ERROR) << "Unable to add reference to exported function";
      return false;
    }

    if (!function.Next()) {
      LOG(ERROR) << "Unable to parse export function table";
      return false;
    }
  }

  // Add references to the export function names.
  PEFileStructPtr<DWORD> name;
  if (!name.Set(export_dir_block,
                RelativeAddress(export_dir->AddressOfNames))) {
    LOG(ERROR) << "Unable to parse export name table";
  }

  for (size_t i = 0; i < export_dir->NumberOfNames; ++i) {
    // All the names in the export directory should point back into
    // the export directory, sanity check this.
    DCHECK_EQ(export_dir_block, address_space_->GetContainingBlock(
        RelativeAddress(*name.ptr()),
        sizeof(RelativeAddress)));

    if (!AddRelative(name, name.ptr(), "Export Function Name")) {
      LOG(ERROR) << "Unable to add reference to export function name";
      return false;
    }

    if (!name.Next()) {
      LOG(ERROR) << "Unable to parse export function table";
      return false;
    }
  }

  return true;
}

bool PEFileParser::ParseTlsDirectory(BlockGraph::Block* tls_directory_block) {
  if (tls_directory_block == NULL)
    return true;

  PEFileStructPtr<IMAGE_TLS_DIRECTORY> tls_directory;
  if (!tls_directory.Set(tls_directory_block)) {
    LOG(ERROR) << "Unable to read the TLS directory";
    return false;
  }

  const IMAGE_TLS_DIRECTORY* dir = tls_directory.ptr();

  return true;
}

bool PEFileParser::ParseLoadConfig(BlockGraph::Block* load_config_block) {
  PEFileStructPtr<IMAGE_LOAD_CONFIG_DIRECTORY> load_config;

  // We read the load config directory directly from the image, because
  // it appears the data directory entry is 8 bytes short for some reason.
  if (!load_config.Read(image_file_, load_config_block->addr())) {
    LOG(ERROR) << "Unable to the load config directory";
    return false;
  }

  if (!AddAbsolute(
          load_config, &load_config->LockPrefixTable, "LockPrefixTable") ||
      !AddAbsolute(load_config, &load_config->EditList, "EditList") ||
      !AddAbsolute(
          load_config, &load_config->SecurityCookie, "SecurityCookie") ||
      !AddAbsolute(
          load_config, &load_config->SEHandlerTable, "SEHandlerTable")) {
    LOG(ERROR) << "Unable to add load config directory references";
    return false;
  }

  // Iterate the exception handlers and add references for them.
  RelativeAddress seh_handler;
  PEFileStructPtr<DWORD> seh_handlers;
  if (!image_file_.Translate(AbsoluteAddress(load_config->SEHandlerTable),
                             &seh_handler) ||
      !seh_handlers.Read(image_file_, seh_handler,
                         load_config->SEHandlerCount * sizeof(DWORD))) {
    LOG(ERROR) << "Unable to read SEH handler table";
    return false;
  }

  for (size_t i = 0; i < load_config->SEHandlerCount; ++i) {
    if (!AddRelative(seh_handlers, seh_handlers.ptr() + i, "SEH Handler")) {
      LOG(ERROR) << "Unable to add SEH handler reference";
      return false;
    }
  }

  return true;
}

bool PEFileParser::ParseDebugDirectory(
    BlockGraph::Block* debug_directory_block) {
  if (debug_directory_block == NULL)
    return true;

  PEFileStructPtr<IMAGE_DEBUG_DIRECTORY> debug_directory;
  if (!debug_directory.Set(debug_directory_block)) {
    LOG(ERROR) << "Unable to the debug directory";
    return false;
  }

  do {
    if (!AddRelative(debug_directory, &debug_directory->AddressOfRawData) ||
        !AddFileOffset(debug_directory, &debug_directory->PointerToRawData)) {
      LOG(ERROR) << "Failed to add debug directory references";
      return false;
    }

    // TODO(siggi): Does it make sense to chunk the data itself?
  } while (debug_directory.Next());

  return true;
}

}  // namespace image_util
