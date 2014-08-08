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

#include "syzygy/pe/pe_file_parser.h"

// The Win8 SDK defines this in winerror.h, and it is subsequently redefined by
// delayimp.h
#undef FACILITY_VISUALCPP
#include <delayimp.h>

#include "base/bind.h"
#include "base/strings/stringprintf.h"
#include "syzygy/common/align.h"

namespace pe {

namespace {

using block_graph::BlockGraph;
using core::AbsoluteAddress;
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

// Given a table type, and whether or not it is bound, returns the type of
// data we can expect to find in the table.
PEFileParser::ThunkDataType GetThunkDataType(
    PEFileParser::ThunkTableType table_type, bool is_bound) {
  switch (table_type) {
    case PEFileParser::kImportNameTable:
      return PEFileParser::kImageThunkData;

    case PEFileParser::kImportAddressTable:
      if (is_bound)
        return PEFileParser::kCodeOutOfImageThunkData;
      else
        return PEFileParser::kImageThunkData;

    case PEFileParser::kDelayLoadImportNameTable:
      return PEFileParser::kImageThunkData;

    case PEFileParser::kDelayLoadImportAddressTable:
      return PEFileParser::kCodeInImageThunkData;

    case PEFileParser::kDelayLoadBoundImportAddressTable:
      return PEFileParser::kArbitraryThunkData;

    default: break;
  }
  NOTREACHED() << "Unknown ThunkDataType.";
  return PEFileParser::kArbitraryThunkData;
}

bool DummyOnImportThunk(const char* module_name,
                        const char* symbol_name,
                        BlockGraph::Block* thunk) {
  return true;
}

}  // namespace

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
                           const AddReferenceCallback& add_reference)
    : image_file_(image_file),
      address_space_(address_space),
      add_reference_(add_reference),
      on_import_thunk_(base::Bind(&DummyOnImportThunk)) {
  DCHECK(!add_reference.is_null());
}

const PEFileParser::DataDirParseEntry PEFileParser::parsers_[] = {
  {
    IMAGE_DIRECTORY_ENTRY_EXPORT,
    "export",
    &PEFileParser::ParseExportDir
  }, {
    // We parse the IAT ahead of the imports because if the IAT entry is
    // present, we want it chunked and ready to reference before we start
    // parsing imports.
    IMAGE_DIRECTORY_ENTRY_IAT,
    "iat",
    &PEFileParser::ParseIatDir
  }, {
    IMAGE_DIRECTORY_ENTRY_IMPORT,
    "import",
    &PEFileParser::ParseImportDir
  }, {
    IMAGE_DIRECTORY_ENTRY_RESOURCE,
    "resource",
    &PEFileParser::ParseResourceDir
  }, {
    IMAGE_DIRECTORY_ENTRY_EXCEPTION,
    "exception",
    &PEFileParser::ParseExceptionDir
  }, {
    IMAGE_DIRECTORY_ENTRY_SECURITY,
    "security",
    &PEFileParser::ParseSecurityDir
  }, {
    IMAGE_DIRECTORY_ENTRY_BASERELOC,
    "relocs",
    &PEFileParser::ParseRelocDir
  }, {
    IMAGE_DIRECTORY_ENTRY_DEBUG,
    "debug",
    &PEFileParser::ParseDebugDir
  }, {
    IMAGE_DIRECTORY_ENTRY_ARCHITECTURE,
    "architecture",
    &PEFileParser::ParseArchitectureDir
  }, {
    IMAGE_DIRECTORY_ENTRY_GLOBALPTR,
    "global",
    &PEFileParser::ParseGlobalDir
  }, {
    IMAGE_DIRECTORY_ENTRY_TLS,
    "tls",
    &PEFileParser::ParseTlsDir
  }, {
    IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG,
    "load config",
    &PEFileParser::ParseLoadConfigDir
  }, {
    IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT,
    "bound import",
    &PEFileParser::ParseBoundImportDir
  }, {
    IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT,
    "delay import",
    &PEFileParser::ParseDelayImportDir
  }, {
    IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR,
    "com descriptor",
    &PEFileParser::ParseComDescriptorDir
  },
};

bool PEFileParser::ParseImage(PEHeader* pe_header) {
  if (!ParseImageHeader(pe_header)) {
    LOG(ERROR) << "Unable to parse image header.";
    return false;
  }

  for (size_t i = 0; i < arraysize(parsers_); ++i) {
    const DataDirParseEntry& parser = parsers_[i];
    DCHECK(parser.entry < IMAGE_NUMBEROF_DIRECTORY_ENTRIES);
    DCHECK(parser.parser != NULL);
    DCHECK(parser.name != NULL);

    const IMAGE_DATA_DIRECTORY& entry =
        image_file_.nt_headers()->OptionalHeader.DataDirectory[parser.entry];

    if (entry.Size != 0) {
      DCHECK(entry.VirtualAddress != 0);
      BlockGraph::Block* block = (this->*parser.parser)(entry);
      if (block == NULL) {
        LOG(ERROR) << "Failed to parse data directory " << parser.name << ".";
        return false;
      }

      pe_header->data_directory[parser.entry] = block;
    }
  }

  return true;
}

bool PEFileParser::ParseImageHeader(PEHeader* header) {
  // Get the start of the image headers.
  size_t dos_header_size =
      reinterpret_cast<const uint8*>(image_file_.nt_headers()) -
      reinterpret_cast<const uint8*>(image_file_.dos_header());

  if (dos_header_size < sizeof(IMAGE_DOS_HEADER)) {
    LOG(ERROR) << "Impossibly small DOS header.";
    return false;
  }

  PEFileStructPtr<IMAGE_DOS_HEADER> dos_header_ptr;
  if (!dos_header_ptr.Read(image_file_, RelativeAddress(0), dos_header_size)) {
    LOG(ERROR) << "No DOS header in image.";
    return false;
  }

  // The length of the DOS header is the address of the NT headers.
  RelativeAddress nt_headers_address(dos_header_size);
  DCHECK(nt_headers_address.value() > sizeof(IMAGE_DOS_HEADER));

  // Chunk out the DOS header and stub.
  BlockGraph::Block* dos_header = AddBlock(BlockGraph::DATA_BLOCK,
                                           RelativeAddress(0),
                                           nt_headers_address.value(),
                                           "DOS Header");
  if (dos_header == NULL) {
    LOG(ERROR) << "Unable to add DOS header block.";
    return false;
  }

  // Add the reference to the PE header. This reference can be interpreted
  // either as a disk or a relative reference, as disk and relative addresses
  // coincide in the image header.
  COMPILE_ASSERT(sizeof(DWORD) == sizeof(dos_header_ptr->e_lfanew),
                 dos_header_e_lfanew_is_wrong_size);
  if (!AddRelative(dos_header_ptr,
                   reinterpret_cast<const DWORD*>(&dos_header_ptr->e_lfanew))) {
    LOG(ERROR) << "Unable to add DOS to NT headers reference.";
    return false;
  }

  PEFileStructPtr<IMAGE_NT_HEADERS> nt_headers_ptr;
  if (!nt_headers_ptr.Read(image_file_, nt_headers_address)) {
    LOG(ERROR) << "Unable to read NT headers.";
    return false;
  }

  for (size_t i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++i) {
    if (!AddRelative(nt_headers_ptr,
            &nt_headers_ptr->OptionalHeader.DataDirectory[i].VirtualAddress)) {
      LOG(ERROR) << "Unable to add data directory reference for "
                 << kDirEntryNames[i];
      return false;
    }
  }

  // Calculate the size of the NT headers and section headers.
  size_t nt_headers_size = sizeof(IMAGE_NT_HEADERS) +
      nt_headers_ptr->FileHeader.NumberOfSections *
          sizeof(IMAGE_SECTION_HEADER);
  // Chunk the NT & section headers.
  BlockGraph::Block* nt_headers = AddBlock(BlockGraph::DATA_BLOCK,
                                           nt_headers_address,
                                           nt_headers_size,
                                           "NT Headers");
  if (nt_headers == NULL) {
    LOG(ERROR) << "Unable to add NT Headers block.";
    return false;
  }

  if (!AddRelative(nt_headers_ptr,
                   &nt_headers_ptr->OptionalHeader.AddressOfEntryPoint)) {
    LOG(ERROR) << "Unable to add entry point reference.";
    return false;
  }

  if (header != NULL) {
    header->dos_header = dos_header;
    header->nt_headers = nt_headers;
  }

  return true;
}

BlockGraph::Block* PEFileParser::ParseExportDir(
    const IMAGE_DATA_DIRECTORY& dir) {
  BlockGraph::Block* export_dir_block =
      AddBlock(BlockGraph::DATA_BLOCK,
               RelativeAddress(dir.VirtualAddress),
               dir.Size,
               "Export Directory");
  if (export_dir_block == NULL) {
    LOG(ERROR) << "Failed to create export directory block.";
    return NULL;
  }

  PEFileStructPtr<IMAGE_EXPORT_DIRECTORY> export_dir;
  if (!export_dir.Set(export_dir_block)) {
    LOG(ERROR) << "Unable to read export directory.";
    return NULL;
  }

  if (!AddRelative(export_dir, &export_dir->Name)) {
    LOG(ERROR) << "Unable to add export functions reference.";
    return NULL;
  }

  // All the references in the export directory should point back into
  // the export directory, unless they are NULL (empty).

  if (export_dir->AddressOfFunctions != 0) {
    DCHECK_EQ(export_dir_block, address_space_->GetContainingBlock(
        RelativeAddress(export_dir->AddressOfFunctions),
        sizeof(RelativeAddress)));
    if (!AddRelative(export_dir, &export_dir->AddressOfFunctions)) {
      LOG(ERROR) << "Unable to add export functions reference.";
      return NULL;
    }

    PEFileStructPtr<DWORD> function;
    if (!function.Set(export_dir_block,
                      RelativeAddress(export_dir->AddressOfFunctions))) {
      LOG(ERROR) << "Unable to parse export function table.";
      return NULL;
    }

    for (size_t i = 0; i < export_dir->NumberOfFunctions; ++i) {
      // TODO(siggi): This could be labeled with the exported function's
      //    name, if one is available.
      if (!AddRelative(function, function.ptr())) {
        LOG(ERROR) << "Unable to add reference to exported function.";
        return NULL;
      }

      if (!function.Next()) {
        LOG(ERROR) << "Unable to parse export function table.";
        return NULL;
      }
    }
  }

  if (export_dir->AddressOfNames != 0) {
    DCHECK_EQ(export_dir_block, address_space_->GetContainingBlock(
        RelativeAddress(export_dir->AddressOfNames),
        sizeof(RelativeAddress)));
    if (!AddRelative(export_dir, &export_dir->AddressOfNames)) {
      LOG(ERROR) << "Unable to add export address of names reference.";
      return NULL;
    }

    // Add references to the export function names.
    PEFileStructPtr<DWORD> name;
    if (!name.Set(export_dir_block,
                  RelativeAddress(export_dir->AddressOfNames))) {
      LOG(ERROR) << "Unable to parse export name table.";
    }

    for (size_t i = 0; i < export_dir->NumberOfNames; ++i) {
      // All the names in the export directory should point back into
      // the export directory, sanity check this.
      DCHECK_EQ(export_dir_block, address_space_->GetContainingBlock(
          RelativeAddress(*name.ptr()),
          sizeof(RelativeAddress)));

      if (!AddRelative(name, name.ptr())) {
        LOG(ERROR) << "Unable to add reference to export function name.";
        return NULL;
      }

      if (!name.Next()) {
        LOG(ERROR) << "Unable to parse export function table.";
        return NULL;
      }
    }
  }

  if (export_dir->AddressOfNameOrdinals != 0) {
    DCHECK_EQ(export_dir_block, address_space_->GetContainingBlock(
        RelativeAddress(export_dir->AddressOfNameOrdinals),
        sizeof(RelativeAddress)));
    if (!AddRelative(export_dir, &export_dir->AddressOfNameOrdinals)) {
      LOG(ERROR) << "Unable to add export address of ordinals reference.";
      return NULL;
    }
  }

  return export_dir_block;
}

size_t PEFileParser::CountImportThunks(RelativeAddress thunk_start) {
  size_t num_thunks = 0;
  for (; true; ++num_thunks, thunk_start += sizeof(IMAGE_THUNK_DATA)) {
    PEFileStructPtr<IMAGE_THUNK_DATA> thunk;
    if (!thunk.Read(image_file_, thunk_start)) {
      // We didn't get to the sentinel, that's an error.
      LOG(ERROR) << "Unable to read image import thunk.";
      return 0;
    }

    if (thunk->u1.AddressOfData == 0U)
      break;
  }

  return num_thunks;
}

bool PEFileParser::ParseImportThunks(RelativeAddress thunk_start,
                                     size_t num_thunks,
                                     bool is_bound,
                                     ThunkTableType table_type,
                                     const char* thunk_type,
                                     const char* import_name) {
  // Only certain table types may be bound.
  DCHECK(!is_bound || table_type == kImportAddressTable ||
             table_type == kDelayLoadBoundImportAddressTable);

  // Start by chunking the IAT/INT, including the terminating sentinel.
  size_t ixt_size = sizeof(IMAGE_THUNK_DATA) * (num_thunks + 1);

  std::string ixt_name =
      base::StringPrintf("%s for \"%s\"", thunk_type, import_name);

  BlockGraph::Block* thunk_block = NULL;
  if (table_type == kDelayLoadBoundImportAddressTable) {
    thunk_block = ChunkDelayBoundIATBlock(thunk_start, ixt_size,
                                          ixt_name.c_str());
  } else {
    // Try to add the block.
    thunk_block = AddBlock(BlockGraph::DATA_BLOCK,
                           thunk_start,
                           ixt_size,
                           ixt_name.c_str());

    // The IAT may have been chunked while parsing the IAT data directory,
    // in which case we want to leave a label for the start of our entries. In
    // this case we should be wholly contained in an existing block.
    if (thunk_block == NULL)
      thunk_block = address_space_->GetContainingBlock(thunk_start, ixt_size);
  }

  if (thunk_block == NULL) {
    LOG(ERROR) << "Unable to add " << thunk_type
               << "block for " << import_name;
    return false;
  }

  // Add a label to the start of the table.
  thunk_block->SetLabel(thunk_start - thunk_block->addr(),
                        ixt_name,
                        BlockGraph::DATA_LABEL);

  // Determine the type of data in the table. We only chunk out names for
  // import name tables. This prevents us from doing the work twice for an
  // unbound IAT.
  ThunkDataType thunk_data_type = GetThunkDataType(table_type, is_bound);
  bool chunk_names = table_type == kImportNameTable ||
      table_type == kDelayLoadImportNameTable;

  // Run through and validate the table contents, parsing IMAGE_IMPORT_BY_NAMES
  // if we're in an import name table.
  for (size_t i = 0; i < num_thunks; ++i) {
    if (!ParseImportThunk(thunk_start, thunk_data_type, thunk_type,
                          import_name, chunk_names)) {
      return false;
    }
    thunk_start += sizeof(IMAGE_THUNK_DATA);
  }

  return true;
}

bool PEFileParser::ParseImportThunk(RelativeAddress thunk_addr,
                                    ThunkDataType thunk_data_type,
                                    const char* thunk_type,
                                    const char* module_name,
                                    bool chunk_name) {
  // We can only chunk names if we're parsing an IMAGE_THUNK_DATA object.
  DCHECK(!chunk_name || thunk_data_type == kImageThunkData);

  PEFileStructPtr<IMAGE_THUNK_DATA> thunk;
  if (!thunk.Read(image_file_, thunk_addr)) {
    LOG(ERROR) << "Unable to read image import thunk.";
    return false;
  }

  switch (thunk_data_type) {
    case kNullThunkData: {
      if (thunk->u1.AddressOfData != 0) {
        LOG(ERROR) << "Expect NULL " << thunk_type << " thunk, got 0x"
                   << std::hex << thunk->u1.AddressOfData;
        return false;
      }
      break;
    }

    case kImageThunkData: {
      // If it's an ordinal, there's nothing to do.
      if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal))
        break;

      // It's not an ordinal, so it must contain an RVA to an
      // IMAGE_IMPORT_BY_NAME.

      // Add the IAT/INT->thunk reference.
      if (!AddRelative(thunk, &thunk->u1.AddressOfData)) {
        LOG(ERROR) << "Unable to add import thunk reference.";
        return false;
      }

      // Read the thunk and name & chunk it out.
      PEFileStructPtr<IMAGE_IMPORT_BY_NAME> name_thunk;
      RelativeAddress name_thunk_addr(thunk->u1.AddressOfData);
      if (!name_thunk.Read(image_file_, name_thunk_addr)) {
        LOG(ERROR) << "Unable to read import name thunk.";
        return false;
      }

      std::string function_name;
      RelativeAddress function_name_addr(
          name_thunk.AddressOf(&name_thunk->Name));
      if (!image_file_.ReadImageString(function_name_addr, &function_name)) {
        LOG(ERROR) << "Unable to read import function name.";
        return false;
      }

      // Calculate the even-padded size of the name thunk.
      size_t name_thunk_size = common::AlignUp(
          offsetof(IMAGE_IMPORT_BY_NAME, Name) + function_name.size() + 1, 2);

      // Chunk the names only on request, as more than one IAT/INT may
      // point to the same name blocks.
      if (chunk_name) {
        BlockGraph::Block* thunk = AddBlock(
            BlockGraph::DATA_BLOCK,
            name_thunk_addr,
            name_thunk_size,
            base::StringPrintf("Import Name Thunk \"%s\" from \"%s\"",
                               function_name.c_str(),
                               module_name).c_str());
        if (thunk == NULL) {
          LOG(ERROR) << "Unable to add function name block.";
          return false;
        }

        if (!on_import_thunk_.Run(module_name, function_name.c_str(), thunk)) {
          LOG(ERROR) << "OnImportThunk callback failed.";
          return false;
        }
      } else {
#ifndef NDEBUG
        // Check that the name blocks exist in debug.
        BlockGraph::Block* block =
            address_space_->GetBlockByAddress(name_thunk_addr);
        DCHECK(block != NULL);
        DCHECK_EQ(name_thunk_size, block->size());
#endif  // NDEBUG
      }
      break;
    }

    case kCodeInImageThunkData: {
      // Add the code reference. This will check that it is in fact a reference
      // to an address in the image, and track the associated block
      // automatically.
      if (!AddAbsolute(thunk, &thunk->u1.AddressOfData)) {
        LOG(ERROR) << "Unable to add import thunk reference.";
        return false;
      }
      break;
    }

    case kCodeOutOfImageThunkData: {
      // This is an absolute address to code outside of the image. It may
      // actually have an address that lies inside our image because the
      // imported module may have an overlapping preferred load address.
      if (thunk->u1.AddressOfData < 0x1000) {
        AbsoluteAddress abs_addr(thunk->u1.AddressOfData);
        LOG(ERROR) << thunk_type << " thunk to external code has invalid "
                   << "address: " << abs_addr;
        return false;
      }
      break;
    }

    case kArbitraryThunkData: {
      // We do nothing. Anything goes!
      break;
    }
  }

  return true;
}

BlockGraph::Block* PEFileParser::ChunkDelayBoundIATBlock(
    RelativeAddress iat_addr, size_t iat_size, const char* iat_name) {
  BlockGraph::Block* iat_block = AddBlock(BlockGraph::DATA_BLOCK,
                                          iat_addr,
                                          iat_size,
                                          iat_name);
  if (iat_block != NULL)
    return iat_block;

  // If we get here we were unable to create a block, so there must be a
  // conflict. We've seen the bound IATs for delay-loaded libraries be too
  // small. That is, one library's bound IAT is overwritten by another library's
  // bound IAT. We do our best to patch things up, by growing the conflicting
  // pre-existing block to also cover the range of the block we want to create.
  //
  // We extend the existing block by creating new blocks (one to the left, one
  // to the right) of the conflicting block that cover the portion of the new
  // table that is not covered. Then, we merge them all.

  iat_block = address_space_->GetFirstIntersectingBlock(iat_addr,
                                                        iat_size);
  VLOG(1) << iat_name << " collides with existing block " << iat_block->name()
          << ".";

  // If we're completely contained within the conflicting block, there's no
  // expanding and merging to do.
  if (iat_block->Contains(iat_addr, iat_size))
    return iat_block;

  // Create a block to the left of the existing block, if the desired table
  // extends to the left.
  if (iat_addr < iat_block->addr()) {
    size_t pre_size = iat_block->addr() - iat_addr;
    BlockGraph::Block* pre_block = AddBlock(BlockGraph::DATA_BLOCK,
                                            iat_addr,
                                            pre_size,
                                            iat_name);
    // This should never fail as iat_block is the *first* intersecting
    // block.
    DCHECK(pre_block != NULL);
  }

  // Insert the missing part of this table to the right of the intersecting
  // block, if there is any needed.
  RelativeAddress new_end = iat_addr + iat_size;
  RelativeAddress old_end = iat_block->addr() + iat_block->size();
  if (new_end > old_end) {
    BlockGraph::Block* next_block =
        address_space_->GetFirstIntersectingBlock(
            old_end, new_end - old_end);

    if (next_block != NULL)
      new_end = next_block->addr();

    if (new_end > old_end) {
      BlockGraph::Block* post_block = AddBlock(BlockGraph::DATA_BLOCK,
                                               old_end,
                                               new_end - old_end,
                                               NULL);
      // This should never fail as we're inserting after the end of
      // iat_block, and before the start of the next block in the
      // address space.
      DCHECK(post_block != NULL);
    }
  }

  // Merge the blocks to create one new contiguous block.
  BlockGraph::AddressSpace::Range range(iat_addr, iat_size);
  if (!address_space_->MergeIntersectingBlocks(range)) {
    LOG(ERROR) << "Unable to merge intersecting bound IAT blocks.";
    return NULL;
  }
  iat_block = address_space_->GetContainingBlock(iat_addr, iat_size);
  DCHECK(iat_block != NULL);

  return iat_block;
}

BlockGraph::Block* PEFileParser::ParseImportDir(
    const IMAGE_DATA_DIRECTORY& dir) {
  // Read the import descriptor, we're going to iterate it.
  RelativeAddress import_descriptor_addr(dir.VirtualAddress);
  PEFileStructPtr<IMAGE_IMPORT_DESCRIPTOR> import_descriptor;
  if (!import_descriptor.Read(image_file_,
                              import_descriptor_addr,
                              dir.Size)) {
    LOG(ERROR) << "Unable to read the import directory.";
    return NULL;
  }

  do {
    // The last import descriptor is a sentinel.
    if (import_descriptor->Characteristics == 0) {
      DCHECK_EQ(0U, import_descriptor->Name);
      DCHECK_EQ(0U, import_descriptor->FirstThunk);
      break;
    }

    // Read the name of the imported DLL.
    std::string import_name;
    RelativeAddress import_name_addr(import_descriptor->Name);
    if (!image_file_.ReadImageString(import_name_addr, &import_name)) {
      LOG(ERROR) << "Unable to read import name.";
      return NULL;
    }

    if (!AddBlock(BlockGraph::DATA_BLOCK,
                  import_name_addr,
                  common::AlignUp(import_name.size() + 1, 2),
                  base::StringPrintf("Import DLL Name \"%s\"",
                                     import_name.c_str()).c_str())) {
      LOG(ERROR) << "Unable to create import name block.";
      return NULL;
    }

    if (!AddRelative(import_descriptor, &import_descriptor->Name)) {
      LOG(ERROR) << "Unable to add import name reference.";
      return NULL;
    }

    // Count the number of import name thunks for this import descriptor.
    RelativeAddress thunk_addr =
        RelativeAddress(import_descriptor->OriginalFirstThunk);
    size_t num_thunks = CountImportThunks(thunk_addr);
    if (num_thunks == 0)
      return NULL;

    // Parse the Import Name Table.
    if (!ParseImportThunks(thunk_addr, num_thunks, false,
                           kImportNameTable, "INT", import_name.c_str())) {
      return NULL;
    }

    // Parse the Import Address Table.
    bool iat_is_bound = import_descriptor->TimeDateStamp != 0;
    if (!ParseImportThunks(RelativeAddress(import_descriptor->FirstThunk),
                           num_thunks, iat_is_bound,
                           kImportAddressTable, "IAT", import_name.c_str())) {
      return NULL;
    }

    if (!AddRelative(import_descriptor,
                     &import_descriptor->OriginalFirstThunk)) {
      LOG(ERROR) << "Unable to add import name table reference.";
      return NULL;
    }

    if (!AddRelative(import_descriptor, &import_descriptor->FirstThunk)) {
      LOG(ERROR) << "Unable to add import address table reference.";
      return NULL;
    }
  } while (import_descriptor.Next());

  BlockGraph::Block* import_descriptor_block =
      AddBlock(BlockGraph::DATA_BLOCK,
               import_descriptor_addr,
               import_descriptor.addr() - import_descriptor_addr +
                   sizeof(IMAGE_IMPORT_DESCRIPTOR),
               "Import Directory");

  return import_descriptor_block;
}

BlockGraph::Block *PEFileParser::ParseComDescriptorDir(
    const IMAGE_DATA_DIRECTORY &dir) {
  LOG(ERROR) << "Parsing for COM descriptors not implemented.";
  return NULL;
}

BlockGraph::Block *PEFileParser::ParseDelayImportDir(
    const IMAGE_DATA_DIRECTORY &dir) {
  // Read the delay import descriptor, we're going to iterate it.
  RelativeAddress import_descriptor_addr(dir.VirtualAddress);
  PEFileStructPtr<ImgDelayDescr> import_descriptor;
  if (!import_descriptor.Read(image_file_,
                              import_descriptor_addr,
                              dir.Size)) {
    LOG(ERROR) << "Unable to read the delay import directory.";
    return NULL;
  }

  do {
    // The last descriptor is a sentinel.
    if (import_descriptor->grAttrs == 0)
      break;

    if (import_descriptor->grAttrs != dlattrRva) {
      LOG(ERROR) << "Unexpected attributes in delay import descriptor 0x"
                 << std::hex << import_descriptor->grAttrs;
      return NULL;
    }

    // Read the name of the delay imported DLL.
    std::string import_name;
    RelativeAddress import_name_addr(import_descriptor->rvaDLLName);
    if (!image_file_.ReadImageString(import_name_addr, &import_name)) {
      LOG(ERROR) << "Unable to read delay import name.";
      return NULL;
    }

    if (!AddBlock(BlockGraph::DATA_BLOCK,
                  import_name_addr,
                  common::AlignUp(import_name.size() + 1, 2),
                  base::StringPrintf("Delay import DLL Name \"%s\"",
                                     import_name.c_str()).c_str())) {
      LOG(ERROR) << "Unable to create import name block.";
      return NULL;
    }

    if (!AddRelative(import_descriptor, &import_descriptor->rvaDLLName)) {
      LOG(ERROR) << "Unable to add delay import name reference.";
      return NULL;
    }

    // Chunk the HMODULE for this import.
    if (!AddBlock(BlockGraph::DATA_BLOCK,
                  RelativeAddress(import_descriptor->rvaHmod),
                  sizeof(HMODULE),
                  base::StringPrintf("Module handle for delay import DLL\"%s\"",
                                     import_name.c_str()).c_str())) {
      LOG(ERROR) << "Unable to create import module handle block.";
      return NULL;
    }

    if (!AddRelative(import_descriptor, &import_descriptor->rvaHmod)) {
      LOG(ERROR) << "Unable to delay import module handle reference.";
      return NULL;
    }

    // Count the number of import name thunks for this import descriptor.
    RelativeAddress int_addr(import_descriptor->rvaINT);
    size_t num_thunks = CountImportThunks(int_addr);
    if (num_thunks == 0)
      return NULL;

    // Parse the Delay Import Name Table.
    if (!ParseImportThunks(int_addr, num_thunks, false,
                           kDelayLoadImportNameTable, "DelayINT",
                           import_name.c_str())) {
      return NULL;
    }

    if (!AddRelative(import_descriptor, &import_descriptor->rvaINT)) {
      LOG(ERROR) << "Unable to add delay import name table reference.";
      return NULL;
    }

    // Parse the Delay Import Address Table.
    if (!ParseImportThunks(RelativeAddress(import_descriptor->rvaIAT),
                           num_thunks, false,
                           kDelayLoadImportAddressTable, "DelayIAT",
                           import_name.c_str())) {
      return NULL;
    }

    if (!AddRelative(import_descriptor, &import_descriptor->rvaIAT)) {
      LOG(ERROR) << "Unable to add delay import address table reference.";
      return NULL;
    }

    // Parse the Bound Import Address Table.
    bool iat_is_bound = import_descriptor->dwTimeStamp != 0;
    if (!ParseImportThunks(RelativeAddress(import_descriptor->rvaBoundIAT),
                           num_thunks, iat_is_bound,
                           kDelayLoadBoundImportAddressTable, "DelayBoundIAT",
                           import_name.c_str())) {
      return NULL;
    }

    if (!AddRelative(import_descriptor, &import_descriptor->rvaBoundIAT)) {
      LOG(ERROR) << "Unable to add delay bound import address table reference.";
      return NULL;
    }

    if (import_descriptor->rvaUnloadIAT != 0U) {
      LOG(ERROR) << "Unexpected UnloadIAT.";
      return NULL;
    }

    if (import_descriptor->dwTimeStamp != 0U) {
      LOG(ERROR) << "Unexpected bound delay imports.";
      return NULL;
    }
  } while (import_descriptor.Next());

  BlockGraph::Block* import_descriptor_block =
      AddBlock(BlockGraph::DATA_BLOCK,
               import_descriptor_addr,
               import_descriptor.addr() - import_descriptor_addr +
                   sizeof(ImgDelayDescr),
               "Delay Import Directory");

  return import_descriptor_block;
}

BlockGraph::Block *PEFileParser::ParseIatDir(
    const IMAGE_DATA_DIRECTORY &dir) {
  return AddBlock(BlockGraph::DATA_BLOCK,
                  RelativeAddress(dir.VirtualAddress),
                  dir.Size,
                  "Import Address Table");
}

BlockGraph::Block *PEFileParser::ParseBoundImportDir(
    const IMAGE_DATA_DIRECTORY &dir) {
  LOG(ERROR) << "Parsing for bound import dir not implemented.";
  return NULL;
}

BlockGraph::Block *PEFileParser::ParseGlobalDir(
    const IMAGE_DATA_DIRECTORY &dir) {
  LOG(ERROR) << "Parsing for global dir not implemented.";
  return NULL;
}

BlockGraph::Block *PEFileParser::ParseArchitectureDir(
    const IMAGE_DATA_DIRECTORY &dir) {
  LOG(ERROR) << "Parsing for architecture dir not implemented.";
  return NULL;
}

BlockGraph::Block *PEFileParser::ParseRelocDir(
    const IMAGE_DATA_DIRECTORY &dir) {
  return AddBlock(BlockGraph::DATA_BLOCK,
                  RelativeAddress(dir.VirtualAddress),
                  dir.Size,
                  "Relocations");
}

BlockGraph::Block *PEFileParser::ParseSecurityDir(
    const IMAGE_DATA_DIRECTORY &dir) {
  LOG(ERROR) << "Parsing for security dir not implemented.";
  return NULL;
}

BlockGraph::Block *PEFileParser::ParseExceptionDir(
    const IMAGE_DATA_DIRECTORY &dir) {
  LOG(ERROR) << "Parsing for exception dir not implemented.";
  return NULL;
}

BlockGraph::Block* PEFileParser::ParseTlsDir(
    const IMAGE_DATA_DIRECTORY& dir) {
  BlockGraph::Block* tls_directory_block =
      AddBlock(BlockGraph::DATA_BLOCK,
               RelativeAddress(dir.VirtualAddress),
               sizeof(IMAGE_TLS_DIRECTORY),
               "Tls Directory");
  if (tls_directory_block == NULL)
    return NULL;

  PEFileStructPtr<IMAGE_TLS_DIRECTORY> tls_directory;
  if (!tls_directory.Set(tls_directory_block)) {
    LOG(ERROR) << "Unable to read the TLS directory.";
    return NULL;
  }

  return tls_directory_block;
}

BlockGraph::Block* PEFileParser::ParseLoadConfigDir(
    const IMAGE_DATA_DIRECTORY& dir) {
  // We chunk the load config directory to sizeof(IMAGE_LOAD_CONFIG_DIRECTORY),
  // because it appears the VC9 linker leaves the data directory entry 8 bytes
  // short for some strange reason.
  BlockGraph::Block* load_config_block =
      AddBlock(BlockGraph::DATA_BLOCK,
               RelativeAddress(dir.VirtualAddress),
               sizeof(IMAGE_LOAD_CONFIG_DIRECTORY),
               "Load Config Directory");

  PEFileStructPtr<IMAGE_LOAD_CONFIG_DIRECTORY> load_config;
  if (!load_config.Set(load_config_block)) {
    LOG(ERROR) << "Unable to the load config directory.";
    return NULL;
  }

  if (!AddAbsolute(load_config, &load_config->LockPrefixTable) ||
      !AddAbsolute(load_config, &load_config->EditList) ||
      !AddAbsolute(load_config, &load_config->SecurityCookie) ||
      !AddAbsolute(load_config, &load_config->SEHandlerTable)) {
    LOG(ERROR) << "Unable to add load config directory references.";
    return NULL;
  }

  // Iterate the exception handlers and add references for them.
  RelativeAddress seh_handler;
  PEFileStructPtr<DWORD> seh_handlers;
  if (!image_file_.Translate(AbsoluteAddress(load_config->SEHandlerTable),
                             &seh_handler) ||
      !seh_handlers.Read(image_file_, seh_handler,
                         load_config->SEHandlerCount * sizeof(DWORD))) {
    LOG(ERROR) << "Unable to read SEH handler table.";
    return NULL;
  }

  for (size_t i = 0; i < load_config->SEHandlerCount; ++i) {
    if (!AddRelative(seh_handlers, seh_handlers.ptr() + i)) {
      LOG(ERROR) << "Unable to add SEH handler reference.";
      return NULL;
    }
  }

  return load_config_block;
}

BlockGraph::Block* PEFileParser::ParseDebugDir(
    const IMAGE_DATA_DIRECTORY& dir) {
  BlockGraph::Block* debug_directory_block =
      AddBlock(BlockGraph::DATA_BLOCK,
               RelativeAddress(dir.VirtualAddress),
               dir.Size,
               "Debug Directory");
  if (debug_directory_block == NULL)
    return NULL;

  PEFileStructPtr<IMAGE_DEBUG_DIRECTORY> debug_directory;
  if (!debug_directory.Set(debug_directory_block)) {
    LOG(ERROR) << "Unable to read the debug directory.";
    return NULL;
  }

  do {
    if (!AddRelative(debug_directory, &debug_directory->AddressOfRawData) ||
        !AddFileOffset(debug_directory, &debug_directory->PointerToRawData)) {
      LOG(ERROR) << "Failed to add debug directory references.";
      return NULL;
    }

    // Chunk the data referenced by the debug directory entry.
    BlockGraph::Block* debug_data =
        AddBlock(BlockGraph::DATA_BLOCK,
                 RelativeAddress(debug_directory->AddressOfRawData),
                 debug_directory->SizeOfData,
                 "Debug Info");
  } while (debug_directory.Next());

  return debug_directory_block;
}

BlockGraph::Block* PEFileParser::ParseResourceDir(
    const IMAGE_DATA_DIRECTORY& dir) {
  BlockGraph::Block* resource_block =
      AddBlock(BlockGraph::DATA_BLOCK,
               RelativeAddress(dir.VirtualAddress),
               dir.Size,
               "Resource Directory");
  if (resource_block == NULL)
    return NULL;

  if (!ParseResourceDirImpl(resource_block, 0))
    return NULL;

  return resource_block;
}

bool PEFileParser::ParseResourceDirImpl(BlockGraph::Block* resource_block,
                                        size_t root_offset) {
  DCHECK(resource_block != NULL);
  RelativeAddress root_addr = resource_block->addr();

  // Setup the directory node we're currently scanning.
  PEFileStructPtr<IMAGE_RESOURCE_DIRECTORY> directory;
  if (!directory.Set(resource_block, root_addr + root_offset)) {
    LOG(ERROR) << "Unable to read the resource directory.";
    return false;
  }

  // How many entries hang from this node in the resource tree?
  size_t num_entries = directory->NumberOfNamedEntries +
      directory->NumberOfIdEntries;
  size_t entry_offset = root_offset + sizeof(IMAGE_RESOURCE_DIRECTORY);

  // Let's walk through them.
  for (size_t i = 0; i < num_entries; ++i) {
    // Note that the offsets in the directory entries are all relative to
    // the root address of the resource block.
    PEFileStructPtr<IMAGE_RESOURCE_DIRECTORY_ENTRY> directory_entry;
    if (!directory_entry.Set(resource_block, root_addr + entry_offset)) {
      LOG(ERROR) << "Unable to read the resource directory entry.";
      return false;
    }
    if (directory_entry->DataIsDirectory) {
      if (!ParseResourceDirImpl(resource_block,
                                directory_entry->OffsetToDirectory)) {
        return false;
      }
    } else {
      PEFileStructPtr<IMAGE_RESOURCE_DATA_ENTRY> data_entry;
      RelativeAddress entry_addr(root_addr + directory_entry->OffsetToData);
      if (!data_entry.Set(resource_block, entry_addr)) {
        LOG(ERROR) << "Unable to read the resource data entry.";
        return false;
      }
      // The offsets in the data entries are RVAs.
      if (!AddRelative(data_entry, &data_entry->OffsetToData)) {
        LOG(ERROR) << "Failed to add resouce data reference.";
        return false;
      }
    }
    entry_offset += sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);
  }

  return true;
}

bool PEFileParser::AddReference(RelativeAddress src,
                                BlockGraph::ReferenceType type,
                                BlockGraph::Size size,
                                RelativeAddress dst) {
  return add_reference_.Run(src, type, size, dst);
}

BlockGraph::Block* PEFileParser::AddBlock(BlockGraph::BlockType type,
                                          RelativeAddress addr,
                                          BlockGraph::Size size,
                                          const char* name) {
  BlockGraph::Block* block = address_space_->AddBlock(type, addr, size, name);
  if (block != NULL) {
    block->set_attribute(BlockGraph::PE_PARSED);

    // Mark the source range from whence this block originates.
    bool pushed = block->source_ranges().Push(
        BlockGraph::Block::DataRange(0, size),
        BlockGraph::Block::SourceRange(addr, size));
    DCHECK(pushed);

    // Set the section for this block. We let blocks that belong to the header
    // be marked with kInvalidSectionId.
    size_t section = image_file_.GetSectionIndex(addr, size);
    if (section == BlockGraph::kInvalidSectionId) {
      // If no section was found for this block, we expect it to be a part of
      // the header.
      const RelativeAddress end_of_headers(
          image_file_.nt_headers()->OptionalHeader.SizeOfHeaders);
      if (addr + size > end_of_headers) {
        LOG(ERROR) << "Found a non-header block outside of sections.";
        return NULL;
      }
    }
    block->set_section(section);

    const uint8* data = image_file_.GetImageData(addr, size);
    if (data != NULL)
      block->SetData(data, size);
  }

  return block;
}

template <typename ItemType>
bool PEFileParser::AddRelative(const PEFileStructPtr<ItemType>& structure,
                               const DWORD* item) {
  DCHECK(item != NULL);
  if (*item == 0)
    return true;

  return AddReference(structure.AddressOf(item),
                      BlockGraph::RELATIVE_REF,
                      sizeof(*item),
                      RelativeAddress(*item));
}

template <typename ItemType>
bool PEFileParser::AddAbsolute(const PEFileStructPtr<ItemType>& structure,
                               const DWORD* item) {
  DCHECK(item != NULL);
  if (*item == 0)
    return true;

  AbsoluteAddress abs(*item);
  RelativeAddress rel;

  // We expect item to be the direct (0 offset) absolute address of the
  // in-image file structure. So, translation to an in-image relative
  // address is expected to yield a valid RVA.
  return image_file_.Translate(abs, &rel) &&
      AddReference(structure.AddressOf(item),
                   BlockGraph::ABSOLUTE_REF,
                   sizeof(*item),
                   rel);
}

template <typename ItemType>
bool PEFileParser::AddFileOffset(const PEFileStructPtr<ItemType>& structure,
                                 const DWORD* item) {
  DCHECK(item != NULL);
  if (*item == 0)
    return true;

  FileOffsetAddress offs(*item);
  RelativeAddress rel;

  // We expect item to be the direct (0 offset) file offset address of the
  // in-image file structure. So, translation to an in-image relative
  // address is expected to yield a valid RVA.
  return image_file_.Translate(offs, &rel) &&
      AddReference(structure.AddressOf(item),
                   BlockGraph::FILE_OFFSET_REF,
                   sizeof(*item),
                   rel);
}

}  // namespace pe
