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
#ifndef SYZYGY_PE_PE_FILE_PARSER_H_
#define SYZYGY_PE_PE_FILE_PARSER_H_

#include "base/callback.h"
#include "syzygy/core/address.h"
#include "syzygy/core/block_graph.h"
#include "syzygy/pe/pe_file.h"

namespace pe {

// Forward declaration.
template <class ItemType> class PEFileStructPtr;

// This class parses the PE image data in an PEImage instance, chunks out
// the image header and various other PE image sections to an address space.
class PEFileParser {
 public:
  typedef core::BlockGraph BlockGraph;
  typedef core::RelativeAddress RelativeAddress;

  typedef Callback5<RelativeAddress,
                    BlockGraph::ReferenceType,
                    BlockGraph::Size,
                    RelativeAddress,
                    const char*>::Type
      AddReferenceCallback;

  PEFileParser(const PEFile& image_file,
               BlockGraph::AddressSpace* address_space,
               AddReferenceCallback* add_reference);

  struct PEHeader {
    PEHeader() {
      memset(this, 0, sizeof(*this));
    }

    // The block that describes the DOS header, including the DOS stub.
    BlockGraph::Block* dos_header;

    // The block that describes the NT and the section headers.
    BlockGraph::Block* nt_headers;

    // The blocks that describe the data directory chunks.
    BlockGraph::Block* data_directory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
  };

  // Parses the image, chunks the various blocks it decomposes into and
  // invokes the AddReferenceCallback for all references encountered.
  bool ParseImage(PEHeader* pe_header);

 protected:
  // Parses the image header, chunks the various blocks it refers and
  // invokes the AddReferenceCallback for all references encountered.
  bool ParseImageHeader(PEHeader* pe_header);

  // These methods parse a given data directory section, chunk out the blocks
  // and create references as they're encountered.
  // @param dir the data directory entry.
  // @returns the chunked block for that directory, or NULL on error.
  // IMAGE_DIRECTORY_ENTRY_EXPORT
  BlockGraph::Block* ParseExportDir(const IMAGE_DATA_DIRECTORY& dir);
  // IMAGE_DIRECTORY_ENTRY_IMPORT
  BlockGraph::Block* ParseImportDir(const IMAGE_DATA_DIRECTORY& dir);
  // IMAGE_DIRECTORY_ENTRY_RESOURCE
  BlockGraph::Block* ParseResourceDir(const IMAGE_DATA_DIRECTORY& dir);
  // IMAGE_DIRECTORY_ENTRY_EXCEPTION
  BlockGraph::Block* ParseExceptionDir(const IMAGE_DATA_DIRECTORY& dir);
  // IMAGE_DIRECTORY_ENTRY_SECURITY
  BlockGraph::Block* ParseSecurityDir(const IMAGE_DATA_DIRECTORY& dir);
  // IMAGE_DIRECTORY_ENTRY_BASERELOC
  BlockGraph::Block* ParseRelocDir(const IMAGE_DATA_DIRECTORY& dir);
  // IMAGE_DIRECTORY_ENTRY_DEBUG
  BlockGraph::Block* ParseDebugDir(const IMAGE_DATA_DIRECTORY& dir);
  // IMAGE_DIRECTORY_ENTRY_ARCHITECTURE
  BlockGraph::Block* ParseArchitectureDir(const IMAGE_DATA_DIRECTORY& dir);
  // IMAGE_DIRECTORY_ENTRY_GLOBALPTR
  BlockGraph::Block* ParseGlobalDir(const IMAGE_DATA_DIRECTORY& dir);
  // IMAGE_DIRECTORY_ENTRY_TLS
  BlockGraph::Block* ParseTlsDir(const IMAGE_DATA_DIRECTORY& dir);
  // IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG
  BlockGraph::Block* ParseLoadConfigDir(const IMAGE_DATA_DIRECTORY& dir);
  // IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT
  BlockGraph::Block* ParseBoundImportDir(const IMAGE_DATA_DIRECTORY& dir);
  // IMAGE_DIRECTORY_ENTRY_IAT
  BlockGraph::Block* ParseIatDir(const IMAGE_DATA_DIRECTORY& dir);
  // IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT
  BlockGraph::Block* ParseDelayImportDir(const IMAGE_DATA_DIRECTORY& dir);
  // IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
  BlockGraph::Block* ParseComDescriptorDir(const IMAGE_DATA_DIRECTORY& dir);

 private:
  // Parses the IAT/INT starting at thunk_start.
  bool ParseImportThunks(RelativeAddress thunk_start,
                         bool is_iat,
                         const char* import_name);

  BlockGraph::Block* AddBlock(BlockGraph::BlockType type,
                              RelativeAddress addr,
                              BlockGraph::Size size,
                              const char* name);

  bool AddReference(RelativeAddress src,
                    BlockGraph::ReferenceType type,
                    BlockGraph::Size size,
                    RelativeAddress dst,
                    const char* name);

  template <typename ItemType>
  bool AddRelative(const PEFileStructPtr<ItemType>& structure,
                   const DWORD* item,
                   const char* name);

  template <typename ItemType>
  bool AddAbsolute(const PEFileStructPtr<ItemType>& structure,
                   const DWORD* item,
                   const char* name = NULL);

  template <typename ItemType>
  bool AddFileOffset(const PEFileStructPtr<ItemType>& structure,
                     const DWORD* item,
                     const char* name = NULL);

  bool ParseResourceDirImpl(BlockGraph::Block* resource_block,
                            size_t root_offset);

  // Pointer to a data dir parser function.
  typedef BlockGraph::Block* (PEFileParser::*ParseDirFunction)(
      const IMAGE_DATA_DIRECTORY& dir);

  struct DataDirParseEntry {
    int entry;
    const char* name;
    ParseDirFunction parser;
  };

  // Array of data directory parser entries used to parse the
  // sundry data directory entries.
  static const DataDirParseEntry parsers_[];

  const PEFile& image_file_;
  BlockGraph::AddressSpace* address_space_;
  AddReferenceCallback* add_reference_;
};

}  // namespace pe

#endif  // SYZYGY_PE_PE_FILE_PARSER_H_
