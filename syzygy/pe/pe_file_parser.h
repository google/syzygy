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

#ifndef SYZYGY_PE_PE_FILE_PARSER_H_
#define SYZYGY_PE_PE_FILE_PARSER_H_

#include "base/callback.h"
#include "syzygy/block_graph/block_graph.h"
#include "syzygy/core/address.h"
#include "syzygy/pe/pe_file.h"

namespace pe {

// Forward declaration.
template <class ItemType> class PEFileStructPtr;

// This class parses the PE image data in an PEImage instance, chunks out
// the image header and various other PE image sections to an address space.
class PEFileParser {
 public:
  typedef block_graph::BlockGraph BlockGraph;
  typedef core::RelativeAddress RelativeAddress;

  typedef base::Callback<bool(RelativeAddress,
                              BlockGraph::ReferenceType,
                              BlockGraph::Size,
                              RelativeAddress)>
      AddReferenceCallback;

  // Callback that is invoked for every named import thunk that is parsed. The
  // arguments are as follows:
  //   1. const char* module_name
  //      The name of the module being imported.
  //   2. const char* symbol_name
  //      The name of the imported symbol.
  //   3. BlockGraph::Block* thunk
  //      The block containing the thunk which will be initialized to point to
  //      the symbol at runtime.
  typedef base::Callback<bool(const char*,
                              const char*,
                              BlockGraph::Block*)>
      OnImportThunkCallback;

  PEFileParser(const PEFile& image_file,
               BlockGraph::AddressSpace* address_space,
               const AddReferenceCallback& add_reference);

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

  void set_on_import_thunk(const OnImportThunkCallback& on_import_thunk) {
    on_import_thunk_ = on_import_thunk;
  }

  // Parses the image, chunks the various blocks it decomposes into and
  // invokes the AddReferenceCallback for all references encountered.
  bool ParseImage(PEHeader* pe_header);

  // Tables of thunks come in various flavours.
  enum ThunkTableType {
    // For parsing of normal imports.
    kImportNameTable,
    kImportAddressTable,

    // For parsing of delay-load imports.
    kDelayLoadImportNameTable,
    kDelayLoadImportAddressTable,
    kDelayLoadBoundImportAddressTable,
  };

  // Thunks in import tables may point to various discrete things. These depend
  // on the ThunkTableType and whether or not the table is bound.
  enum ThunkDataType {
    kNullThunkData,  // Pointer values should all be NULL.
    kImageThunkData,  // IMAGE_THUNK_DATA containing RelativeAddress to a string
                      // in the image.
    kCodeInImageThunkData,  // AbsoluteAddress in image.
    kCodeOutOfImageThunkData,  // AbsoluteAddress out of image.
    kArbitraryThunkData,  // Anything goes.
  };

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
  // Counts the number of import thunks in the run starting at thunk_start.
  // @returns the number of thunks excluding the terminating sentinel, or
  //     zero on error.
  size_t CountImportThunks(RelativeAddress thunk_start);

  // Parses the IAT/INT/BoundIAT starting at thunk_start.
  // @param thunk_start the RVA where the import thunks start.
  // @param is_bound true iff thunks are bound, in which case we tag absolute
  //     references instead of relative. This may only be true if table_type is
  //     kImportAddressTable or kDelayLoadImportAddressTable.
  // @param table_type the type of thunk table.
  // @param thunk_type human readable type for thunk.
  // @param import_name name of imported dll.
  // @returns true on success, false otherwise.
  bool ParseImportThunks(RelativeAddress thunk_start,
                         size_t num_thunks,
                         bool is_bound,
                         ThunkTableType table_type,
                         const char* thunk_type,
                         const char* import_name);
  // Parse a single entry in an import table.
  // @param thunk_addr the address of the thunk.
  // @param thunk_data_type the type of data in the thunk.
  // @param thunk_type human readable type for thunk.
  // @param chunk_name if true, and thunk_data_type is kImageThunkData, will
  //     parse out the referenced IMAGE_THUNK_DATA as a block.
  // @returns true on success, false otherwise.
  bool ParseImportThunk(RelativeAddress thunk_addr,
                        ThunkDataType thunk_data_type,
                        const char* thunk_type,
                        const char* module_name,
                        bool chunk_name);

  // Special handling for delay-load bound import address tables. We've seen
  // cases in actual binaries where these are malformed. This is generally not
  // an issue, but we handle these a little more loosely so that we can complete
  // the decomposition process. If such malformed tables are encountered, this
  // will causes a warning to be logged.
  // @param iat_addr the beginning of the delay-load bound IAT.
  // @param iat_size the expected size of the delay-load bound IAT.
  // @param iat_name the name to give the chunked block, or the label to
  //     associate with iat_addr in an existing block.
  // @returns the block containing the delay-load IAT table.
  BlockGraph::Block* ChunkDelayBoundIATBlock(RelativeAddress iat_addr,
                                             size_t iat_size,
                                             const char* iat_name);

  BlockGraph::Block* AddBlock(BlockGraph::BlockType type,
                              RelativeAddress addr,
                              BlockGraph::Size size,
                              const char* name);

  bool AddReference(RelativeAddress src,
                    BlockGraph::ReferenceType type,
                    BlockGraph::Size size,
                    RelativeAddress dst);

  template <typename ItemType>
  bool AddRelative(const PEFileStructPtr<ItemType>& structure,
                   const DWORD* item);

  template <typename ItemType>
  bool AddAbsolute(const PEFileStructPtr<ItemType>& structure,
                   const DWORD* item);

  template <typename ItemType>
  bool MaybeAddAbsolute(const PEFileStructPtr<ItemType>& structure,
                        const DWORD* item);

  template <typename ItemType>
  bool AddFileOffset(const PEFileStructPtr<ItemType>& structure,
                     const DWORD* item);

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
  AddReferenceCallback add_reference_;
  OnImportThunkCallback on_import_thunk_;
};

}  // namespace pe

#endif  // SYZYGY_PE_PE_FILE_PARSER_H_
