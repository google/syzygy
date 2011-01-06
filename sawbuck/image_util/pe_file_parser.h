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
#ifndef SAWBUCK_IMAGE_UTIL_PE_FILE_PARSER_H_
#define SAWBUCK_IMAGE_UTIL_PE_FILE_PARSER_H_

#include "base/callback.h"
#include "sawbuck/image_util/address.h"
#include "sawbuck/image_util/block_graph.h"
#include "sawbuck/image_util/pe_file.h"

namespace image_util {

// Forward declaration.
template <class ItemType> class PEFileStructPtr;

// This class parses the PE image data in an PEImage instance, chunks out
// the image header and various other PE image sections to an address space.
class PEFileParser {
 public:
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
      memset(this, 0, sizeof(this));
    }

    // The block that describes the DOS header.
    BlockGraph::Block* dos_header;

    // The block that describes the DOS stub (if any).
    BlockGraph::Block* dos_stub;

    // The block that describes the NT headers.
    BlockGraph::Block* nt_headers;

    // The block that describes the image section headers.
    BlockGraph::Block* image_section_headers;

    // The blocks that describe the data directory chunks.
    BlockGraph::Block* data_directory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
  };

  // Parse the image header, chunk the various blocks it refers and
  // invoke the AddReferenceCallback for all references encountered.
  bool ParseImageHeader(PEHeader* pe_header);

  // Parse export directory and invoke the AddReferenceCallback for all
  // references encountered.
  // @param export_dir_block a block referencing a valid export
  //      directory from a PE image.
  bool ParseExportDirectory(BlockGraph::Block* export_dir_block);

 private:
  BlockGraph::Block* AddBlock(BlockGraph::BlockType type,
                         RelativeAddress addr,
                         BlockGraph::Size size,
                         const char* name);

  bool AddReference(RelativeAddress src,
                    BlockGraph::ReferenceType type,
                    BlockGraph::Size size,
                    RelativeAddress dst,
                    const char* name = NULL);

  template <typename ItemType>
  bool AddRelative(const PEFileStructPtr<ItemType>& structure,
                   const DWORD* item,
                   const char* name = NULL);

  template <typename ItemType>
  bool AddAbsolute(const PEFileStructPtr<ItemType>& structure,
                   const DWORD* item,
                   const char* name = NULL);

  const PEFile& image_file_;
  BlockGraph::AddressSpace* address_space_;
  AddReferenceCallback* add_reference_;
};

}  // namespace image_util

#endif  // SAWBUCK_IMAGE_UTIL_PE_FILE_PARSER_H_
