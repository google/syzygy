// Copyright 2011 Google Inc.
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
#ifndef SYZYGY_PE_PE_FILE_BUILDER_H_
#define SYZYGY_PE_PE_FILE_BUILDER_H_

#include <windows.h>
#include <winnt.h>
#include <vector>
#include "syzygy/core/block_graph.h"
#include "syzygy/pe/image_layout.h"
#include "syzygy/pe/pe_file_parser.h"

namespace pe {

// A helper class that assists in assigning address space to PE image sections,
// building self-consistent PE image headers etc.
class PEFileBuilder {
 public:
  typedef core::BlockGraph BlockGraph;
  typedef core::RelativeAddress RelativeAddress;

  // Constructs a new PE file builder on the supplied block graph.
  // The block graph must outlive the file builder.
  explicit PEFileBuilder(BlockGraph* block_graph);

  // Initialize dos_header_block_ and nt_headers_block.
  // @param dos_header_block must be a block that's a valid DOS header
  //    and stub. This block must also refer to the NT headers block,
  //    which in turn must contain valid NT headers.
  // @returns true iff the dos_header_block is valid.
  bool SetImageHeaders(BlockGraph::Block* dos_header_block);

  // Non-const accessors.
  ImageLayout& image_layout() { return image_layout_; }

  BlockGraph::Block* dos_header_block() { return dos_header_block_; }
  BlockGraph::Block* nt_headers_block() { return nt_headers_block_; }

  // Const accessors.
  const ImageLayout& image_layout() const { return image_layout_; }

  const BlockGraph::Block* dos_header_block() const {
    return dos_header_block_;
  }
  const BlockGraph::Block* nt_headers_block() const {
    return nt_headers_block_;
  }
  size_t section_alignment() const { return section_alignment_; }
  size_t file_alignment() const { return file_alignment_; }

  RelativeAddress next_section_address() const { return next_section_address_; }

  // Set the section and file allocation alignment boundaries.
  // @param header_size the size of the NT headers, must be greater than zero.
  // @param section_alignment the section alignment boundary, must be a power
  //     of two and an integer multiple of machine's page size.
  // @param file_alignment the file alignment boundary, must be a power
  //     of two and should be an integer multiple of sector size (512).
  // @pre No sections have been added to this builder.
  void SetAllocationParameters(size_t header_size,
                               size_t section_alignment,
                               size_t file_alignment);

  // Allocates a new section.
  // @param name the name of the new section, must be 8 characters
  //     or less in length.
  // @param size the virtual size of the new section.
  // @param data_size the data size of the new section. This will be rounded
  //     up to the nearest multiple of file alignment.
  // @param characteristics the section characteristics.
  RelativeAddress AddSection(const char* name,
                             size_t size,
                             size_t data_size,
                             uint32 characteristics);

  // Set a data directory entry to refer a block. This will set the entry's
  // size to the size of the block.
  bool SetDataDirectoryEntry(size_t entry_index, BlockGraph::Block* block);

  // Set a data directory entry to a reference and a size.
  bool SetDataDirectoryEntry(size_t entry_index,
                             const BlockGraph::Reference& entry,
                             size_t entry_size);

  // Allocates and populates a new relocations section containing
  // relocations for all absolute references in address_space_.
  bool CreateRelocsSection();

  // Write the NT headers and section headers to the image.
  // After this is done, the image is "baked", and everything except for
  // the image checksum should be up to date.
  bool FinalizeHeaders();

 private:
  static const size_t kDefaultSectionAlignment = 0x1000;
  static const size_t kDefaultFileAlignment = 0x200;

  // Update the DOS header with our own stub.
  bool UpdateDosHeader();

  // The image layout we're building.
  ImageLayout image_layout_;

  // Section alignment must be a multiple of the system page size,
  // defaults to 4096.
  size_t section_alignment_;
  // File alignment of image data, defaults to 0x200.
  size_t file_alignment_;

  // The address where the next section will be allocated.
  RelativeAddress next_section_address_;

  // The blocks that describe the DOS header and the NT headers.
  BlockGraph::Block* dos_header_block_;
  BlockGraph::Block* nt_headers_block_;
};

}  // namespace pe

#endif  // SYZYGY_PE_PE_FILE_BUILDER_H_
