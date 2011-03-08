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

  // Non-const accessors.
  IMAGE_NT_HEADERS& nt_headers() { return nt_headers_; }
  IMAGE_SECTION_HEADER* section_headers() { return &section_headers_.at(0); }
  BlockGraph::AddressSpace& address_space() { return address_space_; }
  BlockGraph::Block* dos_header() { return dos_header_; }

  // Const accessors.
  const IMAGE_NT_HEADERS& nt_headers() const { return nt_headers_; }
  const IMAGE_SECTION_HEADER* section_headers() const {
    return &section_headers_.at(0);
  }
  const BlockGraph::Block* dos_header() const { return dos_header_; }
  const BlockGraph::AddressSpace& address_space() const {
    return address_space_;
  }
  RelativeAddress next_section_address() const { return next_section_address_; }
  const BlockGraph::Reference& entry_point() const { return entry_point_; }

  // Mutators.
  void set_entry_point(const BlockGraph::Reference& entry_point) {
    entry_point_ = entry_point;
  }

  // Allocates a new segment.
  // @param name the name of the new segment, must be 8 characters
  //     or less in length.
  // @param size the virtual size of the new segment.
  // @param data_size the data size of the new segment. This will be rounded
  //     up to the nearest multiple of file alignment.
  // @param characteristics the section characteristics.
  RelativeAddress AddSegment(const char* name,
                             size_t size,
                             size_t data_size,
                             uint32 characteristics);

  // Set a data directory entry to refer a block.
  bool SetDataDirectoryEntry(size_t entry_index, BlockGraph::Block* block);

  // Set a data directory entry explicitly to a reference and a size.
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

  // The default values we assign the file attributes.
  static const size_t kDefaultImageBase = 0x10000000;
  static const size_t kDefaultHeaderSize = 0x400;
  static const size_t kDefaultSectionAlignment = 0x1000;
  static const size_t kDefaultFileAlignment = 0x200;

 private:
  typedef std::vector<IMAGE_SECTION_HEADER> ImageSectionHeaderVector;

  // Create the DOS header for the image.
  bool CreateDosHeader();

  // The NT headers for the image we're building, we set the fields here
  // to default values that may need changing depending on the particulars
  // of the image file to write.
  IMAGE_NT_HEADERS nt_headers_;

  // The address where the next section will be allocated.
  RelativeAddress next_section_address_;

  // The image sections we've allocated.
  ImageSectionHeaderVector section_headers_;

  // The address space the new image will be built in.
  BlockGraph::AddressSpace address_space_;

  // The block that describes the DOS header.
  BlockGraph::Block* dos_header_;

  // A reference to the entrypoint of our image.
  BlockGraph::Reference entry_point_;

  // We keep one of these for each data directory entry.
  struct DataDirectoryEntry {
    DataDirectoryEntry() : size_(0) {
    }

    BlockGraph::Reference ref_;
    size_t size_;
  };

  // The blocks that describe the data directory chunks.
  DataDirectoryEntry data_directory_[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
};

}  // namespace pe

#endif  // SYZYGY_PE_PE_FILE_BUILDER_H_
