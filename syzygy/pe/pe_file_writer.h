// Copyright 2011 Google Inc. All Rights Reserved.
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

#ifndef SYZYGY_PE_PE_FILE_WRITER_H_
#define SYZYGY_PE_PE_FILE_WRITER_H_

#include "base/files/file_path.h"
#include "syzygy/block_graph/block_graph.h"
#include "syzygy/core/address_space.h"
#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/image_layout.h"
#include "syzygy/pe/pe_file_parser.h"

namespace pe {

// Given an address space and header information, writes a BlockGraph out
// to a PE image file.
class PEFileWriter {
 public:
  typedef block_graph::BlockGraph BlockGraph;
  typedef core::AbsoluteAddress AbsoluteAddress;
  typedef core::FileOffsetAddress FileOffsetAddress;
  typedef core::RelativeAddress RelativeAddress;

  // @param image_layout the image layout to write.
  explicit PEFileWriter(const ImageLayout& image_layout);

  // Writes the image to path.
  bool WriteImage(const base::FilePath& path);

  // Updates the checksum for the image @p path.
  static bool UpdateFileChecksum(const base::FilePath& path);

 protected:
  // Validates the DOS header and the NT headers in the image.
  // On success, sets the nt_headers_ pointer.
  bool ValidateHeaders();

  // Validates that the section info is consistent and populates
  // section_file_range_map_ and section_index_space_.
  bool CalculateSectionRanges();

  // Writes the entire image to the given file. Delegates to FlushSection and
  // WriteOneBlock.
  bool WriteBlocks(FILE* file);

  // Closes off the writing of a section by adding any necessary padding to the
  // output buffer.
  void FlushSection(size_t section_index, std::vector<uint8_t>* buffer);

  // Writes a single block to the buffer, first writing any necessary padding
  // (the content of which depends on the section type), followed by the
  // block data (containing finalized references).
  bool WriteOneBlock(AbsoluteAddress image_base,
                     size_t section_index,
                     const BlockGraph::Block* block,
                     std::vector<uint8_t>* buffer);

  // The file ranges of each section. This is populated by
  // CalculateSectionRanges and is a map from section index (as ordered in
  // the image layout) to section ranges on disk.
  typedef core::AddressRange<core::FileOffsetAddress, size_t> FileRange;
  typedef std::map<size_t, FileRange> SectionIndexFileRangeMap;
  SectionIndexFileRangeMap section_file_range_map_;

  // This stores an address-space from RVAs to section indices and is populated
  // by CalculateSectionRanges. This can be used to map from a block's
  // address to the index of its section. This is needed for finalizing
  // references.
  typedef core::AddressSpace<core::RelativeAddress, size_t, size_t>
      SectionIndexSpace;
  SectionIndexSpace section_index_space_;

  // Our image layout as provided to the constructor.
  const ImageLayout& image_layout_;

  // Refers to the nt headers from the image during WriteImage.
  const IMAGE_NT_HEADERS* nt_headers_;

 private:
  DISALLOW_COPY_AND_ASSIGN(PEFileWriter);
};

}  // namespace pe

#endif  // SYZYGY_PE_PE_FILE_WRITER_H_
