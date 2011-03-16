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
#ifndef SYZYGY_PE_PE_FILE_WRITER_H_
#define SYZYGY_PE_PE_FILE_WRITER_H_

#include "base/file_path.h"
#include "syzygy/core/address_space.h"
#include "syzygy/core/block_graph.h"
#include "syzygy/pe/pe_file_parser.h"

namespace pe {

// Given an address space and header information, writes a BlockGraph out
// to a PE image file.
class PEFileWriter {
 public:
  typedef core::AbsoluteAddress AbsoluteAddress;
  typedef core::BlockGraph BlockGraph;
  typedef core::FileOffsetAddress FileOffsetAddress;
  typedef core::RelativeAddress RelativeAddress;

  // @param image_data the data in the image.
  // @param nt_headers the NT header information for the image.
  // @param section_headers the image section headers for the image,
  //     must point to an array of nt_headers->FileHeader.NumberOfSections
  //     elements.
  // @note the @p image_data must conform to the information in
  //     @p header, in that all data must reside within the sections
  //     defined in the header.
  PEFileWriter(const BlockGraph::AddressSpace& image_data,
               const IMAGE_NT_HEADERS* nt_headers,
               const IMAGE_SECTION_HEADER* section_headers);

  // Writes the image to path.
  bool WriteImage(const FilePath& path);

  // Updates the checksum for the image @p path.
  static bool PEFileWriter::UpdateFileChecksum(const FilePath& path);

 protected:
  bool InitializeSectionFileAddressSpace();
  bool WriteBlocks(FILE* file);
  bool WriteOneBlock(AbsoluteAddress image_base,
                     const BlockGraph::Block* block,
                     FILE* file);

  // Maps from the relative offset to the start of a section to
  // the file offset for the start of that same section.
  typedef core::AddressSpace<RelativeAddress, size_t, FileOffsetAddress>
      SectionFileAddressSpace;
  SectionFileAddressSpace section_file_offsets_;

  // Maps from section virtual address range to section index.
  typedef core::AddressSpace<RelativeAddress, size_t, size_t>
      SectionAddressSpace;
  SectionAddressSpace sections_;

  const BlockGraph::AddressSpace& image_;
  const IMAGE_NT_HEADERS* nt_headers_;
  const IMAGE_SECTION_HEADER* section_headers_;
};

}  // namespace pe

#endif  // SYZYGY_PE_PE_FILE_WRITER_H_
