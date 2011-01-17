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
#ifndef SAWBUCK_IMAGE_UTIL_PE_FILE_WRITER_H_
#define SAWBUCK_IMAGE_UTIL_PE_FILE_WRITER_H_

#include "base/file_path.h"
#include "sawbuck/image_util/address_space.h"
#include "sawbuck/image_util/block_graph.h"
#include "sawbuck/image_util/pe_file_parser.h"

namespace image_util {

// Given an address space and header information, writes a BlockGraph out
// to a PE image file.
class PEFileWriter {
 public:
  // @param image_data the data in the image.
  // @param header PE header information for the image.
  // @note the @p image_data must conform to the information in
  //      @p header, in that all data must reside within the sections
  //      defined in the header.
  PEFileWriter(const BlockGraph::AddressSpace& image_data,
               const PEFileParser::PEHeader& header);

  // Writes the image to path.
  bool WriteImage(const FilePath& path);

 protected:
  bool InitializeSectionAddressSpace();
  bool WriteBlocks(FILE* file);
  bool WriteOneBlock(AbsoluteAddress image_base,
                     const BlockGraph::Block* block,
                     FILE* file);

  // Validate and return the NT headers from header_.
  const IMAGE_NT_HEADERS* GetNTHeaders() const;

  // Validate and return the section headers from header_.
  const IMAGE_SECTION_HEADER* GetSectionHeaders() const;

  // Maps from the relative offset to the start of a section to
  // the file offset for the start of that same section.
  typedef AddressSpace<RelativeAddress, size_t, FileOffsetAddress>
      SectionAddressSpace;
  SectionAddressSpace section_offsets_;

  const BlockGraph::AddressSpace& image_;
  const PEFileParser::PEHeader& header_;
};

}  // namespace image_util

#endif  // SAWBUCK_IMAGE_UTIL_PE_FILE_WRITER_H_
