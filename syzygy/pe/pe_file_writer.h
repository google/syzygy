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
#ifndef SYZYGY_PE_PE_FILE_WRITER_H_
#define SYZYGY_PE_PE_FILE_WRITER_H_

#include "base/file_path.h"
#include "syzygy/core/address_space.h"
#include "syzygy/core/block_graph.h"
#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/image_layout.h"
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

  // @param image_layout the image layout to write.
  explicit PEFileWriter(const ImageLayout& image_layout);

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

  // Our image layout as provided to the constructor.
  const ImageLayout& image_layout_;

 private:
  DISALLOW_COPY_AND_ASSIGN(PEFileWriter);
};

}  // namespace pe

#endif  // SYZYGY_PE_PE_FILE_WRITER_H_
