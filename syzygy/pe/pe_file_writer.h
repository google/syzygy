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
#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/pe_file_parser.h"

namespace pe {

// Fwd.
class PEFileBuilder;

struct ImageLayout {
  // Information necessary to create PE image headers.
  struct HeaderInfo {
    // These fields correspond to the similarly named fields in the
    // IMAGE_FILE_HEADER and IMAGE_OPTIONAL_HEADER members of the
    // IMAGE_NT_HEADERS structure.
    // These fields are exclusive of any field that can be computed from
    // the image itself.
    int16 characteristics;
    uint8 major_linker_version;
    uint8 minor_linker_version;
    size_t image_base;
    size_t section_alignment;
    size_t file_alignment;
    int16 major_operating_system_version;
    int16 minor_operating_system_version;
    int16 major_image_version;
    int16 minor_image_version;
    int16 major_subsystem_version;
    int16 minor_subsystem_version;
    size_t win32_version_value;
    size_t size_of_headers;
    int16 subsystem;
    int16 dll_characteristics;
    size_t size_of_stack_reserve;
    size_t size_of_stack_commit;
    size_t size_of_heap_reserve;
    size_t size_of_heap_commit;
    size_t loader_flags;
  };

  // Per-segment information.
  struct SegmentInfo {
    // Name of the segment, note that this will be truncated to a max of
    // 8 characters on output.
    std::string name;
    // The segment's starting RVA, must be a multiple of the image's
    // SectionAlignment value.
    core::RelativeAddress addr;
    // The virtual size of the segment, must be greater than zero. Any
    // part of the segment that extends beyond data_size is implicitly
    // zero initialized.
    size_t size;
    // The initialized data size of the segment, must be a multple of the
    // image's FileAlignment value.
    size_t data_size;
    // The segment characteristics, a bitmask of IMAGE_SCN_* values.
    uint32 characteristics;
  };

  // TODO(siggi): Remove this constructor once PEFileBuilder is
  //    yielding an ImageLayout as output.
  explicit ImageLayout(const PEFileBuilder& builder);

  // TODO(siggi): Remove this constructor once Decomposer is
  //    yielding an ImageLayout as output.
  explicit ImageLayout(const Decomposer::DecomposedImage& decomposed_image);

  // Information to populate the PE header.
  HeaderInfo header_info;

  // The segments in the image.
  std::vector<SegmentInfo> segments;

  // The blocks that should be written to the image.
  const core::BlockGraph::AddressSpace* blocks;
};

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
