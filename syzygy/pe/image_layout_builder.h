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
//
// Declares an image layout builder, a utility class for constructing valid
// ImageLayout objects.

#ifndef SYZYGY_PE_IMAGE_LAYOUT_BUILDER_H_
#define SYZYGY_PE_IMAGE_LAYOUT_BUILDER_H_

#include <windows.h>
#include <winnt.h>
#include <vector>

#include "syzygy/block_graph/block_graph.h"
#include "syzygy/block_graph/ordered_block_graph.h"
#include "syzygy/pe/image_layout.h"
#include "syzygy/pe/pe_file_parser.h"

namespace pe {

// A helper class that assists in assigning address space to PE image sections,
// building self-consistent PE image headers etc.
class ImageLayoutBuilder {
 public:
  typedef block_graph::BlockGraph BlockGraph;
  typedef block_graph::OrderedBlockGraph OrderedBlockGraph;
  typedef core::RelativeAddress RelativeAddress;

  // Constructs a new image layout builder that populates the provided image
  // layout. The image layout must outlive the builder.
  explicit ImageLayoutBuilder(ImageLayout* image_layout);

  // Sets the padding. If this is non-zero, blank space will be left after
  // each block that is laid out. The contents of this space are dictated by
  // the PEFileWriter (which uses 0xcc for code sections, and 0x00 for data
  // sections).
  void set_padding(size_t padding) { padding_ = padding; }

  // Accessors.
  ImageLayout* image_layout() { return image_layout_; }
  BlockGraph* block_graph() { return image_layout_->blocks.graph(); }
  BlockGraph::Block* dos_header_block() { return dos_header_block_; }
  BlockGraph::Block* nt_headers_block() { return nt_headers_block_; }
  size_t padding() const { return padding_; }
  const ImageLayout* image_layout() const { return image_layout_; }
  const BlockGraph* block_graph() const {
    return image_layout_->blocks.graph();
  }
  const BlockGraph::Block* dos_header_block() const {
    return dos_header_block_;
  }
  const BlockGraph::Block* nt_headers_block() const {
    return nt_headers_block_;
  }

  // Lays out the image headers, and sets the file and section alignment using
  // the values from the header.
  // @param dos_header_block must be a block that's a valid DOS header
  //    and stub. This block must also refer to the NT headers block,
  //    which in turn must contain valid NT headers.
  // @returns true iff the dos_header_block is valid.
  // @pre OpenSection and LayoutBlock must not have been called.
  bool LayoutImageHeaders(BlockGraph::Block* dos_header_block);

  // Opens a new section for writing. If another section is already open, closes
  // it first.
  // @param name the name of the section.
  // @param characteristics the section characteristics.
  // @param section a pointer to the section information.
  // @pre LayoutImageHeaders must have been called.
  bool OpenSection(const char* name, uint32 characteristics);
  bool OpenSection(const BlockGraph::Section* section);

  // Lays out the provided block using the blocks internal alignment.
  bool LayoutBlock(BlockGraph::Block* block);

  // Lays out the provided block using the provided alignment.
  bool LayoutBlock(size_t alignment, BlockGraph::Block* block);

  // Closes the initialized data portion of the section that is currently
  // being written. If this is not explicitly called for a section it will be
  // automatically determined based on block contents.
  // @pre OpenSection must already have been called.
  void CloseExplicitSectionData();

  // Closes the section that is currently being written.
  // @returns true on success, false otherwise.
  // @pre a section must currently be open.
  bool CloseSection();

  // Creates sections and lays out blocks using the provided ordered block
  // graph as a template. Lays out all sections except for the reloc section,
  // which must be the last section if it is present.
  // @param obg the ordered block graph to layout, which must be for the same
  //     block-graph as used in the constructor.
  // @returns true on success, false otherwise.
  // @pre LayoutImageHeaders has been called.
  bool LayoutOrderedBlockGraph(const OrderedBlockGraph& obg);

  // Finalizes the image layout. This builds the relocs, finalizes the headers,
  // and does any other PE touch-ups that are required to make the image
  // self-consistent. This may remove and/or modify blocks in the block-graph.
  // @returns true on success, false otherwise.
  bool Finalize();

 private:
  // Lays out a block at the current cursor location.
  bool LayoutBlockImpl(BlockGraph::Block* block);

  // Ensure that the Safe SEH Table is sorted.
  bool SortSafeSehTable();
  // Allocates and populates a new relocations section containing
  // relocations for all absolute references in address_space_.
  bool CreateRelocsSection();
  // Write the NT headers and section headers to the image.
  // After this is done, the image is "baked", and everything except for
  // the image checksum should be up to date.
  bool FinalizeHeaders();
  // Ensure that the image layout has the same number of blocks as the
  // block-graph. The relocs blocks that are in the block-graph but not in the
  // image layout will be removed. If there are extra blocks from other sections
  // in the block-graph an error will be returned.
  // @returns true if the block-graph and the image layout are consistent,
  //     false otherwise.
  bool ReconcileBlockGraphAndImageLayout();

  // The image layout we're building.
  ImageLayout* image_layout_;

  // The padding we're using.
  size_t padding_;

  // The current location of the output cursor, as well as information regarding
  // the current section in progress.
  RelativeAddress cursor_;
  RelativeAddress section_start_;
  RelativeAddress section_auto_init_end_;
  RelativeAddress section_init_end_;

  // The blocks that describe the DOS header and the NT headers.
  BlockGraph::Block* dos_header_block_;
  BlockGraph::Block* nt_headers_block_;
};

}  // namespace pe

#endif  // SYZYGY_PE_IMAGE_LAYOUT_BUILDER_H_
