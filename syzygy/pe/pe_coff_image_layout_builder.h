// Copyright 2013 Google Inc. All Rights Reserved.
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
// The PECoffImageLayoutBuilder is the base class for PE and COFF image
// layout builders, which contains common functions for laying out blocks
// and sections.

#ifndef SYZYGY_PE_PE_COFF_IMAGE_LAYOUT_BUILDER_H_
#define SYZYGY_PE_PE_COFF_IMAGE_LAYOUT_BUILDER_H_

#include <windows.h>

#include "syzygy/block_graph/block_graph.h"
#include "syzygy/block_graph/ordered_block_graph.h"
#include "syzygy/pe/image_layout.h"
#include "syzygy/pe/pe_file_parser.h"

namespace pe {

// A helper class that assists in mapping PE or COFF image sections and
// blocks to an address space.
//
// Image layout builders are stateful objects that progressively lay out
// blocks at increasing addresses. A builder keeps information on the
// current position (address to build at) and section being laid out.
class PECoffImageLayoutBuilder {
 public:
  typedef block_graph::BlockGraph BlockGraph;
  typedef block_graph::OrderedBlockGraph OrderedBlockGraph;
  typedef core::RelativeAddress RelativeAddress;

  // Set the inter-block padding. If this is non-zero, it specifies the
  // minimum amount of blank space that will be left between blocks laid out
  // within a same section. The content of the padding is left unspecified
  // and will appear as a gap in the address space, usually filled by the
  // file writer with appropriate padding bytes.
  //
  // @param padding the new inter-block padding.
  void set_padding(size_t padding) { padding_ = padding; }

  // @returns the current inter-block padding.
  // @see set_padding(size_t)
  size_t padding() const { return padding_; }

  // @param alignment the minimal alignment for a code block.
  void set_code_alignment(size_t alignment) { code_alignment_ = alignment; }

  // @returns the current code block alignment.
  size_t code_alignment() const { return code_alignment_; }

  // @returns the mutable image layout this builder builds to.
  ImageLayout* image_layout() { return image_layout_; }

  // @returns the image layout this builder builds to.
  const ImageLayout* image_layout() const {
    return image_layout_;
  }

  // @returns the mutable block graph this builder builds from.
  // @note The block graph matches that returned by image_layout().
  BlockGraph* block_graph() { return image_layout_->blocks.graph(); }

  // @returns the block graph this builder builds from.
  // @note The block graph matches that returned by image_layout().
  const BlockGraph* block_graph() const {
    return image_layout_->blocks.graph();
  }

  // Start laying out a new section. If another section is currently open,
  // it will first be closed.
  //
  // @param name the name of the section.
  // @param characteristics the section characteristics.
  // @returns true on success, false on failure.
  // @note Sections cannot be laid out at offset zero; derived classes are
  //     expected to lay out some headers before laying out sections.
  bool OpenSection(const char* name, uint32_t characteristics);

  // Start laying out a new section. If another section is currently open,
  // it will first be closed.
  //
  // @param section the section to be laid out.
  // @returns true on success, false on failure.
  // @see OpenSection(const char*, uint32_t)
  bool OpenSection(const BlockGraph::Section& section);

  // Lay out the provided block, enforcing to the inter-block block
  // padding. The block is aligned according to the internal alignment of
  // @p block.
  //
  // @param block the block to lay out.
  // @returns true on success, false on failure.
  bool LayoutBlock(BlockGraph::Block* block);

  // Lay out the provided block, using the specified alignment.
  //
  // @param alignment the explicit alignment to use.
  // @param block the block to lay out.
  // @returns true on success, false on failure.
  // @see LayoutBlock(BlockGraph::Block*)
  bool LayoutBlock(size_t alignment, BlockGraph::Block* block);

  // Mark the end of the initialized data portion of the section that is
  // currently being laid out. If not explicitly called for a given section,
  // the span of initialized data will be automatically determined based on
  // block contents.
  //
  // @note A section must be open for layout.
  void CloseExplicitSectionData();

  // Mark the end of the section that is currently being laid out.
  //
  // @returns true on success, false on failure.
  // @note A section must be open for layout.
  bool CloseSection();

 protected:
  // Construct a new image layout builder that populates the provided image
  // layout. The image layout must outlive the builder.
  //
  // @param image_layout the image layout to build into.
  explicit PECoffImageLayoutBuilder(ImageLayout* image_layout);

  // Lay out a block at the current cursor location.
  //
  // @param block the block to lay out.
  // @returns true on success, false on failure.
  bool LayoutBlockImpl(BlockGraph::Block* block);

  // Initialize the layout builder with the specified alignment constraints.
  // Section alignment should be equal or greater than raw data (file)
  // alignment.
  //
  // According to the PE specifications, file alignment should be a power of
  // two between 512 and 64K for PE files. For object files, it may be zero.
  //
  // @param section_alignment the alignment of layed out sections.
  // @param file_alignment the alignment of raw data.
  void Init(size_t section_alignment, size_t file_alignment);

  // The image layout this object builds into.
  ImageLayout* image_layout_;

  // The inter-block padding.
  size_t padding_;

  // The minimal code block alignment.
  size_t code_alignment_;

  // The current position of the output cursor.
  RelativeAddress cursor_;

  // The start of the section currently being laid out.
  RelativeAddress section_start_;

  // The automatic estimate of the end of initialized data in the section
  // currently being laid out.
  RelativeAddress section_auto_init_end_;

  // The explicit end of initialized data in the section currently being
  // laid out, if any; valid if greater than the cursor position.
  RelativeAddress section_init_end_;

  // The (virtual) alignment of sections.
  size_t section_alignment_;

  // The alignment of section raw data in the image file.
  size_t file_alignment_;

 private:
  DISALLOW_COPY_AND_ASSIGN(PECoffImageLayoutBuilder);
};

}  // namespace pe

#endif  // SYZYGY_PE_PE_COFF_IMAGE_LAYOUT_BUILDER_H_
