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
// PE ImageLayout objects.

#ifndef SYZYGY_PE_PE_IMAGE_LAYOUT_BUILDER_H_
#define SYZYGY_PE_PE_IMAGE_LAYOUT_BUILDER_H_

#include <windows.h>
#include <winnt.h>
#include <vector>

#include "syzygy/block_graph/block_graph.h"
#include "syzygy/block_graph/ordered_block_graph.h"
#include "syzygy/pe/image_layout.h"
#include "syzygy/pe/pe_coff_image_layout_builder.h"
#include "syzygy/pe/pe_file_parser.h"

namespace pe {

// A helper class that assists in assigning address space to PE image sections,
// building self-consistent PE image headers etc.
class PEImageLayoutBuilder : public PECoffImageLayoutBuilder {
 public:
  // Constructs a new image layout builder that populates the provided image
  // layout. The image layout must outlive the builder.
  explicit PEImageLayoutBuilder(ImageLayout* image_layout);

  // Accessors.
  BlockGraph::Block* dos_header_block() { return dos_header_block_; }
  BlockGraph::Block* nt_headers_block() { return nt_headers_block_; }
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

  // The blocks that describe the DOS header and the NT headers.
  BlockGraph::Block* dos_header_block_;
  BlockGraph::Block* nt_headers_block_;

  DISALLOW_COPY_AND_ASSIGN(PEImageLayoutBuilder);
};

}  // namespace pe

#endif  // SYZYGY_PE_PE_IMAGE_LAYOUT_BUILDER_H_
