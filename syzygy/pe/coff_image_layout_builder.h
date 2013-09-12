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
// The CoffImageLayoutBuilder is the COFF-specific class for building image
// layouts for object files.

#ifndef SYZYGY_PE_COFF_IMAGE_LAYOUT_BUILDER_H_
#define SYZYGY_PE_COFF_IMAGE_LAYOUT_BUILDER_H_

#include <windows.h>
#include <map>

#include "syzygy/block_graph/block_graph.h"
#include "syzygy/block_graph/ordered_block_graph.h"
#include "syzygy/pe/image_layout.h"
#include "syzygy/pe/pe_coff_image_layout_builder.h"

namespace pe {

// A CoffImageLayoutBuilder builds an image layout for a COFF file, mapping
// blocks and sections to addresses, updating relocation tables, and fixing
// all needed file offset pointers.
class CoffImageLayoutBuilder : public PECoffImageLayoutBuilder {
 public:
  // Construct a new image layout builder that populates the provided image
  // layout. The image layout must outlive the builder.
  //
  // @param image_layout The image layout object to populate.
  explicit CoffImageLayoutBuilder(ImageLayout* image_layout);

  // Lay out the image according to the specified ordering.
  //
  // @param ordered_graph the ordered block graph; the underlying block
  //     graph must match that of the image layout passed to the
  //     constructor.
  // @returns true on success, false on failure.
  bool LayoutImage(const block_graph::OrderedBlockGraph& ordered_graph);

 private:
  // Lay out the incomplete COFF file header and section table. This
  // essentially reserves space for these entities, copying over the old
  // data, assuming the headers block is correctly sized for the expected
  // number of section header entries, and all old references, in particular
  // to old relocation tables, have been removed. The contents will need
  // fixing by the other helper routines, as the information becomes
  // available.
  //
  // @returns true on success, false on failure.
  bool LayoutHeaders();

  // Lay out all section blocks, section by section in the specified order,
  // as well as the computed relocations for each section, if any; update
  // the COFF section headers as appropriate.
  //
  // @param ordered_graph the ordered block graph.
  // @returns true on success, false on failure.
  bool LayoutSectionBlocks(const OrderedBlockGraph& ordered_graph);

  // Lay out the symbol and string tables, and update the COFF file header.
  //
  // @param ordered_graph the ordered block graph.
  // @returns true on success, false on failure.
  bool LayoutSymbolAndStringTables(const OrderedBlockGraph& ordered_graph);

  // Remove unmapped relocation blocks, and ensure that no other block is
  // left unmapped.
  //
  // @returns true on success, false on failure.
  bool RemoveOldRelocBlocks();

  // The headers block that contains the file header and section table.
  BlockGraph::Block* headers_block_;

  // The block containing the symbol table.
  BlockGraph::Block* symbols_block_;

  // The block containing the string table.
  BlockGraph::Block* strings_block_;

  DISALLOW_COPY_AND_ASSIGN(CoffImageLayoutBuilder);
};

}  // namespace pe

#endif  // SYZYGY_PE_COFF_IMAGE_LAYOUT_BUILDER_H_
