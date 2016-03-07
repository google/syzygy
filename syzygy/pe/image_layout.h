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
// Declares ImageLayout, a lightweight structure that imposes a layout on a
// BlockGraph via an AddressSpace and a set of section headers.

#ifndef SYZYGY_PE_IMAGE_LAYOUT_H_
#define SYZYGY_PE_IMAGE_LAYOUT_H_

#include <windows.h>
#include <winnt.h>
#include <string>
#include <vector>

#include "syzygy/block_graph/block_graph.h"
#include "syzygy/core/address_space.h"

namespace pe {

// An ImageLayout imposes a layout on a BlockGraph via an AddressSpace over the
// blocks and a set of section headers.
struct ImageLayout {
  // Per-section information.
  struct SectionInfo {
    // Name of the section, note that this will be truncated to a max of
    // 8 characters on output.
    std::string name;
    // The section's starting RVA, must be a multiple of the image's
    // SectionAlignment value.
    core::RelativeAddress addr;
    // The virtual size of the section, must be greater than zero. Any
    // part of the section that extends beyond data_size is implicitly
    // zero initialized.
    size_t size;
    // The initialized data size of the section, must be a multiple of the
    // image's FileAlignment value.
    size_t data_size;
    // The section characteristics, a bitmask of IMAGE_SCN_* values.
    uint32_t characteristics;
  };

  // Creates an empty image layout on the supplied block graph.
  explicit ImageLayout(block_graph::BlockGraph* block_graph);

  // The sections in the image.
  std::vector<SectionInfo> sections;

  // The blocks that should be written to the image.
  block_graph::BlockGraph::AddressSpace blocks;
};

// Copies section headers to section info.
// @param num_sections the number of sections to copy.
// @param section_headers the array of section headers.
// @param sections the vector of section info structs to fill out.
void CopySectionHeadersToImageLayout(
    size_t num_sections,
    const IMAGE_SECTION_HEADER* section_headers,
    std::vector<ImageLayout::SectionInfo>* sections);

// Copies section headers to section info.
// @param nt_headers_block the block containing the NT headers.
// @param layout the image layout to be populated.
bool CopyHeaderToImageLayout(
    const block_graph::BlockGraph::Block* nt_headers_block,
    ImageLayout* layout);

// For testing.
inline bool operator==(const ImageLayout::SectionInfo& a,
                       const ImageLayout::SectionInfo& b) {
  return a.name == b.name && a.addr == b.addr &&
      a.size == b.size && a.data_size == b.data_size &&
      a.characteristics == b.characteristics;
}

// Generates a canonical ImageLayout. If the contained BlockGraph is unmodified
// as output by Decomposer, this will be the same as the original ImageLayout,
// up to but not including the SectionInfo.data_size values: we are more
// aggressive at trimming empty data from the end of a section. This does not
// modify the underlying BlockGraph.
//
// @param image_layout the ImageLayout to populate.
// @returns true on success, false otherwise.
// @pre The AddressSpace contained by image_layout is empty.
bool BuildCanonicalImageLayout(ImageLayout* image_layout);

// Given an @p input_image_layout generate a second @p output_image_layout that
// is identical to the first but not containing any padding blocks. This also
// removes the corresponding padding blocks from the underlying block-graph.
// @note The @p input_image_layout is invalid after this operation as it
//     will contain dangling block pointers.
// @param input_image_layout The input image layout to be copied.
// @param output_image_layout The image layout to receive the new layout minus
//     padding blocks. This must be initially empty and over the same
//     block-graph as @p input_image_layout.
bool CopyImageLayoutWithoutPadding(const ImageLayout& input_image_layout,
                                   ImageLayout* output_image_layout);

}  // namespace pe

#endif  // SYZYGY_PE_IMAGE_LAYOUT_H_
