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
#ifndef SYZYGY_PE_IMAGE_LAYOUT_H_
#define SYZYGY_PE_IMAGE_LAYOUT_H_

#include <string>
#include <vector>

#include <windows.h>
#include <winnt.h>

#include "base/basictypes.h"
#include "syzygy/core/address_space.h"
#include "syzygy/core/block_graph.h"

namespace pe {

struct ImageLayout {
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

  // Creates an empty image layout on the supplied block graph.
  explicit ImageLayout(core::BlockGraph* block_graph);

  // The segments in the image.
  std::vector<SegmentInfo> segments;

  // The blocks that should be written to the image.
  core::BlockGraph::AddressSpace blocks;
};

// Copies section headers to segment info.
void CopySectionHeadersToImageLayout(
    size_t num_sections,
    const IMAGE_SECTION_HEADER* section_headers,
    std::vector<ImageLayout::SegmentInfo>* segments);

// For testing.
inline bool operator==(const ImageLayout::SegmentInfo& a,
                       const ImageLayout::SegmentInfo& b) {
  return a.name == b.name && a.addr == b.addr &&
      a.size == b.size && a.data_size == b.data_size &&
      a.characteristics == b.characteristics;
}

}  // namespace pe

#endif  // SYZYGY_PE_IMAGE_LAYOUT_H_
