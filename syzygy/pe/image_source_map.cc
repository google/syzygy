// Copyright 2011 Google Inc. All Rights Reserved.
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

#include "syzygy/pe/image_source_map.h"

namespace pe {

using block_graph::BlockGraph;
using core::RelativeAddress;

// When inverting, in order to have as much address space available for the
// destination image as is available to the source image, we peg this constant
// to the middle of the possible address space. Thus, we are able to build OMAPs
// for images up to 2GB in size.
const ULONG kInvalidOmapRvaTo = 0x80000000;

void BuildImageSourceMap(const ImageLayout& image_layout,
                         ImageSourceMap* new_to_old) {
  // Walk through all blocks in the image.
  BlockGraph::AddressSpace::RangeMapConstIter block_it =
      image_layout.blocks.begin();
  for (; block_it != image_layout.blocks.end(); ++block_it) {
    const BlockGraph::Block* block = block_it->second;
    DCHECK(block != NULL);

    // Walk through all of the source ranges for this block.
    BlockGraph::Block::SourceRanges::RangePairs::const_iterator src_it =
        block->source_ranges().range_pairs().begin();
    for (; src_it != block->source_ranges().range_pairs().end(); ++src_it) {
      RelativeAddress new_start =
          block_it->first.start() + src_it->first.start();
      RelativeAddress old_start = src_it->second.start();
      size_t new_size = src_it->first.size();
      size_t old_size = src_it->second.size();

      // Add this range mapping to the image range map.
      bool pushed = new_to_old->Push(
          RelativeAddressRange(new_start, new_size),
          RelativeAddressRange(old_start, old_size));
      DCHECK(pushed);
    }
  }
}

void BuildOmapVectorFromImageSourceMap(const RelativeAddressRange& range,
                                       const ImageSourceMap& source_map,
                                       std::vector<OMAP>* omaps) {
  // The image size must be less than the constant we use as an indication of
  // invalid addresses.
  DCHECK_LE(range.end().value(), kInvalidOmapRvaTo);
  DCHECK(omaps != NULL);

  // We know that we will have roughly as many OMAP entries as there are range
  // pairs.
  omaps->reserve(source_map.size());

  RelativeAddress address = range.start();
  ImageSourceMap::RangePairs::const_iterator pair_it =
      source_map.range_pairs().begin();
  for (; pair_it != source_map.range_pairs().end(); ++pair_it) {
    // Skip any source ranges that come before us.
    if (pair_it->first.end() < range.start())
      continue;

    // Stop if this source range is beyond the end of the range we're concerned
    // with.
    if (range.end() < pair_it->first.start())
      break;

    // Have a gap to fill?
    if (address < pair_it->first.start()) {
      OMAP omap = { address.value(), kInvalidOmapRvaTo };
      omaps->push_back(omap);
    }

    // A long mapping means that there is some range of source addresses that
    // mapped to a shorter range of destination addresses. This means that
    // source pointers pointing to the tail end of the source range will be
    // mapped to an address outside of the intended detination range.
    //
    // We patch these by making several OMAP entries for them, each one covering
    // a portion of the source range and repeatedly mapping it to the same
    // destination range.
    if (pair_it->first.size() > pair_it->second.size()) {
      address = pair_it->first.start();
      while (address < pair_it->first.end()) {
        OMAP omap = { address.value(), pair_it->second.start().value() };
        omaps->push_back(omap);
        address += pair_it->second.size();
      }
    } else {
      OMAP omap = { pair_it->first.start().value(),
                    pair_it->second.start().value() };
      omaps->push_back(omap);

      address = pair_it->first.end();
    }
  }

  // Do we need an entry for the end of the range?
  if (address < range.end()) {
    OMAP omap = { address.value(), kInvalidOmapRvaTo };
    omaps->push_back(omap);
  }

  // Cap off the OMAP vector with an entry for the first address beyond the end
  // of the part of the image we're concerned with.
  OMAP last_omap = { range.end().value(), kInvalidOmapRvaTo };
  omaps->push_back(last_omap);
}

}  // namespace pe
