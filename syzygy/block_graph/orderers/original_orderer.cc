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

#include "syzygy/block_graph/orderers/original_orderer.h"

namespace block_graph {
namespace orderers {

namespace {

// Returns true if the block contains only zeros, and may safely be left
// implicitly initialized.
bool BlockIsZeros(const BlockGraph::Block* block) {
  if (block->references().size() != 0)
    return false;
  const uint8_t* data = block->data();
  if (data == NULL)
    return true;
  for (size_t i = 0; i < block->data_size(); ++i, ++data) {
    if (*data != 0)
      return false;
  }
  return true;
}

struct BlockCompareFunctor {
  bool operator()(const BlockGraph::Block* block1,
                  const BlockGraph::Block* block2) {
    DCHECK(block1 != NULL);
    DCHECK(block2 != NULL);

    // Determine if the blocks have source data.
    bool have_source1 = block1->source_ranges().size() > 0;
    bool have_source2 = block2->source_ranges().size() > 0;

    // If both blocks have source data the block with earlier source
    // data comes first. This preserves the original order where
    // possible.
    if (have_source1 && have_source2) {
      BlockGraph::Block::SourceRanges::RangePairs::const_iterator it1 =
          block1->source_ranges().range_pairs().begin();
      BlockGraph::Block::SourceRanges::RangePairs::const_iterator it2 =
          block2->source_ranges().range_pairs().begin();
      if (it1->second.start() != it2->second.start())
        return it1->second.start() < it2->second.start();
    }

    // Next, we sort by initialized and uninitialized data. Blocks containing
    // strictly uninitialized data go to the end of the section.
    bool is_zeros1 = BlockIsZeros(block1);
    bool is_zeros2 = BlockIsZeros(block2);
    if (is_zeros1 != is_zeros2)
      return is_zeros2;

    // Blocks with source data go to the beginning.
    if (have_source1 != have_source2)
      return have_source1;

    // Finally we break ties using the block ID.
    return block1->id() < block2->id();
  }
};

struct SectionCompareFunctor {
  bool operator()(const BlockGraph::Section* section1,
                  const BlockGraph::Section* section2) {
    DCHECK(section1 != NULL);
    DCHECK(section2 != NULL);

    // Simply sort by section ID.
    return section1->id() < section2->id();
  }
};

}  // namespace

const char OriginalOrderer::kOrdererName[] = "OriginalOrderer";

bool OriginalOrderer::OrderBlockGraph(OrderedBlockGraph* ordered_block_graph,
                                      BlockGraph::Block* header_block) {
  DCHECK(ordered_block_graph != NULL);
  DCHECK(header_block != NULL);

  // Sort the sections.
  ordered_block_graph->Sort(SectionCompareFunctor());

  // Sort the blocks in each section.
  const BlockGraph* bg = ordered_block_graph->block_graph();
  BlockGraph::SectionMap::const_iterator section_it = bg->sections().begin();
  for (; section_it != bg->sections().end(); ++section_it) {
    const BlockGraph::Section* section = &section_it->second;
    ordered_block_graph->Sort(section, BlockCompareFunctor());
  }

  return true;
}

}  // namespace orderers
}  // namespace block_graph
