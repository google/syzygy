// Copyright 2014 Google Inc. All Rights Reserved.
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

#include "syzygy/pe/transforms/pe_remove_empty_sections_transform.h"

namespace pe {
namespace transforms {

namespace {

using block_graph::BlockGraph;

}  // namespace

const char PERemoveEmptySectionsTransform::kTransformName[] =
    "PERemoveEmptySectionsTransform";

PERemoveEmptySectionsTransform::PERemoveEmptySectionsTransform() {
}

bool PERemoveEmptySectionsTransform::TransformBlockGraph(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BlockGraph::Block* dos_header_block) {
  DCHECK_NE(reinterpret_cast<TransformPolicyInterface*>(NULL), policy);
  DCHECK_NE(reinterpret_cast<BlockGraph*>(NULL), block_graph);
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), dos_header_block);
  DCHECK_EQ(BlockGraph::PE_IMAGE, block_graph->image_format());

  // Keep track of sections used by at least one block.
  std::set<BlockGraph::SectionId> sections_used;
  BlockGraph::BlockMap::const_iterator block = block_graph->blocks().begin();
  for (; block != block_graph->blocks().end(); ++block)
    sections_used.insert(block->second.section());

  // Remove unused sections.
  std::set<BlockGraph::SectionId> sections_unused;
  BlockGraph::SectionMap& sections = block_graph->sections_mutable();
  BlockGraph::SectionMap::iterator it = sections.begin();
  while (it != sections.end()) {
    BlockGraph::Section& section = it->second;
    ++it;

    // Check whether this section is used and remove it otherwise.
    if (sections_used.find(section.id()) == sections_used.end()) {
      LOG(INFO) << "Removing empty section: " << section.name();
      block_graph->RemoveSectionById(section.id());
    }
  }

  return true;
}

}  // namespace transforms
}  // namespace pe
