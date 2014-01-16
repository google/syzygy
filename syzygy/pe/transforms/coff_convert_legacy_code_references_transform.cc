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

#include "syzygy/pe/transforms/coff_convert_legacy_code_references_transform.h"

namespace pe {
namespace transforms {
namespace {

using block_graph::BlockGraph;

// Convert all non-relocation references to equivalent relocation references
// in @p block.
// @param block the block whose references are to be converted.
void ConvertReferences(BlockGraph::Block* block) {
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), block);

  BlockGraph::Block::ReferenceMap::const_iterator it =
      block->references().begin();
  for (; it != block->references().end(); ++it) {
    if ((it->second.type() & BlockGraph::RELOC_REF_BIT) != 0)
      continue;
    BlockGraph::ReferenceType new_type =
        static_cast<BlockGraph::ReferenceType>(
            it->second.type() | BlockGraph::RELOC_REF_BIT);
    BlockGraph::Reference ref(new_type,
                              it->second.size(),
                              it->second.referenced(),
                              it->second.offset(),
                              it->second.base());
    // We expect this to return false, as the reference already exists.
    CHECK(!block->SetReference(it->first, ref));
  }
  return;
}

}  // namespace

const char CoffConvertLegacyCodeReferencesTransform::kTransformName[] =
    "CoffConvertLegacyCodeReferencesTransform";

bool CoffConvertLegacyCodeReferencesTransform::TransformBlockGraph(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BlockGraph::Block* /* headers_block */) {
  DCHECK_NE(reinterpret_cast<TransformPolicyInterface*>(NULL), policy);
  DCHECK_NE(reinterpret_cast<BlockGraph*>(NULL), block_graph);
  DCHECK_EQ(BlockGraph::COFF_IMAGE, block_graph->image_format());

  BlockGraph::BlockMap::iterator it = block_graph->blocks_mutable().begin();
  for (; it != block_graph->blocks_mutable().end(); ++it) {
    if (it->second.type() == BlockGraph::CODE_BLOCK)
      ConvertReferences(&it->second);
  }
  return true;
}

}  // namespace transforms
}  // namespace pe
