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

#include "syzygy/pe/transforms/coff_prepare_headers_transform.h"

#include "syzygy/block_graph/typed_block.h"
#include "syzygy/pe/pe_utils.h"

namespace pe {
namespace transforms {

using block_graph::BlockGraph;
using block_graph::TypedBlock;

const char CoffPrepareHeadersTransform::kTransformName[] =
    "CoffPrepareHeadersTransform";

bool CoffPrepareHeadersTransform::TransformBlockGraph(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BlockGraph::Block* headers_block) {
  DCHECK_NE(reinterpret_cast<TransformPolicyInterface*>(NULL), policy);
  DCHECK_NE(reinterpret_cast<BlockGraph*>(NULL), block_graph);
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), headers_block);
  DCHECK_EQ(BlockGraph::COFF_IMAGE, block_graph->image_format());

  TypedBlock<IMAGE_FILE_HEADER> file_header;
  if (!file_header.Init(0, headers_block)) {
    LOG(ERROR) << "Unable to dereference COFF headers.";
    return false;
  }

  // Wipe out references from headers to section blocks; these will be
  // rewritten during layout building.
  if (!headers_block->RemoveAllReferences()) {
    LOG(ERROR) << "Unable to remove references from COFF headers.";
    return false;
  }

  // Resize the section table after the file header to reflect the number of
  // sections in the block graph. This ignores any optional header space, as
  // none should be included in the output COFF file.
  size_t new_headers_size = sizeof(IMAGE_FILE_HEADER) +
      sizeof(IMAGE_SECTION_HEADER) * block_graph->sections().size();
  size_t old_headers_size = file_header.block()->size();
  if (!headers_block->InsertOrRemoveData(
          0, old_headers_size, new_headers_size, true)) {
    LOG(ERROR) << "Unable to resize COFF headers.";
    return false;
  }

  file_header->NumberOfSections = block_graph->sections().size();
  file_header->SizeOfOptionalHeader = 0;

  return true;
}

}  // namespace transforms
}  // namespace pe
