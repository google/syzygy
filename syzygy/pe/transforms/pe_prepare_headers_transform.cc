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

#include "syzygy/pe/transforms/pe_prepare_headers_transform.h"

#include "syzygy/block_graph/typed_block.h"
#include "syzygy/pe/pe_utils.h"

namespace pe {
namespace transforms {

using block_graph::TypedBlock;

typedef TypedBlock<IMAGE_DOS_HEADER> DosHeader;
typedef TypedBlock<IMAGE_NT_HEADERS> NtHeaders;

const char PEPrepareHeadersTransform::kTransformName[] =
    "PEPrepareHeadersTransform";

bool PEPrepareHeadersTransform::TransformBlockGraph(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BlockGraph::Block* dos_header_block) {
  DCHECK_NE(reinterpret_cast<TransformPolicyInterface*>(NULL), policy);
  DCHECK_NE(reinterpret_cast<BlockGraph*>(NULL), block_graph);
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), dos_header_block);
  DCHECK_EQ(BlockGraph::PE_IMAGE, block_graph->image_format());

  DosHeader dos_header;
  NtHeaders nt_headers;
  if (!dos_header.Init(0, dos_header_block) ||
      !dos_header.Dereference(dos_header->e_lfanew, &nt_headers)) {
    LOG(ERROR) << "Unable to dereference headers.";
    return false;
  }

  if (!UpdateDosHeader(dos_header_block)) {
    LOG(ERROR) << "Unable to update DOS header.";
    return false;
  }

  // Resize the NT headers to reflect the number of sections in the block graph.
  size_t new_nt_headers_size = sizeof(IMAGE_NT_HEADERS) +
      sizeof(IMAGE_SECTION_HEADER) * block_graph->sections().size();
  size_t old_nt_headers_size = nt_headers.block()->size();
  if (!nt_headers.block()->InsertOrRemoveData(
          0, old_nt_headers_size, new_nt_headers_size, true)) {
    LOG(ERROR) << "Unable to resize NT headers.";
    return false;
  }

  nt_headers->FileHeader.NumberOfSections = block_graph->sections().size();
  nt_headers->OptionalHeader.CheckSum = 0;
  nt_headers->OptionalHeader.SizeOfHeaders =
      common::AlignUp(dos_header_block->size() + nt_headers.block()->size(),
                      nt_headers->OptionalHeader.FileAlignment);

  return true;
}

}  // namespace transforms
}  // namespace pe
