// Copyright 2015 Google Inc. All Rights Reserved.
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

#include "syzygy/pe/transforms/add_hot_patching_metadata_transform.h"

#include "syzygy/block_graph/hot_patching_metadata.h"
#include "syzygy/block_graph/typed_block.h"
#include "syzygy/common/defs.h"
#include "syzygy/pe/pe_utils.h"

namespace pe {
namespace transforms {

const char AddHotPatchingMetadataTransform::kTransformName[] =
    "AddHotPatchingMetadataTransform";

AddHotPatchingMetadataTransform::AddHotPatchingMetadataTransform()
    : blocks_prepared_(nullptr) {
}

bool AddHotPatchingMetadataTransform::TransformBlockGraph(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BlockGraph::Block* header_block) {
  DCHECK_NE(static_cast<BlockVector*>(nullptr), blocks_prepared_);

  // Add the section that contains the hot patching metadata.
  if (!blocks_prepared_->empty())
    AddHotPatchingSection(block_graph);

  return true;
}

void AddHotPatchingMetadataTransform::AddHotPatchingSection(
    BlockGraph* block_graph) {
  DCHECK_NE(static_cast<BlockGraph*>(nullptr), block_graph);
  DCHECK_NE(static_cast<BlockVector*>(nullptr), blocks_prepared_);

  using block_graph::TypedBlock;
  using block_graph::HotPatchingBlockMetadata;
  using block_graph::HotPatchingMetadataHeader;

  // Create a block for hot patching metadata.
  BlockGraph::Size hp_metadata_size = sizeof(HotPatchingMetadataHeader) +
      sizeof(HotPatchingBlockMetadata) * blocks_prepared_->size();
  BlockGraph::Block* hp_metadata_block = block_graph->AddBlock(
      BlockGraph::DATA_BLOCK,
      hp_metadata_size,
      common::kHotPatchingMetadataSectionName);
  DCHECK_NE(static_cast<BlockGraph::Block*>(nullptr), hp_metadata_block);
  hp_metadata_block->AllocateData(hp_metadata_size);
  DCHECK(hp_metadata_block->owns_data());

  // Create hot patching metadata header.
  TypedBlock<HotPatchingMetadataHeader> hp_header;
  hp_header.Init(0, hp_metadata_block);
  hp_header->version = block_graph::kHotPatchingMetadataVersion;
  hp_header->number_of_blocks = blocks_prepared_->size();

  // Create hot patching block metadata.
  size_t index = 0;
  for (BlockGraph::Block* block : *blocks_prepared_) {
    TypedBlock<HotPatchingBlockMetadata> hp_block_metadata;
    hp_block_metadata.Init(sizeof(HotPatchingMetadataHeader) +
        sizeof(HotPatchingBlockMetadata) * index, hp_metadata_block);
    hp_block_metadata.SetReference(BlockGraph::RELATIVE_REF,
                                   hp_block_metadata->relative_address,
                                   block,
                                   0,
                                   0);
    hp_block_metadata->data_size = block->size();

    ++index;
  }
  DCHECK_EQ(index, blocks_prepared_->size());

  // Create a section for hot patching metadata and put the block inside.
  BlockGraph::Section* hp_section =
      block_graph->AddSection(common::kHotPatchingMetadataSectionName,
                              kReadOnlyDataCharacteristics);
  DCHECK_NE(static_cast<BlockGraph::Section*>(nullptr), hp_section);
  hp_metadata_block->set_section(hp_section->id());
}

}  // namespace transforms
}  // namespace pe
