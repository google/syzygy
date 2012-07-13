// Copyright 2012 Google Inc.
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
// Implements the ExplodeBasicBlockSubGraphTransform and
// ExplodeBasicBlocksTransform classes.

#include "syzygy/pe/transforms/explode_basic_blocks_transform.h"

#include "syzygy/block_graph/basic_block_subgraph.h"
#include "syzygy/block_graph/block_builder.h"
#include "syzygy/pe/block_util.h"

namespace pe {
namespace transforms {
namespace {

using block_graph::BasicBlock;
using block_graph::BlockBuilder;
using block_graph::BlockGraph;
using block_graph::BasicBlockSubGraph;

typedef BlockGraph::Block Block;

void GetTypeAndAttributes(const Block* original_block,
                          const BasicBlock& basic_block,
                          BlockGraph::BlockType* type,
                          BlockGraph::BlockAttributes* attributes) {
  DCHECK(original_block != NULL);
  DCHECK(type != NULL);
  DCHECK(attributes != NULL);

  *type = (basic_block.type() == BasicBlock::BASIC_DATA_BLOCK) ?
      BlockGraph::DATA_BLOCK : BlockGraph::CODE_BLOCK;

  *attributes = original_block->attributes();
  if (basic_block.type() == BasicBlock::BASIC_PADDING_BLOCK)
    *attributes |= BlockGraph::PADDING_BLOCK;
}

}  // namespace

const char ExplodeBasicBlockSubGraphTransform::kTransformName[] =
    "ExplodeBasicBlockSubGraphTransform";

bool ExplodeBasicBlockSubGraphTransform::TransformBasicBlockSubGraph(
    BlockGraph* block_graph , BasicBlockSubGraph* subgraph) {
  DCHECK(block_graph != NULL);
  DCHECK(subgraph != NULL);

  // Remove any extant block descriptions.
  subgraph->block_descriptions().clear();

  // Generate a new block description for each basic-block in the subgraph.
  BasicBlockSubGraph::BBCollection::iterator it =
      subgraph->basic_blocks().begin();
  for (; it != subgraph->basic_blocks().end(); ++it) {
    BasicBlock& bb = it->second;
    BlockGraph::BlockType type = BlockGraph::CODE_BLOCK;
    BlockGraph::BlockAttributes attributes = 0;
    GetTypeAndAttributes(subgraph->original_block(), bb, &type, &attributes);
    DCHECK_LT(0U, bb.size());

    if (exclude_padding_ && (attributes & BlockGraph::PADDING_BLOCK) != 0)
      continue;

    BasicBlockSubGraph::BlockDescription* desc = subgraph->AddBlockDescription(
        bb.name(), type, subgraph->original_block()->section(), 4, attributes);
    desc->basic_block_order.push_back(&bb);
  }
  return true;
}

const char ExplodeBasicBlocksTransform::kTransformName[] =
    "ExplodeBasicBlocksTransform";

bool ExplodeBasicBlocksTransform::OnBlock(BlockGraph* block_graph,
                                          BlockGraph::Block* block) {
  DCHECK(block_graph != NULL);
  DCHECK(block != NULL);

  if (block->type() != BlockGraph::CODE_BLOCK)
    return true;

  if (!CodeBlockIsBasicBlockDecomposable(block))
    return true;

  if (SkipThisBlock(block))
    return true;

  ExplodeBasicBlockSubGraphTransform transform(exclude_padding_);

  if (!ApplyBasicBlockSubGraphTransform(&transform, block_graph, block, NULL))
    return false;

  return true;
}

bool ExplodeBasicBlocksTransform::SkipThisBlock(const Block* candidate) {
  return false;
}

}  // namespace transforms
}  // namespace pe
