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
// Implements the ExplodeBasicBlocksTransform. This transform seperates all
// of the basic-blocks in a block-graph into individual code and data blocks.
// This is primarily a test to exercise the basic-block motion machinery.

#include "syzygy/pe/transforms/explode_basic_blocks_transform.h"

#include "syzygy/block_graph/basic_block_subgraph.h"
#include "syzygy/block_graph/block_builder.h"
#include "syzygy/pe/basic_block_decomposer.h"
#include "syzygy/pe/block_util.h"

namespace pe {
namespace transforms {
namespace {

using block_graph::BasicBlock;
using block_graph::BlockBuilder;
using block_graph::BlockGraph;
using block_graph::BasicBlockSubGraph;

typedef BlockGraph::Block Block;

const BlockGraph::BlockAttributes kPaddingAttributes =
    BlockGraph::PADDING_BLOCK | BlockGraph::GAP_BLOCK;

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
    *attributes |= kPaddingAttributes;
}

}  // namespace

const char ExplodeBasicBlocksTransform::kTransformName[] =
    "ExplodeBasicBlocksTransform";

ExplodeBasicBlocksTransform::ExplodeBasicBlocksTransform()
    : exclude_padding_(false) {
}

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

  // Decompose block to basic blocks.
  BasicBlockSubGraph subgraph;
  BasicBlockDecomposer bb_decomposer(block, &subgraph);
  if (!bb_decomposer.Decompose())
    return false;

  // Turn each basic block into a new block in the subgraph.
  subgraph.block_descriptions().clear();
  BasicBlockSubGraph::BBCollection::iterator it =
      subgraph.basic_blocks().begin();
  for (; it != subgraph.basic_blocks().end(); ++it) {
    BasicBlock& bb = it->second;
    BlockGraph::BlockType type = BlockGraph::CODE_BLOCK;
    BlockGraph::BlockAttributes attributes = 0;
    GetTypeAndAttributes(subgraph.original_block(), bb, &type, &attributes);
    DCHECK_LT(0U, bb.size());

    if (exclude_padding_ && (attributes & kPaddingAttributes) != 0)
      continue;

    BasicBlockSubGraph::BlockDescription* desc = subgraph.AddBlockDescription(
        bb.name(), type, block->section(), 4, attributes);
    desc->basic_block_order.push_back(&bb);
  }

  // Merge the exploded subgraph back into the block_graph.
  BlockBuilder builder(block_graph);
  if (!builder.Merge(&subgraph))
    return false;

  return true;
}

bool ExplodeBasicBlocksTransform::SkipThisBlock(const Block* candidate) {
  return false;
}

}  // namespace transforms
}  // namespace pe
