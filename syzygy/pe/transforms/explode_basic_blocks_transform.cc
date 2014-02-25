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
//
// Implements the ExplodeBasicBlockSubGraphTransform and
// ExplodeBasicBlocksTransform classes.

#include "syzygy/pe/transforms/explode_basic_blocks_transform.h"

#include "syzygy/block_graph/basic_block_subgraph.h"
#include "syzygy/block_graph/block_builder.h"

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

  if (basic_block.type() == BasicBlock::BASIC_DATA_BLOCK) {
    *type = BlockGraph::DATA_BLOCK;
  } else {
    DCHECK_EQ(BasicBlock::BASIC_CODE_BLOCK, basic_block.type());
    *type = BlockGraph::CODE_BLOCK;
  }

  *attributes = original_block->attributes();
  if (basic_block.is_padding())
    *attributes |= BlockGraph::PADDING_BLOCK;
}

}  // namespace

const char ExplodeBasicBlockSubGraphTransform::kTransformName[] =
    "ExplodeBasicBlockSubGraphTransform";

ExplodeBasicBlockSubGraphTransform::ExplodeBasicBlockSubGraphTransform(
    bool exclude_padding)
        : exclude_padding_(exclude_padding),
          output_code_blocks_(0),
          output_data_blocks_(0) {
}

bool ExplodeBasicBlockSubGraphTransform::TransformBasicBlockSubGraph(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BasicBlockSubGraph* subgraph) {
  DCHECK(policy != NULL);
  DCHECK(block_graph != NULL);
  DCHECK(subgraph != NULL);

  // Remove any extant block descriptions.
  subgraph->block_descriptions().clear();

  // Generate a new block description for each basic-block in the subgraph,
  // skipping basic-end blocks.
  BasicBlockSubGraph::BBCollection::iterator it =
      subgraph->basic_blocks().begin();
  for (; it != subgraph->basic_blocks().end(); ++it) {
    BasicBlock* bb = *it;

    // Skip end blocks. They don't have any actual content, so we can safely
    // ignore them.
    if (bb->type() == BasicBlock::BASIC_END_BLOCK)
      continue;

    BlockGraph::BlockType type = BlockGraph::CODE_BLOCK;
    BlockGraph::BlockAttributes attributes = 0;
    GetTypeAndAttributes(subgraph->original_block(), *bb, &type, &attributes);

    if (exclude_padding_ && (attributes & BlockGraph::PADDING_BLOCK) != 0)
      continue;

    if (type == BlockGraph::CODE_BLOCK) {
      ++output_code_blocks_;
    } else {
      ++output_data_blocks_;
    }

    BasicBlockSubGraph::BlockDescription* desc = subgraph->AddBlockDescription(
        bb->name(),
        subgraph->original_block()->compiland_name(),
        type,
        subgraph->original_block()->section(),
        4,
        attributes);
    desc->basic_block_order.push_back(bb);
  }
  return true;
}

const char ExplodeBasicBlocksTransform::kTransformName[] =
    "ExplodeBasicBlocksTransform";

ExplodeBasicBlocksTransform::ExplodeBasicBlocksTransform()
    : exclude_padding_(false),
      non_decomposable_code_blocks_(0),
      skipped_code_blocks_(0),
      input_code_blocks_(0),
      output_code_blocks_(0),
      output_data_blocks_(0) {
}

bool ExplodeBasicBlocksTransform::OnBlock(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BlockGraph::Block* block) {
  DCHECK(policy != NULL);
  DCHECK(block_graph != NULL);
  DCHECK(block != NULL);

  // Skip non-code blocks.
  if (block->type() != BlockGraph::CODE_BLOCK)
    return true;

  // Skip gap blocks.
  if (block->attributes() & BlockGraph::GAP_BLOCK)
    return true;

  if (!policy->BlockIsSafeToBasicBlockDecompose(block)) {
    VLOG(1) << "Skipping block '" << block->name() << "', attributes: "
            << BlockGraph::BlockAttributesToString(block->attributes());

    ++non_decomposable_code_blocks_;
    return true;
  }

  if (SkipThisBlock(block)) {
    ++skipped_code_blocks_;
    return true;
  }

  ExplodeBasicBlockSubGraphTransform transform(exclude_padding_);

  if (!ApplyBasicBlockSubGraphTransform(
          &transform, policy, block_graph, block, NULL)) {
    return false;
  }

  ++input_code_blocks_;
  output_code_blocks_ += transform.output_code_blocks();
  output_data_blocks_ += transform.output_data_blocks();

  return true;
}

bool ExplodeBasicBlocksTransform::PostBlockGraphIteration(
    const TransformPolicyInterface* unused_policy,
    BlockGraph* unused_block_graph,
    BlockGraph::Block* unused_header_block) {
  LOG(INFO) << "Exploded " << input_code_blocks_ << " input code blocks to";
  LOG(INFO) << "  Code blocks: " << output_code_blocks_;
  LOG(INFO) << "  Data blocks: " << output_data_blocks_;
  LOG(INFO) << "Non-decomposable blocks: " << non_decomposable_code_blocks_;
  LOG(INFO) << "Skipped blocks: " << skipped_code_blocks_;

  return true;
}

bool ExplodeBasicBlocksTransform::SkipThisBlock(const Block* candidate) {
  return false;
}

}  // namespace transforms
}  // namespace pe
