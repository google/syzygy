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
//
// Implements the JumpTableCaseCountTransform class.

#include "syzygy/instrument/transforms/jump_table_count_transform.h"

#include "base/logging.h"
#include "syzygy/pe/block_util.h"
#include "syzygy/pe/pe_utils.h"
#include "syzygy/pe/transforms/add_imports_transform.h"

namespace instrument {
namespace transforms {

namespace {

using block_graph::BasicBlock;
using block_graph::BlockGraph;

const char kDefaultModuleName[] = "jump_table_count.dll";

}  // namespace

const char JumpTableCaseCountTransform::kTransformName[] =
    "JumpTableCountTransform";

JumpTableCaseCountTransform::JumpTableCaseCountTransform()
    :  instrument_dll_name_(kDefaultModuleName) {
}

bool JumpTableCaseCountTransform::PreBlockGraphIteration(
    BlockGraph* block_graph,
    BlockGraph::Block* header_block) {
  DCHECK(block_graph != NULL);
  DCHECK(header_block != NULL);

  // TODO(sebmarchand): Implement this function.

  return true;
}

bool JumpTableCaseCountTransform::OnBlock(BlockGraph* block_graph,
                                          BlockGraph::Block* block) {
  DCHECK(block_graph != NULL);
  DCHECK(block != NULL);

  if (block->type() != BlockGraph::CODE_BLOCK)
    return true;

  if (!pe::CodeBlockIsBasicBlockDecomposable(block))
    return true;

  if (!ApplyBasicBlockSubGraphTransform(this, block_graph, block, NULL))
    return false;

  return true;
}

bool JumpTableCaseCountTransform::TransformBasicBlockSubGraph(
    BlockGraph* block_graph , BasicBlockSubGraph* subgraph) {
  DCHECK(block_graph != NULL);
  DCHECK(subgraph != NULL);

  // TODO(sebmarchand): Implement this function.

  return true;
}

bool JumpTableCaseCountTransform::PostBlockGraphIteration(
    BlockGraph* block_graph, BlockGraph::Block* header_block) {
  DCHECK(block_graph != NULL);
  DCHECK(header_block != NULL);

  // TODO(sebmarchand): Implement this function.

  return true;
}

}  // namespace transforms
}  // namespace instrument
