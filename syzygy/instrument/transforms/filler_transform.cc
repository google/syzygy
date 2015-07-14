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

#include "syzygy/instrument/transforms/filler_transform.h"

#include "base/logging.h"
#include "syzygy/assm/assembler_base.h"
#include "syzygy/block_graph/basic_block_assembler.h"
#include "syzygy/block_graph/basic_block_subgraph.h"
#include "syzygy/block_graph/block_util.h"
#include "syzygy/block_graph/transform_policy.h"

namespace instrument {
namespace transforms {

const char FillerBasicBlockTransform::kTransformName[] =
    "FillerBasicBlockTransform";

const char FillerTransform::kTransformName[] = "FillerTransform";

// static
void FillerBasicBlockTransform::InjectNop(
    const NopSpec& nop_spec,
    bool debug_friendly,
    BasicBlock::Instructions* instructions) {
  BasicBlock::Instructions::iterator inst_it = instructions->begin();
  NopSpec::const_iterator nop_it = nop_spec.begin();
  size_t write_index = 0LL;
  while (inst_it != instructions->end() && nop_it != nop_spec.end()) {
    if (nop_it->first == write_index) {
      block_graph::BasicBlockAssembler assm(inst_it, instructions);
      // If specified, set source range for successive NOPs to to be that of the
      // current instruction (which follows the NOPs). Caveat: This breaks the
      // 1:1 OMAP mapping and may confuse some debuggers.
      if (debug_friendly)
        assm.set_source_range(inst_it->source_range());
      // Add all NOPs with consecutive instruction indexes.
      while (nop_it != nop_spec.end() && nop_it->first == write_index) {
        assm.nop(nop_it->second);
        ++nop_it;
        ++write_index;
      }
    }
    ++inst_it;
    ++write_index;
  }
}

bool FillerBasicBlockTransform::TransformBasicBlockSubGraph(
      const TransformPolicyInterface* policy,
      BlockGraph* block_graph,
      BasicBlockSubGraph* basic_block_subgraph) {
  DCHECK(nullptr != policy);
  DCHECK(nullptr != block_graph);
  DCHECK(nullptr != basic_block_subgraph);

  // Visit each basic code block and inject NOPs.
  BasicBlockSubGraph::BBCollection& basic_blocks =
      basic_block_subgraph->basic_blocks();
  for (auto& bb : basic_blocks) {
    BasicCodeBlock* bc_block = BasicCodeBlock::Cast(bb);
    if (bc_block != nullptr) {
      BasicBlock::Instructions* instructions = &bc_block->instructions();
      NopSpec nop_spec;
      size_t size = instructions->size();
      // Inject NOP after every instruction, except the last.
      for (size_t i = 1; i < size; ++i) {
        nop_spec[i * 2 - 1] = NopSizes::NOP1;
      }
      InjectNop(nop_spec, debug_friendly_, instructions);
    }
  }
  return true;
}

FillerTransform::FillerTransform(const std::set<std::string>& target_set,
                                 bool add_copy)
    : debug_friendly_(false),
      num_blocks_(0),
      num_code_blocks_(0),
      num_targets_updated_(0),
      add_copy_(add_copy) {
  // Targets are not found yet, so initialize value to null.
  for (const std::string& target : target_set)
    target_visited_[target] = false;
}

bool FillerTransform::ShouldProcessBlock(Block* block) const {
  return target_visited_.find(block->name()) != target_visited_.end();
}

void FillerTransform::CheckAllTargetsFound() const {
  bool has_missing = false;
  for (const auto& it : target_visited_) {
    if (it.second)
      continue;
    if (!has_missing) {
      LOG(WARNING) << "There are missing target(s):";
      has_missing = true;
    }
    LOG(WARNING) << "  " << it.first;
  }
}

bool FillerTransform::PreBlockGraphIteration(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    Block* header_block) {
  return true;
}

bool FillerTransform::OnBlock(const TransformPolicyInterface* policy,
                              BlockGraph* block_graph,
                              Block* block) {
  DCHECK(nullptr != policy);
  DCHECK(nullptr != block_graph);
  DCHECK(nullptr != block);

  ++num_blocks_;
  if (block->type() != BlockGraph::CODE_BLOCK)
    return true;

  ++num_code_blocks_;
  if (!ShouldProcessBlock(block))
    return true;

  // Mark target as found. Add copy of target if specified to do so.
  std::string name(block->name());
  auto target_it = target_visited_.find(block->name());
  if (target_it != target_visited_.end()) {
    target_it->second = true;
    if (add_copy_)
      block_graph->CopyBlock(block, block->name() + "_copy");
  }

  // Skip blocks that aren't eligible for basic-block decomposition.
  if (!policy->BlockIsSafeToBasicBlockDecompose(block))
    return true;

  ++num_targets_updated_;
  // Apply the basic block transform.
  FillerBasicBlockTransform basic_block_transform;
  basic_block_transform.set_debug_friendly(debug_friendly());
  return ApplyBasicBlockSubGraphTransform(
      &basic_block_transform, policy, block_graph, block, NULL);
}

bool FillerTransform::PostBlockGraphIteration(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    Block* header_block) {
  LOG(INFO) << "Found " << num_blocks_ << " block(s).";
  LOG(INFO) << "Found " << num_code_blocks_ << " code block(s).";
  LOG(INFO) << "Updated " << num_targets_updated_ << " blocks(s).";
  CheckAllTargetsFound();
  return true;
}

}  // namespace transforms
}  // namespace instrument
