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

#include "syzygy/optimize/transforms/basic_block_reordering_transform.h"

#include "syzygy/block_graph/block_graph.h"
#include "syzygy/optimize/application_profile.h"

namespace optimize {
namespace transforms {

namespace {

using block_graph::BasicBlock;
using block_graph::BasicCodeBlock;
using block_graph::BasicBlockSubGraph;
using block_graph::Successor;
using block_graph::analysis::ControlFlowAnalysis;
typedef ControlFlowAnalysis::BasicBlockOrdering BasicBlockOrdering;
typedef ControlFlowAnalysis::StructuralTree StructuralTree;
typedef ControlFlowAnalysis::StructuralNode StructuralNode;
typedef SubGraphProfile::BasicBlockProfile BasicBlockProfile;
typedef grinder::basic_block_util::EntryCountType EntryCountType;

// A helper to "cast" the given successor as a BasicCodeBlock.
const BasicCodeBlock* GetSuccessorBB(const Successor& successor) {
  const BasicBlock* bb = successor.reference().basic_block();

  // This might be an inter block reference (i.e., refers to a block not
  // a basic-block).
  if (bb == NULL)
    return NULL;

  // If it's a basic-block then it must be a code basic-block.
  const BasicCodeBlock* code_bb = BasicCodeBlock::Cast(bb);
  DCHECK_NE(reinterpret_cast<BasicCodeBlock*>(NULL), code_bb);
  return code_bb;
}

void FlattenStructuralTreeRecursive(const StructuralNode* tree,
                                    const SubGraphProfile* profile,
                                    BasicBlockOrdering* order,
                                    BasicBlockOrdering* cold) {
  DCHECK_NE(reinterpret_cast<StructuralNode*>(NULL), tree);
  DCHECK_NE(reinterpret_cast<SubGraphProfile*>(NULL), profile);
  DCHECK_NE(reinterpret_cast<BasicBlockOrdering*>(NULL), order);
  DCHECK_NE(reinterpret_cast<BasicBlockOrdering*>(NULL), cold);

  // TODO(etienneb): Implement rules based on profile.
  switch (tree->kind()) {
    case StructuralNode::kBaseNode: {
      order->push_back(tree->root());
      break;
    }
    case StructuralNode::kSequenceNode: {
      FlattenStructuralTreeRecursive(tree->entry_node(), profile, order, cold);
      FlattenStructuralTreeRecursive(tree->sequence_node(),
                                     profile,
                                     order,
                                     cold);
      break;
    }
    case StructuralNode::kIfThenNode: {
      FlattenStructuralTreeRecursive(tree->entry_node(), profile, order, cold);
      FlattenStructuralTreeRecursive(tree->then_node(), profile, order, cold);
      break;
    }
    case StructuralNode::kIfThenElseNode: {
      FlattenStructuralTreeRecursive(tree->entry_node(), profile, order, cold);
      FlattenStructuralTreeRecursive(tree->then_node(), profile, order, cold);
      FlattenStructuralTreeRecursive(tree->else_node(), profile, order, cold);
      break;
    }
    case StructuralNode::kRepeatNode: {
      FlattenStructuralTreeRecursive(tree->entry_node(), profile, order, cold);
      break;
    }
    case StructuralNode::kWhileNode: {
      FlattenStructuralTreeRecursive(tree->entry_node(), profile, order, cold);
      FlattenStructuralTreeRecursive(tree->body_node(), profile, order, cold);
      break;
    }
    case StructuralNode::kLoopNode: {
      FlattenStructuralTreeRecursive(tree->entry_node(), profile, order, cold);
      break;
    }
    default: {
      NOTREACHED() << "Invalid structural-tree node.";
    }
  }
}

}  // namespace

bool BasicBlockReorderingTransform::FlattenStructuralTreeToAnOrder(
    const BasicBlockSubGraph* subgraph,
    const SubGraphProfile* subgraph_profile,
    BasicBlockOrdering* order) {
  DCHECK_NE(reinterpret_cast<const BasicBlockSubGraph*>(NULL), subgraph);
  DCHECK_NE(reinterpret_cast<BasicBlockOrdering*>(NULL), order);

  // Build a structural tree.
  ControlFlowAnalysis::StructuralTree tree;
  bool reducible = ControlFlowAnalysis::BuildStructuralTree(subgraph, &tree);
  if (!reducible)
    return false;

  // Flatten the structural tree.
  BasicBlockOrdering cold;
  FlattenStructuralTreeRecursive(tree.get(),
                                 subgraph_profile,
                                 order,
                                 &cold);

  // Cold basic blocks are appended after the hot ones.
  order->insert(order->end(), cold.begin(), cold.end());

  return reducible;
}

uint64 BasicBlockReorderingTransform::EvaluateCost(
    const BasicBlockOrdering& order,
    const SubGraphProfile& profile) {
  uint64 accumulate = 0;

  // For each basic block, accumulate the number of taken jumps.
  BasicBlockOrdering::const_iterator it = order.begin();
  for (; it != order.end(); ++it) {
    const BasicCodeBlock* bb = BasicCodeBlock::Cast(*it);
    if (bb == NULL)
      continue;

    // Get the successor of this basic block in the ordering.
    BasicBlockOrdering::const_iterator next = it;
    next++;

    // Retrieve the basic block profile information.
    const BasicBlockProfile* bb_profile = profile.GetBasicBlockProfile(bb);
    EntryCountType bb_count = bb_profile->count();

    // Accumulate the count for jumps which do not target the next basic block.
    const BasicCodeBlock::Successors& successors = bb->successors();
    BasicCodeBlock::Successors::const_iterator succ = successors.begin();
    for (; succ != successors.end(); ++succ) {
      const BasicCodeBlock* succ_bb = GetSuccessorBB(*succ);
      if (succ_bb == NULL)
        continue;
      // Assume the branch is taken when the basic block is the last one or when
      // the next successor doesn't jump to the next basic block.
      if (next == order.end() || succ_bb != *next)
        accumulate += bb_profile->GetSuccessorCount(succ_bb);
    }
  }

  return accumulate;
}

void BasicBlockReorderingTransform::CommitOrdering(
    const BasicBlockOrdering& order,
    BasicBlockSubGraph::BasicBlockOrdering* target) {
  DCHECK_NE(reinterpret_cast<BasicBlockSubGraph::BasicBlockOrdering*>(NULL),
            target);

  size_t previous_size = target->size();
  target->clear();

  std::set<BasicCodeBlock*> placed;

  BasicBlockOrdering::const_iterator it = order.begin();
  for (; it != order.end(); ++it) {
    BasicCodeBlock* bb = const_cast<BasicCodeBlock*>(*it);
    CHECK(placed.insert(bb).second);
    target->push_back(bb);
  }

  CHECK_EQ(previous_size, target->size());
}

bool BasicBlockReorderingTransform::TransformBasicBlockSubGraph(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BasicBlockSubGraph* subgraph,
    ApplicationProfile* profile,
    SubGraphProfile* subgraph_profile) {
  DCHECK_NE(reinterpret_cast<TransformPolicyInterface*>(NULL), policy);
  DCHECK_NE(reinterpret_cast<BlockGraph*>(NULL), block_graph);
  DCHECK_NE(reinterpret_cast<BasicBlockSubGraph*>(NULL), subgraph);
  DCHECK_NE(reinterpret_cast<ApplicationProfile*>(NULL), profile);
  DCHECK_NE(reinterpret_cast<SubGraphProfile*>(NULL), subgraph_profile);

  // Do not reorder cold code.
  const BlockGraph::Block* block = subgraph->original_block();
  DCHECK_NE(reinterpret_cast<const BlockGraph::Block*>(NULL), block);
  const ApplicationProfile::BlockProfile* block_profile =
      profile->GetBlockProfile(block);
  if (block_profile->count() == 0)
    return true;

  // Avoid reordering a block with a jump table or data block.
  // TODO(etienneb): Add support for jump table reordering.
  BasicBlockSubGraph::BBCollection::iterator bb_iter =
      subgraph->basic_blocks().begin();
  for (; bb_iter != subgraph->basic_blocks().end(); ++bb_iter) {
    BasicCodeBlock* bb = BasicCodeBlock::Cast(*bb_iter);
    if (bb == NULL)
      return true;
  }

  // Retrieve the block description.
  BasicBlockSubGraph::BlockDescriptionList& descriptions =
      subgraph->block_descriptions();
  if (descriptions.size() != 1)
    return true;

  // Retrieve the original ordering of this subgraph.
  BasicBlockOrdering original_order;
  BasicBlockSubGraph::BasicBlockOrdering& original_order_list =
      descriptions.begin()->basic_block_order;
  BasicBlockSubGraph::BasicBlockOrdering::const_iterator order_it =
      original_order_list.begin();
  for (; order_it != original_order_list.end(); ++order_it) {
    BasicCodeBlock* bb = BasicCodeBlock::Cast(*order_it);
    DCHECK_NE(reinterpret_cast<BasicCodeBlock*>(NULL), bb);
    original_order.push_back(bb);
  }

  // Compute the number of jumps taken for the original ordering.
  uint64 original_cost = EvaluateCost(original_order, *subgraph_profile);
  if (original_cost == 0)
    return true;

  BasicBlockOrdering flatten_order;
  bool reducible = FlattenStructuralTreeToAnOrder(subgraph,
                                                  subgraph_profile,
                                                  &flatten_order);
  if (reducible) {
    // Compute the number of jumps taken for the optimized ordering.
    uint64 flatten_cost = EvaluateCost(flatten_order, *subgraph_profile);

    // If the new basic block layout is better than the previous one, commit it.
    if (flatten_cost < original_cost)
      CommitOrdering(flatten_order, &original_order_list);
  }

  return true;
}

}  // namespace transforms
}  // namespace optimize
