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

#include "syzygy/block_graph/analysis/control_flow_analysis.h"

#include <set>
#include <stack>

namespace block_graph {
namespace analysis {
namespace {

typedef BasicBlockSubGraph::BBCollection BBCollection;
typedef block_graph::BasicBlockSubGraph::BasicBlock BasicBlock;
typedef block_graph::BasicBlockSubGraph::BasicBlock::Successors Successors;
typedef block_graph::BasicBlockSubGraph::BasicCodeBlock BasicCodeBlock;

}  // namespace

void ControlFlowAnalysis::Analyze(const BasicBlockSubGraph* subgraph) {
  DCHECK_NE(reinterpret_cast<BasicBlockSubGraph*>(NULL), subgraph);

  // TODO(etienneb): Control Flow Analysis by interval analysis.
}

void ControlFlowAnalysis::FlattenBasicBlocksInPostOrder(
    const BBCollection& basic_blocks,
    std::vector<const BasicCodeBlock*>* order) {
  DCHECK(order != NULL);

  // Build a reverse post-order (RPO) ordering of basic blocks. This is needed
  // for faster fix-point convergence, but works with any ordering.
  std::set<BasicBlock*> marked;
  std::stack<BasicBlock*> working;

  // For each basic block, flatten its reachable sub-tree in post-order.
  BBCollection::const_iterator iter_end = basic_blocks.end();
  for (BBCollection::const_iterator iter = basic_blocks.begin();
       iter != iter_end; ++iter) {
    // When not marked, mark it and add it to working stack.
    if (marked.insert(*iter).second)
      working.push(*iter);

    // Flatten this tree without following back-edge, push them in post-order.
    while (!working.empty()) {
      const BasicBlock* top = working.top();

      // Skip data basic block.
      const BasicCodeBlock* bb = BasicCodeBlock::Cast(top);
      if (bb == NULL) {
        working.pop();
        continue;
      }

      // Add unvisited child to the working stack.
      bool has_unvisited_child = false;
      const BasicBlock::Successors& successors = bb->successors();
      Successors::const_iterator succ_end = successors.end();
      for (Successors::const_iterator succ = successors.begin();
           succ != succ_end;  ++succ) {
        BasicBlock* basic_block = succ->reference().basic_block();
        // When not marked, mark it and add it to working stack.
        if (marked.insert(basic_block).second) {
          working.push(basic_block);
          has_unvisited_child = true;
          break;
        }
      }

      if (!has_unvisited_child) {
        // Push this basic block in post-order in the ordering.
        order->push_back(bb);
        working.pop();
      }
    }
  }
}

}  // namespace analysis
}  // namespace block_graph
