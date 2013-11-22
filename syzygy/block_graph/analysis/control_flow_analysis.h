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
/// A class that performs a structural control flow analysis of a subgraph.
//
#ifndef SYZYGY_BLOCK_GRAPH_ANALYSIS_CONTROL_FLOW_ANALYSIS_H_
#define SYZYGY_BLOCK_GRAPH_ANALYSIS_CONTROL_FLOW_ANALYSIS_H_

#include <vector>

#include "base/basictypes.h"
#include "syzygy/block_graph/basic_block.h"
#include "syzygy/block_graph/basic_block_subgraph.h"

namespace block_graph {
namespace analysis {

// This class implements control-flow analysis on a SubGraph.
//
// Control-Flow Ordering
// ----------------------------
// The control-flow analysis provides an ordering analysis. The order allows two
// directions for traversing the flow graph: Post-Order and Reverse Post-Order.
//
// Post-Order:
//     This is a typical iteration order for backward data-flow problems. In
//     post-order iteration, a node is visited after all its successor nodes
//     have been visited.
//
// Reverse Post-Order:
//     This is a typical iteration order for forward data-flow problems. In
//     reverse post-order iteration, a node is visited before any of its
//     successor nodes has been visited (except for back edges).
//
// Example:
//
//  const BBCollection& basic_blocks = subgraph->basic_blocks();
//  BasicBlockOrdering order;
//  ControlFlowAnalysis::FlattenBasicBlocksInPostOrder(basic_blocks, &order);
//  BasicBlockOrdering::const_reverse_iterator it = order.rbegin();
//  for (; it != order.rend(); ++it) {
//    // Perform an action in reverse post order.
//  }
//
//  This graph will be flattened to: [n5, n4, n2, n3, n1, n0].
//
//           /--\
//         (n0)  |
//        /      |
//      (n1)     |
//      /  \     |
//    (n2) (n3)  |
//      \  /     |
//      (n4)     |
//      / \------/
//   (n5)
//
// Structural Analysis
// ----------------------------
// The structural analysis is a conservative analysis which tries to reduce the
// flow graph to a structural tree. A structural tree is composed of the basic
// flow operators found in programming language: statement, if, while, loop.
//
// See: "Advanced Compiler Design Implementation", by Steven S. Muchnick.
//       Chapter 7.7 Structural Analysis.
//
// Example:
//
//  BasicBlockSubGraph subgraph;
//  ControlFlowAnalysis::StructuralTree tree;
//  bool reducible = ControlFlowAnalysis::BuildStructuralTree(&subgraph, &tree);
//  if (reducible) {
//    std::string txt;
//    CHECK(tree->ToString(&txt));
//    LOG(INFO) << "Reduce to:\n" << txt'
//  }
//
//  The graph on the left reduces to the tree on the right:
//
//           /--\               Sequence
//         (n0)  |               /     \
//        /      |             Repeat  n5
//      (n1)     |              |
//      /  \     |           Sequence
//    (n2) (n3)  |           /    \
//      \  /     |          n0    Sequence
//      (n4)     |                 /     \
//      / \------/            IfThenElse  \
//   (n5)                      /  |  \     \
//                            n1  n2  n3   n4

class ControlFlowAnalysis {
 public:
  typedef block_graph::BasicBlockSubGraph BasicBlockSubGraph;
  typedef BasicBlockSubGraph::BBCollection BBCollection;
  typedef std::vector<const BasicCodeBlock*> BasicBlockOrdering;

  // Forward declaration.
  class StructuralNode;
  typedef scoped_ptr<StructuralNode> StructuralTree;

  // Constructor.
  ControlFlowAnalysis() { }

  // Construct a structural representation of a given control flow graph.
  // @param subgraph SubGraph to apply the structural analysis.
  // @param tree receives the structural tree.
  // @returns true on success, false otherwise.
  static bool BuildStructuralTree(const BasicBlockSubGraph* subgraph,
                                  StructuralTree* tree);

  // Traverse basic blocks in depth first and push basic blocks in post order.
  // @param basic_blocks The basic blocks to order.
  // @param order Receives the basic blocks in post order.
  static void FlattenBasicBlocksInPostOrder(
      const BBCollection& basic_blocks,
      BasicBlockOrdering* order);

 private:
  DISALLOW_COPY_AND_ASSIGN(ControlFlowAnalysis);
};

// StructuralNode is the building block of the StructuralTree produced by the
// control-flow analysis. The structural tree recursively divides the
// control-flow graph into regions with a single entry node and a single exit
// node. A StructuralNode has a kind which represents the semantics of the
// region and has different child nodes (depending on the kind of node).
//
// Base:
// ===========
//  (entry)
//     |
// basic-block
//
// Sequential:
// ===========
//  Sequence      IfThen          IfThenElse
//
//  (entry)        (entry)         (entry)
//     |             | \            /  \
// (sequence)        | (then)   (then) (else)
//     |             |  /          \    /
//                   |/             \  /
// Looping:
// ===========
//  Repeat        While           Loop
//
//      | /---\      | /---\         | /---\
//   (entry)  |   (entry)   \     (entry)  |
//     / \----/     / \      |       \-----/
//    /            /  (body) |
//                       \--/

class ControlFlowAnalysis::StructuralNode {
 public:
  typedef ControlFlowAnalysis::StructuralTree StructuralTree;

  // Structural node kinds.
  enum Kind {
    kBaseNode,
    kSequenceNode,
    kIfThenNode,
    kIfThenElseNode,
    kRepeatNode,
    kWhileNode,
    kLoopNode,
    // Below this point: internal nodes should not occur in the resulting tree.
    kStartNode,
    kStopNode,
  };

  // @name Constructors.
  // @{
  // @param kind the kind of the region.
  // @param root the entry basic block of the region.
  // @param entry_node the entry node of the tree.
  // @param child1 the first child of the tree.
  // @param child2 the second child of the tree.
  explicit StructuralNode(Kind kind);
  StructuralNode(Kind kind, const BasicCodeBlock* root);
  StructuralNode(Kind kind, StructuralTree entry_node);
  StructuralNode(Kind kind,
                 StructuralTree entry_node,
                 StructuralTree child1);
  StructuralNode(Kind kind,
                 StructuralTree entry_node,
                 StructuralTree child1,
                 StructuralTree child2);
  // @}

  // @returns the kind of the region.
  Kind kind() const { return kind_; }

  // @returns the first basic block of the region.
  const BasicCodeBlock* root() const;

  // @name Accessors.
  // @note The kind of region is validated by the accessors. It is invalid to
  // access a field that is not defined for the given node type.
  // @{
  const StructuralNode* entry_node() const;
  const StructuralNode* sequence_node() const;
  const StructuralNode* then_node() const;
  const StructuralNode* else_node() const;
  const StructuralNode* body_node() const;
  // @}

  // Produce a textual representation of the tree.
  // @param str receives the resulting text.
  // @returns true on success, false otherwise.
  bool ToString(std::string* str) const;

 private:
  // The region kind.
  Kind kind_;

  // The entry basic block of the region.
  const BasicCodeBlock* root_;

  // Sub-trees of this node.
  StructuralTree entry_node_;
  StructuralTree child1_;
  StructuralTree child2_;
};

}  // namespace analysis
}  // namespace block_graph

#endif  // SYZYGY_BLOCK_GRAPH_ANALYSIS_CONTROL_FLOW_ANALYSIS_H_
