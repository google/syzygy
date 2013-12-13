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
// The structural analysis is a control flow analysis applied on a flow graph
// of basic blocks which produces a structural tree. The algorithm reduces the
// graph by applying iteratively applying basic block reduction patterns on a
// root node until a stable state (no more reductions are possible). If the
// resulting graph is a single node, the graph is reducible, otherwise it cannot
// be represented as a tree.
//
// Each basic pattern matches a region with a single entry node and single exit
// node (SESE). By definition, incoming edges to a child are forbidden. Thus,
// a pattern reduces the smallest reducible region.
//
// Matching patterns must not overlap otherwise the reduction will not be
// deterministic. In the current implementation, the Sequence reduction is not
// deterministic thus it is possible to obtain different valid trees for the
// same flow graph.
// TODO(etienneb): Add a canonical form for the Sequence nodes.
//
// Example:
//
//  (a)      /--\    (b)     /--\    (c)     /--\
//         (n0)  |         (n0)  |         (n0)  |
//        /      |         /     |         /     |
//      (n1)     |         |     |         |     |
//      /  \     |       (n123)  |       (n1234) |
//    (n2) (n3)  |          |    |          |    |
//      \  /     |          |    |          |    |
//      (n4)     |         (n4)  |          |    |
//      / \------/         / \---/         / \---/
//   (n5)               (n5)            (n5)
//
//
//  (d)    /--\      (e)  (n01234)   (f)  n(012345)
//        |    |              |
//     (n01234)|            (n5)
//        |    |
//       / \--/
//     (n5)
//
// The above graph (also present in the header file) reduces by applying the
// following sequence of transformation:
//
//     a) Original graph
//     b) Reduce an IfThenElse on (n1), produce (n123).
//     c) Reduce a Sequence on (n123), produce (n1234).
//     d) Reduce a Repeat on (n1234), produce (n1234) without the back edge.
//     e) Reduce a Sequence on (n012345), produce n(012345)
//     f) The resulting graph.

#include "syzygy/block_graph/analysis/control_flow_analysis.h"

#include <list>
#include <set>
#include <sstream>
#include <stack>

namespace block_graph {
namespace analysis {
namespace {

typedef block_graph::analysis::ControlFlowAnalysis::StructuralNode
    StructuralNode;
typedef block_graph::BasicBlockSubGraph::BasicBlock BasicBlock;
typedef block_graph::BasicBlockSubGraph::BasicCodeBlock BasicCodeBlock;
typedef block_graph::BasicBlockSubGraph::BasicBlock::Successors Successors;
typedef block_graph::BasicBlockSubGraph::BBCollection BBCollection;
typedef block_graph::BasicBlockSubGraph::BlockDescriptionList
    BlockDescriptionList;

typedef ControlFlowAnalysis::StructuralTree StructuralTree;
typedef std::map<const BasicCodeBlock*, StructuralTree> BasicBlocksRemap;
typedef std::list<StructuralTree*> StructuralTreeList;
typedef std::map<StructuralTree*, StructuralTreeList> AbstractLinks;

void AddLink(StructuralTree* from,
             StructuralTree* to,
             AbstractLinks* forward_list,
             AbstractLinks* backward_list) {
  DCHECK_NE(reinterpret_cast<StructuralTree*>(NULL), from);
  DCHECK_NE(reinterpret_cast<StructuralTree*>(NULL), to);
  DCHECK_NE(reinterpret_cast<AbstractLinks*>(NULL), forward_list);
  DCHECK_NE(reinterpret_cast<AbstractLinks*>(NULL), backward_list);
  (*forward_list)[from].push_back(to);
  (*backward_list)[to].push_back(from);
}

void RemoveLink(StructuralTree* from,
                StructuralTree* to,
                AbstractLinks* forward_list,
                AbstractLinks* backward_list) {
  DCHECK_NE(reinterpret_cast<StructuralTree*>(NULL), from);
  DCHECK_NE(reinterpret_cast<StructuralTree*>(NULL), to);
  DCHECK_NE(reinterpret_cast<AbstractLinks*>(NULL), forward_list);
  DCHECK_NE(reinterpret_cast<AbstractLinks*>(NULL), backward_list);

  StructuralTreeList& sources = (*forward_list)[from];
  StructuralTreeList& destinations = (*backward_list)[to];
  sources.remove(to);
  destinations.remove(from);

  if (sources.empty())
    forward_list->erase(from);
  if (destinations.empty())
    backward_list->erase(to);
}

void MoveLinks(StructuralTree* from,
               StructuralTree* to,
               AbstractLinks* forward_list,
               AbstractLinks* backward_list) {
  DCHECK_NE(reinterpret_cast<StructuralTree*>(NULL), from);
  DCHECK_NE(reinterpret_cast<StructuralTree*>(NULL), to);
  DCHECK_NE(reinterpret_cast<AbstractLinks*>(NULL), forward_list);
  DCHECK_NE(reinterpret_cast<AbstractLinks*>(NULL), backward_list);

  // Need a copy of the sources because they are updated via RemoveLink/AddLink.
  StructuralTreeList sources = (*forward_list)[from];
  StructuralTreeList::iterator it = sources.begin();
  for (; it != sources.end(); ++it) {
    RemoveLink(from, *it, forward_list, backward_list);
    AddLink(to, *it, forward_list, backward_list);
  }
}

bool SwapNode(bool swap, StructuralTree** node1, StructuralTree** node2) {
  DCHECK_NE(reinterpret_cast<StructuralTree**>(NULL), node1);
  DCHECK_NE(reinterpret_cast<StructuralTree**>(NULL), node2);
  if (swap) {
    StructuralTree* tmp = *node1;
    *node1 = *node2;
    *node2 = tmp;
  }

  return true;
}

bool CheckDistinct(StructuralTree* node1, StructuralTree* node2) {
  DCHECK_NE(reinterpret_cast<StructuralTree*>(NULL), node1);
  DCHECK_NE(reinterpret_cast<StructuralTree*>(NULL), node2);
  DCHECK_NE(reinterpret_cast<StructuralNode*>(NULL), node1->get());
  DCHECK_NE(reinterpret_cast<StructuralNode*>(NULL), node2->get());
  return node1 != node2;
}

bool CheckDistinct(StructuralTree* node1,
                   StructuralTree* node2,
                   StructuralTree* node3) {
  if (!CheckDistinct(node1, node2) ||
      !CheckDistinct(node1, node3) ||
      !CheckDistinct(node2, node3)) {
    return false;
  }
  return true;
}

// If |current| has only exactly one link into |links|, returns it into target.
// Otherwise, returns false.
bool MatchUniqueLink(const AbstractLinks& links,
                     StructuralTree* current,
                     StructuralTree** target) {
  DCHECK_NE(reinterpret_cast<StructuralTree*>(NULL), current);
  DCHECK_NE(reinterpret_cast<StructuralTree**>(NULL), target);

  AbstractLinks::const_iterator look = links.find(current);
  if (look == links.end())
    return false;

  const StructuralTreeList& lst = look->second;
  if (lst.size() != 1)
    return false;

  *target = lst.front();
  return true;
}

// If |current| has only exactly two links into |links|, returns them into
// target1 and target2. Otherwise, returns false.
bool MatchTwoLinks(const AbstractLinks& links,
                   StructuralTree* current,
                   StructuralTree** target1,
                   StructuralTree** target2) {
  DCHECK_NE(reinterpret_cast<StructuralTree*>(NULL), current);
  DCHECK_NE(reinterpret_cast<StructuralTree**>(NULL), target1);
  DCHECK_NE(reinterpret_cast<StructuralTree**>(NULL), target2);

  AbstractLinks::const_iterator look = links.find(current);
  if (look == links.end())
    return false;

  const StructuralTreeList& lst = look->second;
  if (lst.size() != 2)
    return false;

  *target1 = lst.front();
  *target2 = lst.back();
  return true;
}

// Check if |current| has only one link into |links|, and validate that this
// link is to |target|. Otherwise, returns false.
bool CheckUniqueLink(const AbstractLinks& links,
                     StructuralTree* current,
                     StructuralTree* target) {
  StructuralTree* matched_target = NULL;
  if (!MatchUniqueLink(links, current, &matched_target))
    return false;

  if (target != matched_target)
    return false;

  return true;
}

// Check if |current| has only two links into |links|, and validate that those
// links are |target1| and |target2|. Otherwise, returns false.
bool CheckTwoLinks(const AbstractLinks& links,
                   StructuralTree* current,
                   StructuralTree* target1,
                   StructuralTree* target2) {
  StructuralTree* matched_target1 = NULL;
  StructuralTree* matched_target2 = NULL;
  if (!MatchTwoLinks(links, current, &matched_target1, &matched_target2))
    return false;

  if (target1 != matched_target1 || target2 != matched_target2)
    return false;

  return true;
}

// Try to reduce a Sequence pattern on |current_node|. Match when |current_node|
// has only one successor and this successor has only |current_node| as
// predecessor. No incoming edges are allowed into the successor.
bool MatchSequenceNode(StructuralTree* current_node,
                       AbstractLinks* predecessor_links,
                       AbstractLinks* successor_links) {
  DCHECK_NE(reinterpret_cast<StructuralTree*>(NULL), current_node);
  DCHECK_NE(reinterpret_cast<AbstractLinks*>(NULL), predecessor_links);
  DCHECK_NE(reinterpret_cast<AbstractLinks*>(NULL), successor_links);

  StructuralTree* end_node = NULL;

  // Try to match a SequenceNode.
  if (MatchUniqueLink(*successor_links, current_node, &end_node) &&
      CheckUniqueLink(*predecessor_links, end_node, current_node) &&
      end_node->get()->kind() != StructuralNode::kStopNode &&
      CheckDistinct(current_node, end_node)) {
    current_node->reset(new StructuralNode(StructuralNode::kSequenceNode,
                                           current_node->Pass(),
                                           end_node->Pass()));

    // Remove internal links.
    RemoveLink(current_node, end_node, successor_links, predecessor_links);

    // Move successor of end_node to current_node links.
    MoveLinks(end_node, current_node, successor_links, predecessor_links);

    return true;
  }

  return false;
}

// Try to reduce an IfThen pattern on |current_node|. A pattern is found when
// |current_node| has only two successors: (then), (end). The (then) node does
// not have other predecessor, except (entry). The (then) node has (end) as
// successor. No incoming edges are allowed into (then).
//
//    (entry)                   (entry,then)
//      | \                           |
//      | (then)       ->             |
//      | /                         (end)
//      |/
//     (end)
bool MatchIfThenNode(StructuralTree* current_node,
                     AbstractLinks* predecessor_links,
                     AbstractLinks* successor_links,
                     bool swap) {
  DCHECK_NE(reinterpret_cast<StructuralTree*>(NULL), current_node);
  DCHECK_NE(reinterpret_cast<AbstractLinks*>(NULL), predecessor_links);
  DCHECK_NE(reinterpret_cast<AbstractLinks*>(NULL), successor_links);

  StructuralTree* then_node = NULL;
  StructuralTree* end_node = NULL;

  // Try to match an IfThenNode.
  if (MatchTwoLinks(*successor_links, current_node, &then_node, &end_node) &&
      SwapNode(swap, &then_node, &end_node) &&
      CheckUniqueLink(*successor_links, then_node, end_node) &&
      CheckUniqueLink(*predecessor_links, then_node, current_node) &&
      CheckDistinct(current_node, then_node)) {
    current_node->reset(new StructuralNode(StructuralNode::kIfThenNode,
                                           current_node->Pass(),
                                           then_node->Pass()));

    // Remove internal links.
    RemoveLink(current_node, then_node, successor_links, predecessor_links);
    RemoveLink(then_node, end_node, successor_links, predecessor_links);
    RemoveLink(current_node, end_node, successor_links, predecessor_links);

    // Add the new link.
    AddLink(current_node, end_node, successor_links, predecessor_links);

    return true;
  }

  return false;
}

// Try to reduce an IfThenElse pattern on |current_node|. A pattern is found
// when |current_node| has only two successors: (then), (else). The (then) and
// (else) nodes do not have other predecessor, except (entry). Both (then) and
// (else) nodes have (end) as successor. No incoming edges are allowed into
// (then) and (else).
//
//    (entry)                (entry,then,else)
//     /   \                          |
// (then) (else)       ->             |
//     \   /                        (end)
//      \ /
//     (end)
bool MatchIfThenElseNode(StructuralTree* current_node,
                         AbstractLinks* predecessor_links,
                         AbstractLinks* successor_links) {
  DCHECK_NE(reinterpret_cast<StructuralTree*>(NULL), current_node);
  DCHECK_NE(reinterpret_cast<AbstractLinks*>(NULL), predecessor_links);
  DCHECK_NE(reinterpret_cast<AbstractLinks*>(NULL), successor_links);

  StructuralTree* then_node = NULL;
  StructuralTree* else_node = NULL;
  StructuralTree* end_node = NULL;

  // Try to match an IfThenElseNode.
  if (MatchTwoLinks(*successor_links, current_node, &then_node, &else_node) &&
      MatchUniqueLink(*successor_links, then_node, &end_node) &&
      CheckUniqueLink(*successor_links, else_node, end_node) &&
      CheckUniqueLink(*predecessor_links, then_node, current_node) &&
      CheckUniqueLink(*predecessor_links, else_node, current_node) &&
      CheckDistinct(current_node, then_node, else_node)) {
    current_node->reset(new StructuralNode(StructuralNode::kIfThenElseNode,
                                           current_node->Pass(),
                                           then_node->Pass(),
                                           else_node->Pass()));

    // Remove internal links.
    RemoveLink(current_node, then_node, successor_links, predecessor_links);
    RemoveLink(current_node, else_node, successor_links, predecessor_links);
    RemoveLink(then_node, end_node, successor_links, predecessor_links);
    RemoveLink(else_node, end_node, successor_links, predecessor_links);

    // Add the new link.
    AddLink(current_node, end_node, successor_links, predecessor_links);

    return true;
  }

  return false;
}

// Try to reduce a Repeat pattern on |current_node|. A pattern is found when
// |current_node| has two successors and a back edge to itself.
//
//      | /---\                      |
//   (entry)  |        ->         (entry)
//     /  \---/                      |
//    /
//
bool MatchRepeatNode(StructuralTree* current_node,
                     AbstractLinks* predecessor_links,
                     AbstractLinks* successor_links,
                     bool swap) {
  DCHECK_NE(reinterpret_cast<StructuralTree*>(NULL), current_node);
  DCHECK_NE(reinterpret_cast<AbstractLinks*>(NULL), predecessor_links);
  DCHECK_NE(reinterpret_cast<AbstractLinks*>(NULL), successor_links);

  StructuralTree* end_node = NULL;
  StructuralTree* body_node = NULL;

  // Try to match a RepeatNode.
  if (MatchTwoLinks(*successor_links, current_node, &body_node, &end_node) &&
      SwapNode(swap, &body_node, &end_node) &&
      body_node == current_node &&
      body_node != end_node) {
    current_node->reset(new StructuralNode(StructuralNode::kRepeatNode,
                                           body_node->Pass()));

    // Remove internal links.
    RemoveLink(current_node, current_node, successor_links, predecessor_links);
    RemoveLink(current_node, end_node, successor_links, predecessor_links);

    // Add the new link.
    AddLink(current_node, end_node, successor_links, predecessor_links);

    return true;
  }

  return false;
}

// Try to reduce a While pattern on |current_node|. A pattern is found when
// |current_node| has two successors. The (body) node has a successor to
// (entry), the back edge of the loop. No incoming edges are allowed into
// (body).
//
//     | /---\                        |
//  (entry)   \         ->         (entry)
//    / \      |                      |
//   /  (body) |
//         \--/
bool MatchWhileNode(StructuralTree* current_node,
                    AbstractLinks* predecessor_links,
                    AbstractLinks* successor_links,
                    bool swap) {
  DCHECK_NE(reinterpret_cast<StructuralTree*>(NULL), current_node);
  DCHECK_NE(reinterpret_cast<AbstractLinks*>(NULL), predecessor_links);
  DCHECK_NE(reinterpret_cast<AbstractLinks*>(NULL), successor_links);

  StructuralTree* body_node = NULL;
  StructuralTree* end_node = NULL;

  // Try to match a RepeatNode.
  if (MatchTwoLinks(*successor_links, current_node, &body_node, &end_node) &&
      SwapNode(swap, &body_node, &end_node) &&
      CheckUniqueLink(*predecessor_links, body_node, current_node) &&
      CheckUniqueLink(*successor_links, body_node, current_node) &&
      CheckDistinct(current_node, body_node)) {
    current_node->reset(new StructuralNode(StructuralNode::kWhileNode,
                                           current_node->Pass(),
                                           body_node->Pass()));

    // Remove internal links.
    RemoveLink(current_node, body_node, successor_links, predecessor_links);
    RemoveLink(body_node, current_node, successor_links, predecessor_links);
    RemoveLink(current_node, end_node, successor_links, predecessor_links);

    // Add the new link.
    AddLink(current_node, end_node, successor_links, predecessor_links);

    return true;
  }

  return false;
}

// Try to reduce a Loop pattern on |current_node|. An infinite loop has only
// one successor to itself.
//
//     | /--\                        |
//  (entry)  |         ->         (entry)
//       \--/
bool MatchLoopNode(StructuralTree* current_node,
                   StructuralTree* stop_node,
                   AbstractLinks* predecessor_links,
                   AbstractLinks* successor_links) {
  DCHECK_NE(reinterpret_cast<StructuralTree*>(NULL), current_node);
  DCHECK_NE(reinterpret_cast<AbstractLinks*>(NULL), predecessor_links);
  DCHECK_NE(reinterpret_cast<AbstractLinks*>(NULL), successor_links);

  StructuralTree* body_node = NULL;

  // Try to match a LoopNode.
  if (MatchUniqueLink(*successor_links, current_node, &body_node) &&
      body_node == current_node) {
    current_node->reset(new StructuralNode(StructuralNode::kLoopNode,
                                           current_node->Pass()));

    // Remove internal links.
    RemoveLink(current_node, current_node, successor_links, predecessor_links);

    // Add the new link.
    AddLink(current_node, stop_node, successor_links, predecessor_links);

    return true;
  }

  return false;
}

void DumpStructuralTreeToString(const StructuralNode* tree,
                                size_t indent,
                                std::stringstream* out) {
  DCHECK_NE(reinterpret_cast<const StructuralNode* >(NULL), tree);
  DCHECK_NE(reinterpret_cast<std::stringstream*>(NULL), out);

  std::string indent_string(4 * indent, ' ');

  switch (tree->kind()) {
    case StructuralNode::kBaseNode: {
      const BasicCodeBlock* bb = tree->root();
      BasicCodeBlock::Instructions::const_iterator it =
        bb->instructions().begin();
      for (; it != bb->instructions().end(); ++it) {
        std::string instruction_string;
        if (!it->ToString(&instruction_string)) {
          *out << "<error>\n";
        } else {
          *out << indent_string << instruction_string << "\n";
        }
      }
      break;
    }
    case StructuralNode::kSequenceNode: {
      DumpStructuralTreeToString(tree->entry_node(), indent, out);
      DumpStructuralTreeToString(tree->sequence_node(), indent, out);
      break;
    }
    case StructuralNode::kIfThenNode: {
      *out << indent_string << "IF {\n";
      DumpStructuralTreeToString(tree->entry_node(), indent + 1, out);
      *out << indent_string << "} THEN {\n";
      DumpStructuralTreeToString(tree->then_node(), indent + 1, out);
      *out << indent_string << "}\n";
      break;
    }
    case StructuralNode::kIfThenElseNode: {
      *out << indent_string << "IF {\n";
      DumpStructuralTreeToString(tree->entry_node(), indent + 1, out);
      *out << indent_string << "} THEN {\n";
      DumpStructuralTreeToString(tree->then_node(), indent + 1, out);
      *out << indent_string << "} ELSE {\n";
      DumpStructuralTreeToString(tree->else_node(), indent + 1, out);
      *out << indent_string << "}\n";
      break;
    }
    case StructuralNode::kRepeatNode: {
      *out << indent_string << "REPEAT {\n";
      DumpStructuralTreeToString(tree->entry_node(), indent + 1, out);
      *out << indent_string << "}";
      break;
    case StructuralNode::kWhileNode:
      *out << indent_string << "WHILE {\n";
      DumpStructuralTreeToString(tree->entry_node(), indent + 1, out);
      *out << indent_string << "} DO {\n";
      DumpStructuralTreeToString(tree->body_node(), indent + 1, out);
      *out << indent_string << "}\n";
      break;
    }
    case StructuralNode::kLoopNode: {
      *out << indent_string << "LOOP {\n";
      DumpStructuralTreeToString(tree->entry_node(), indent + 1, out);
      *out << indent_string << "}\n";
      break;
    }
    default: {
      NOTREACHED() << "Invalid structural node.";
    }
  }
}

}  // namespace

StructuralNode::StructuralNode(Kind kind)
    : kind_(kind), root_(NULL) {
  DCHECK(kind == kStartNode || kind == kStopNode);
}

StructuralNode::StructuralNode(Kind kind, const BasicCodeBlock* root)
    : kind_(kind), root_(root) {
  DCHECK_EQ(kBaseNode, kind);
  DCHECK_NE(reinterpret_cast<const BasicCodeBlock*>(NULL), root);
}

StructuralNode::StructuralNode(Kind kind, StructuralTree entry_node)
    : kind_(kind), root_(NULL),
      entry_node_(entry_node.Pass()) {
  root_ = entry_node_->root();
}

StructuralNode::StructuralNode(Kind kind,
                               StructuralTree entry_node,
                               StructuralTree child1)
    : kind_(kind), root_(NULL),
      entry_node_(entry_node.Pass()),
      child1_(child1.Pass()) {
  root_ = entry_node_->root();
}

StructuralNode::StructuralNode(Kind kind,
                               StructuralTree entry_node,
                               StructuralTree child1,
                               StructuralTree child2)
    : kind_(kind), root_(NULL),
      entry_node_(entry_node.Pass()),
      child1_(child1.Pass()),
      child2_(child2.Pass()) {
  root_ = entry_node_->root();
}

const BasicCodeBlock* StructuralNode::root() const {
  DCHECK_NE(reinterpret_cast<const BasicCodeBlock*>(NULL), root_);
  return root_;
}

const StructuralNode* StructuralNode::entry_node() const {
  DCHECK_NE(reinterpret_cast<const StructuralNode*>(NULL), entry_node_.get());
  return entry_node_.get();
}

const StructuralNode* StructuralNode::sequence_node() const {
  DCHECK_EQ(kind_, kSequenceNode);
  DCHECK_NE(reinterpret_cast<const StructuralNode*>(NULL), child1_.get());
  return child1_.get();
}

const StructuralNode* StructuralNode::then_node() const {
  DCHECK(kind_ == kIfThenNode || kind_ == kIfThenElseNode);
  DCHECK_NE(reinterpret_cast<const StructuralNode*>(NULL), child1_.get());
  return child1_.get();
}

const StructuralNode* StructuralNode::else_node() const {
  DCHECK_EQ(kind_, kIfThenElseNode);
  DCHECK_NE(reinterpret_cast<const StructuralNode*>(NULL), child2_.get());
  return child2_.get();
}

const StructuralNode* StructuralNode::body_node() const {
  DCHECK_EQ(kind_, kWhileNode);
  DCHECK_NE(reinterpret_cast<const StructuralNode*>(NULL), child1_.get());
  return child1_.get();
}

bool ControlFlowAnalysis::BuildStructuralTree(
    const BasicBlockSubGraph* subgraph,
    StructuralTree* tree) {
  DCHECK_NE(reinterpret_cast<BasicBlockSubGraph*>(NULL), subgraph);
  DCHECK_NE(reinterpret_cast<StructuralTree*>(NULL), tree);

  // Get a basic block ordering to reduce graph in reverse order.
  BasicBlockOrdering order;
  FlattenBasicBlocksInPostOrder(subgraph->basic_blocks(), &order);

  // Create a base StructuralNode for each basic block.
  BasicBlocksRemap basic_block_map;
  BasicBlockOrdering::iterator it = order.begin();
  for (; it != order.end(); ++it) {
    basic_block_map[*it].reset(
        new StructuralNode(StructuralNode::kBaseNode, *it));
  }

  // Add predecessors/successors to abstract nodes.
  AbstractLinks successor_links;
  AbstractLinks predecessor_links;
  BasicBlocksRemap::iterator node = basic_block_map.begin();
  for (; node != basic_block_map.end(); ++node) {
    const BasicCodeBlock* bb = node->first;
    StructuralTree* current_node = &node->second;

    // For each successor add links between predecessor and successor.
    const Successors& successors = bb->successors();
    Successors::const_iterator succ = successors.begin();
    for (; succ != successors.end(); ++succ) {
      BasicCodeBlock* next_bb =
          BasicCodeBlock::Cast(succ->reference().basic_block());
      if (next_bb == NULL)
        continue;
      StructuralTree* succ_node = &basic_block_map[next_bb];
      AddLink(current_node, succ_node, &successor_links, &predecessor_links);
    }
  }

  // Create a start and a stop node to manage block entry/exit. Those node
  // must never be folded by the fixed-point reduction.
  StructuralTree start_node;
  StructuralTree stop_node;
  start_node.reset(new StructuralNode(StructuralNode::kStartNode));
  stop_node.reset(new StructuralNode(StructuralNode::kStopNode));

  const BlockDescriptionList& descriptions = subgraph->block_descriptions();
  DCHECK(!descriptions.empty());
  BlockDescriptionList::const_iterator description = descriptions.begin();
  for (; description != descriptions.end(); ++description) {
    CHECK(!description->basic_block_order.empty());
    const BasicCodeBlock* bb =
        BasicCodeBlock::Cast(description->basic_block_order.front());
    if (bb == NULL)
      return false;
    StructuralTree& current = basic_block_map[bb];
    AddLink(&start_node, &current, &successor_links, &predecessor_links);
  }

  // Find unconnected starting and ending nodes and add missing links.
  node = basic_block_map.begin();
  for (; node != basic_block_map.end(); ++node) {
    StructuralTree& current = node->second;
    if (successor_links.find(&current) == successor_links.end())
      AddLink(&current, &stop_node, &successor_links, &predecessor_links);
    if (predecessor_links.find(&current) == predecessor_links.end())
      AddLink(&start_node, &current, &successor_links, &predecessor_links);
  }

  // Fixed-point reduction. To guarantee ending of the algorithm, the number of
  // active nodes/links must be smaller at each iteration.
  bool changed;
  do {
    changed = false;

    BasicBlockOrdering::iterator bb = order.begin();
    while (bb != order.end()) {
      BasicBlocksRemap::iterator look = basic_block_map.find(*bb);

      // This node is already reduced.
      if (look == basic_block_map.end()) {
        ++bb;
        continue;
      }

      // This node has been reduced, but not removed from active set.
      if (look->second.get() == NULL) {
        basic_block_map.erase(look);
        changed = true;
        continue;
      }

      // Try to match a pattern at a given root node.
      StructuralTree* current_node = &look->second;
      if (MatchSequenceNode(current_node,
                            &predecessor_links,
                            &successor_links) ||
          MatchIfThenNode(current_node,
                          &predecessor_links,
                          &successor_links,
                          false) ||
          MatchIfThenNode(current_node,
                          &predecessor_links,
                          &successor_links,
                          true) ||
          MatchIfThenElseNode(current_node,
                              &predecessor_links,
                              &successor_links) ||
          MatchRepeatNode(current_node,
                          &predecessor_links,
                          &successor_links,
                          false) ||
          MatchRepeatNode(current_node,
                          &predecessor_links,
                          &successor_links,
                          true) ||
          MatchWhileNode(current_node,
                         &predecessor_links,
                         &successor_links,
                         false) ||
          MatchWhileNode(current_node,
                         &predecessor_links,
                         &successor_links,
                         true) ||
          MatchLoopNode(current_node,
                        &stop_node,
                        &predecessor_links,
                        &successor_links)) {
        changed = true;
        continue;
      }

      // Move to the next basic block.
      ++bb;
    }
  } while (changed);

  // The graph must be reduced to a unique root node.
  if (basic_block_map.size() != 1)
    return false;

  // If reducing the graph is successful, returns the reduced tree.
  // The reduced graph must be: start -> tree -> stop.
  StructuralTree* reduced_tree = NULL;
  if (MatchUniqueLink(successor_links, &start_node, &reduced_tree) &&
      CheckUniqueLink(predecessor_links, reduced_tree, &start_node) &&
      CheckUniqueLink(successor_links, reduced_tree, &stop_node) &&
      CheckUniqueLink(predecessor_links, &stop_node, reduced_tree)) {
    *tree = reduced_tree->Pass();
    return true;
  }

  // TODO(etienneb): Return a forest of (partially reduced) trees when the graph
  //     is irreducible.
  return false;
}

bool ControlFlowAnalysis::StructuralNode::ToString(std::string* str) const {
  std::stringstream out;
  DumpStructuralTreeToString(this, 0, &out);
  *str = out.str();
  return true;
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

    // Flatten this tree without following back edges, push them in post-order.
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
