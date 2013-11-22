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
// Unittests for control flow analysis.

#include "syzygy/block_graph/analysis/control_flow_analysis.h"

#include "base/bind.h"
#include "base/stringprintf.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace block_graph {
namespace analysis {

// This operator is used to serialize the actual tree for error reporting.
std::ostream& operator <<(std::ostream& stream,
                          const ControlFlowAnalysis::StructuralNode* tree) {
  DCHECK_NE(reinterpret_cast<const ControlFlowAnalysis::StructuralNode*>(NULL),
            tree);
  switch (tree->kind()) {
    case ControlFlowAnalysis::StructuralNode::kBaseNode: {
      stream << "Base(";
      if (tree->root() == NULL) {
        stream << "NULL";
      } else {
        stream << tree->root()->name();
      }
      stream << ")";
      break;
    }
    case ControlFlowAnalysis::StructuralNode::kSequenceNode: {
      stream << "Sequence("
             << tree->entry_node()
             << ","
             << tree->sequence_node()
             << ")";
      break;
    }
    case ControlFlowAnalysis::StructuralNode::kIfThenNode: {
      stream << "IfThen(" << tree->entry_node() << tree->then_node() << ")";
      break;
    }
    case ControlFlowAnalysis::StructuralNode::kIfThenElseNode: {
      stream << "IfThenElse("
             << tree->entry_node()
             << ","
             << tree->then_node()
             << ","
             << tree->else_node()
             << ")";
      break;
    }
    case ControlFlowAnalysis::StructuralNode::kRepeatNode: {
      stream << "Repeat(" << tree->entry_node() << ")";
      break;
    }
   case ControlFlowAnalysis::StructuralNode::kWhileNode: {
      stream << "While(" << tree->entry_node() << ")";
      break;
    }
   case ControlFlowAnalysis::StructuralNode::kLoopNode: {
      stream << "Loop(" << tree->entry_node() << ")";
      break;
    }
   default: {
      stream << "ERROR(" << tree->entry_node() << ")";
      break;
    }
  }
  return stream;
}

namespace {

using testing::ElementsAre;
typedef BasicBlockSubGraph::BBCollection BBCollection;
typedef block_graph::BasicBlockSubGraph::BasicBlock::Successors Successors;
typedef block_graph::BasicBlockSubGraph::BasicCodeBlock BasicCodeBlock;

class ControlFlowAnalysisTest : public testing::Test {
 public:
  ControlFlowAnalysisTest() {}

 protected:
  void BuildReversePostOrder();
  bool BuildStructuralTree(BasicCodeBlock* root);

  void AddSuccessorBetween(Successor::Condition condition,
                           BasicCodeBlock* from,
                           BasicCodeBlock* to);

  void Connect(BasicCodeBlock* from,
               BasicCodeBlock* to);

  void MakeIf(BasicCodeBlock* root,
              BasicCodeBlock* true_stm,
              BasicCodeBlock* end_stm);

  BasicBlockSubGraph subgraph_;
  std::vector<const BasicCodeBlock*> order_;
  ControlFlowAnalysis::StructuralTree tree_;
};

void ControlFlowAnalysisTest::BuildReversePostOrder() {
  ControlFlowAnalysis::FlattenBasicBlocksInPostOrder(subgraph_.basic_blocks(),
                                                     &order_);
  ASSERT_EQ(subgraph_.basic_blocks().size(), order_.size());
}

bool ControlFlowAnalysisTest::BuildStructuralTree(BasicCodeBlock* entry) {
  // Add the entry block in the block description.
  BasicBlockSubGraph::BlockDescription* description =
      subgraph_.AddBlockDescription("bb1", "test.obj", BlockGraph::CODE_BLOCK,
                                    7, 2, 42);
  description->basic_block_order.push_back(entry);

  // Analyze the subgraph.
  bool result = ControlFlowAnalysis::BuildStructuralTree(&subgraph_, &tree_);
  return result;
}

void ControlFlowAnalysisTest::AddSuccessorBetween(
    Successor::Condition condition,
    BasicCodeBlock* from,
    BasicCodeBlock* to) {
  DCHECK_NE(reinterpret_cast<BasicCodeBlock*>(NULL), from);
  DCHECK_NE(reinterpret_cast<BasicCodeBlock*>(NULL), to);
  DCHECK_LT(from->successors().size(), 2U);

  from->successors().push_back(
      Successor(condition,
                BasicBlockReference(BlockGraph::RELATIVE_REF,
                                    BlockGraph::Reference::kMaximumSize,
                                    to),
                0));
}

void ControlFlowAnalysisTest::Connect(BasicCodeBlock* from,
                                      BasicCodeBlock* to) {
  DCHECK_NE(reinterpret_cast<BasicCodeBlock*>(NULL), from);
  DCHECK_NE(reinterpret_cast<BasicCodeBlock*>(NULL), to);
  DCHECK_LT(from->successors().size(), 1U);

  AddSuccessorBetween(Successor::kConditionTrue, from, to);
}

void ControlFlowAnalysisTest::MakeIf(
    BasicCodeBlock* root,
    BasicCodeBlock* true_stm,
    BasicCodeBlock* false_stm) {
  DCHECK_NE(reinterpret_cast<BasicCodeBlock*>(NULL), root);
  DCHECK_NE(reinterpret_cast<BasicCodeBlock*>(NULL), true_stm);
  DCHECK_NE(reinterpret_cast<BasicCodeBlock*>(NULL), false_stm);

  Successor::Condition condition =Successor::kConditionAbove;
  AddSuccessorBetween(condition, root, true_stm);
  AddSuccessorBetween(Successor::InvertCondition(condition), root, false_stm);
}

MATCHER_P(Base, node, "Base(...)") {
  return arg->kind() == ControlFlowAnalysis::StructuralNode::kBaseNode &&
         arg->root() == node;
}

MATCHER_P2(Sequence, node1, node2, "Sequence(...)") {
  return arg->kind() == ControlFlowAnalysis::StructuralNode::kSequenceNode &&
         testing::Value(arg->entry_node(), node1) &&
         testing::Value(arg->sequence_node(), node2);
}

MATCHER_P2(IfThen, node1, node2, "IfThen(...)") {
  return arg->kind() == ControlFlowAnalysis::StructuralNode::kIfThenNode &&
         testing::Value(arg->entry_node(), node1) &&
         testing::Value(arg->then_node(), node2);
}

MATCHER_P3(IfThenElse, node1, node2, node3, "IfThenElse(...)") {
  return arg->kind() == ControlFlowAnalysis::StructuralNode::kIfThenElseNode &&
         testing::Value(arg->entry_node(), node1) &&
         testing::Value(arg->then_node(), node2) &&
         testing::Value(arg->else_node(), node3);
}

MATCHER_P(Repeat, node1, "Repeat(...)") {
  return arg->kind() == ControlFlowAnalysis::StructuralNode::kRepeatNode &&
         testing::Value(arg->entry_node(), node1);
}

MATCHER_P2(While, node1, node2, "While(...)") {
  return arg->kind() == ControlFlowAnalysis::StructuralNode::kWhileNode &&
         testing::Value(arg->entry_node(), node1) &&
         testing::Value(arg->body_node(), node2);
}

MATCHER_P(Loop, node1, "Loop(...)") {
  return arg->kind() == ControlFlowAnalysis::StructuralNode::kLoopNode &&
         testing::Value(arg->entry_node(), node1);
}

TEST_F(ControlFlowAnalysisTest, SingleIfOneBranchOrdering) {
  BasicCodeBlock* if1 = subgraph_.AddBasicCodeBlock("if1");
  BasicCodeBlock* true1 = subgraph_.AddBasicCodeBlock("true1");
  BasicCodeBlock* end1 = subgraph_.AddBasicCodeBlock("end1");

  MakeIf(if1, true1, end1);
  Connect(true1, end1);

  ASSERT_NO_FATAL_FAILURE(BuildReversePostOrder());
  EXPECT_THAT(order_, testing::ElementsAre(end1, true1, if1));
}

TEST_F(ControlFlowAnalysisTest, SingleIfTwoBranchOrdering) {
  BasicCodeBlock* if1 = subgraph_.AddBasicCodeBlock("if1");
  BasicCodeBlock* true1 = subgraph_.AddBasicCodeBlock("true1");
  BasicCodeBlock* false1 = subgraph_.AddBasicCodeBlock("false1");
  BasicCodeBlock* end1 = subgraph_.AddBasicCodeBlock("end1");

  MakeIf(if1, true1, false1);
  Connect(true1, end1);
  Connect(false1, end1);

  ASSERT_NO_FATAL_FAILURE(BuildReversePostOrder());
  EXPECT_THAT(order_, testing::ElementsAre(end1, true1, false1, if1));
}

TEST_F(ControlFlowAnalysisTest, TwoIfOneBranchOrdering) {
  BasicCodeBlock* if1 = subgraph_.AddBasicCodeBlock("if1");
  BasicCodeBlock* true1 = subgraph_.AddBasicCodeBlock("true1");
  BasicCodeBlock* if2 = subgraph_.AddBasicCodeBlock("if2");
  BasicCodeBlock* true2 = subgraph_.AddBasicCodeBlock("true2");
  BasicCodeBlock* end = subgraph_.AddBasicCodeBlock("end");

  MakeIf(if1, true1, if2);
  Connect(true1, if2);
  MakeIf(if2, true2, end);
  Connect(true2, end);

  ASSERT_NO_FATAL_FAILURE(BuildReversePostOrder());
  EXPECT_THAT(order_, testing::ElementsAre(end, true2, if2, true1, if1));
}

TEST_F(ControlFlowAnalysisTest, SimpleLoopOrdering) {
  BasicCodeBlock* if1 = subgraph_.AddBasicCodeBlock("if1");
  BasicCodeBlock* body1 = subgraph_.AddBasicCodeBlock("body1");
  BasicCodeBlock* end1 = subgraph_.AddBasicCodeBlock("end1");

  MakeIf(if1, body1, end1);
  Connect(body1, if1);

  ASSERT_NO_FATAL_FAILURE(BuildReversePostOrder());
  EXPECT_THAT(order_, testing::ElementsAre(body1, end1, if1));
}

TEST_F(ControlFlowAnalysisTest, ComplexLoopOrdering) {
  BasicCodeBlock* if0 = subgraph_.AddBasicCodeBlock("if0");
  BasicCodeBlock* if1 = subgraph_.AddBasicCodeBlock("if1");
  BasicCodeBlock* body1 = subgraph_.AddBasicCodeBlock("body1");
  BasicCodeBlock* if2 = subgraph_.AddBasicCodeBlock("if2");
  BasicCodeBlock* body2 = subgraph_.AddBasicCodeBlock("body2");
  BasicCodeBlock* body3 = subgraph_.AddBasicCodeBlock("body3");
  BasicCodeBlock* end = subgraph_.AddBasicCodeBlock("end");

  MakeIf(if0, if1, if2);

  MakeIf(if1, body1, end);
  Connect(body1, if1);

  MakeIf(if2, body2, body3);
  Connect(body2, end);
  Connect(body3, if2);

  ASSERT_NO_FATAL_FAILURE(BuildReversePostOrder());
  EXPECT_THAT(order_,
              testing::ElementsAre(body1, end, if1, body2, body3, if2, if0));
}

TEST_F(ControlFlowAnalysisTest, SequenceStructure) {
  BasicCodeBlock* seq1 = subgraph_.AddBasicCodeBlock("seq1");
  BasicCodeBlock* seq2 = subgraph_.AddBasicCodeBlock("seq2");
  BasicCodeBlock* seq3 = subgraph_.AddBasicCodeBlock("seq3");

  Connect(seq1, seq2);
  Connect(seq2, seq3);

  ASSERT_TRUE(BuildStructuralTree(seq1));
  EXPECT_THAT(tree_.get(), Sequence(Base(seq1),
                                    Sequence(Base(seq2),
                                             Base(seq3))));
}

TEST_F(ControlFlowAnalysisTest, IfThenStructure) {
  BasicCodeBlock* if1 = subgraph_.AddBasicCodeBlock("if1");
  BasicCodeBlock* true1 = subgraph_.AddBasicCodeBlock("true1");
  BasicCodeBlock* end1 = subgraph_.AddBasicCodeBlock("end1");

  MakeIf(if1, true1, end1);
  Connect(true1, end1);

  ASSERT_TRUE(BuildStructuralTree(if1));
  EXPECT_THAT(tree_.get(), Sequence(IfThen(Base(if1), Base(true1)),
                                    Base(end1)));
}

TEST_F(ControlFlowAnalysisTest, IfThenFlippedStructure) {
  BasicCodeBlock* if1 = subgraph_.AddBasicCodeBlock("if1");
  BasicCodeBlock* true1 = subgraph_.AddBasicCodeBlock("true1");
  BasicCodeBlock* end1 = subgraph_.AddBasicCodeBlock("end1");

  MakeIf(if1, end1, true1);
  Connect(true1, end1);

  ASSERT_TRUE(BuildStructuralTree(if1));
  EXPECT_THAT(tree_.get(), Sequence(IfThen(Base(if1), Base(true1)),
                                    Base(end1)));
}

TEST_F(ControlFlowAnalysisTest, IfThenElseStructure) {
  BasicCodeBlock* if1 = subgraph_.AddBasicCodeBlock("if1");
  BasicCodeBlock* true1 = subgraph_.AddBasicCodeBlock("true1");
  BasicCodeBlock* false1 = subgraph_.AddBasicCodeBlock("false1");
  BasicCodeBlock* end1 = subgraph_.AddBasicCodeBlock("end1");

  MakeIf(if1, true1, false1);
  Connect(true1, end1);
  Connect(false1, end1);

  ASSERT_TRUE(BuildStructuralTree(if1));
  EXPECT_THAT(tree_.get(), Sequence(IfThenElse(Base(if1),
                                               Base(true1),
                                               Base(false1)),
                                    Base(end1)));
}

TEST_F(ControlFlowAnalysisTest, IfThenIfThenElseStructure) {
  BasicCodeBlock* if1 = subgraph_.AddBasicCodeBlock("if1");
  BasicCodeBlock* if2 = subgraph_.AddBasicCodeBlock("if2");
  BasicCodeBlock* true2 = subgraph_.AddBasicCodeBlock("true2");
  BasicCodeBlock* false2 = subgraph_.AddBasicCodeBlock("false2");
  BasicCodeBlock* end1 = subgraph_.AddBasicCodeBlock("end1");

  MakeIf(if1, if2, end1);
  MakeIf(if2, true2, false2);
  Connect(true2, end1);
  Connect(false2, end1);

  ASSERT_TRUE(BuildStructuralTree(if1));
  EXPECT_THAT(tree_.get(), Sequence(IfThen(Base(if1),
                                           IfThenElse(Base(if2),
                                                      Base(true2),
                                                      Base(false2))),
                                    Base(end1)));
}

TEST_F(ControlFlowAnalysisTest, SequenceOfTwoIfThenStructure) {
  BasicCodeBlock* if1 = subgraph_.AddBasicCodeBlock("if1");
  BasicCodeBlock* true1 = subgraph_.AddBasicCodeBlock("true1");
  BasicCodeBlock* if2 = subgraph_.AddBasicCodeBlock("if2");
  BasicCodeBlock* true2 = subgraph_.AddBasicCodeBlock("true2");
  BasicCodeBlock* end2 = subgraph_.AddBasicCodeBlock("end2");

  MakeIf(if1, true1, if2);
  Connect(true1, if2);
  MakeIf(if2, true2, end2);
  Connect(true2, end2);

  ASSERT_TRUE(BuildStructuralTree(if1));
  EXPECT_THAT(tree_.get(), Sequence(IfThen(Base(if1),
                                           Base(true1)),
                                    Sequence(IfThen(Base(if2),
                                                    Base(true2)),
                                             Base(end2))));
}

TEST_F(ControlFlowAnalysisTest, NestedIfThenStructure) {
  BasicCodeBlock* if1 = subgraph_.AddBasicCodeBlock("if1");
  BasicCodeBlock* if2 = subgraph_.AddBasicCodeBlock("if2");
  BasicCodeBlock* true2 = subgraph_.AddBasicCodeBlock("true2");
  BasicCodeBlock* end1 = subgraph_.AddBasicCodeBlock("end1");

  MakeIf(if1, if2, end1);
  MakeIf(if2, true2, end1);
  Connect(true2, end1);

  ASSERT_TRUE(BuildStructuralTree(if1));
  EXPECT_THAT(tree_.get(), Sequence(IfThen(Base(if1),
                                           IfThen(Base(if2),
                                                  Base(true2))),
                                    Base(end1)));
}

TEST_F(ControlFlowAnalysisTest, IfThenLongSequenceStructure) {
  BasicCodeBlock* if1 = subgraph_.AddBasicCodeBlock("if1");
  BasicCodeBlock* true1 = subgraph_.AddBasicCodeBlock("true1");
  BasicCodeBlock* true2 = subgraph_.AddBasicCodeBlock("true2");
  BasicCodeBlock* true3 = subgraph_.AddBasicCodeBlock("true3");
  BasicCodeBlock* end1 = subgraph_.AddBasicCodeBlock("end1");

  MakeIf(if1, true1, end1);
  Connect(true1, true2);
  Connect(true2, true3);
  Connect(true3, end1);

  ASSERT_TRUE(BuildStructuralTree(if1));
  EXPECT_THAT(tree_.get(), Sequence(IfThen(Base(if1),
                                           Sequence(Base(true1),
                                                    Sequence(Base(true2),
                                                             Base(true3)))),
                                    Base(end1)));
}

TEST_F(ControlFlowAnalysisTest, ComplexNestedIfStructure) {
  BasicCodeBlock* if1 = subgraph_.AddBasicCodeBlock("if1");
  BasicCodeBlock* true1 = subgraph_.AddBasicCodeBlock("true1");
  BasicCodeBlock* end1 = subgraph_.AddBasicCodeBlock("end1");
  MakeIf(if1, true1, end1);
  Connect(true1, end1);

  BasicCodeBlock* if2 = subgraph_.AddBasicCodeBlock("if2");
  BasicCodeBlock* true2 = subgraph_.AddBasicCodeBlock("true2");
  BasicCodeBlock* end2 = subgraph_.AddBasicCodeBlock("end2");
  MakeIf(if2, end2, true2);
  Connect(true2, end2);

  BasicCodeBlock* if3 = subgraph_.AddBasicCodeBlock("if3");
  MakeIf(if3, if1, if2);
  Connect(end1, end2);

  BasicCodeBlock* if4 = subgraph_.AddBasicCodeBlock("if4");
  MakeIf(if4, end2, if3);

  ASSERT_TRUE(BuildStructuralTree(if4));
  EXPECT_THAT(tree_.get(),
              Sequence(IfThen(Base(if4),
                              IfThenElse(Base(if3),
                                         Sequence(IfThen(Base(if1),
                                                         Base(true1)),
                                                  Base(end1)),
                                         IfThen(Base(if2),
                                                Base(true2)))),
                       Base(end2)));
}

TEST_F(ControlFlowAnalysisTest, RepeatStructure) {
  BasicCodeBlock* loop = subgraph_.AddBasicCodeBlock("loop");
  BasicCodeBlock* test = subgraph_.AddBasicCodeBlock("test");
  BasicCodeBlock* end = subgraph_.AddBasicCodeBlock("end");

  Connect(loop, test);
  MakeIf(test, loop, end);

  ASSERT_TRUE(BuildStructuralTree(loop));
  EXPECT_THAT(tree_.get(), Sequence(Repeat(Sequence(Base(loop), Base(test))),
                                    Base(end)));
}

TEST_F(ControlFlowAnalysisTest, RepeatFlippedStructure) {
  BasicCodeBlock* loop = subgraph_.AddBasicCodeBlock("loop");
  BasicCodeBlock* test = subgraph_.AddBasicCodeBlock("test");
  BasicCodeBlock* end = subgraph_.AddBasicCodeBlock("end");

  Connect(loop, test);
  MakeIf(test, end, loop);

  ASSERT_TRUE(BuildStructuralTree(loop));
  EXPECT_THAT(tree_.get(), Sequence(Repeat(Sequence(Base(loop), Base(test))),
                                    Base(end)));
}

TEST_F(ControlFlowAnalysisTest, RepeatSeqStructure) {
  BasicCodeBlock* loop = subgraph_.AddBasicCodeBlock("loop");
  BasicCodeBlock* body = subgraph_.AddBasicCodeBlock("body");
  BasicCodeBlock* test = subgraph_.AddBasicCodeBlock("test");
  BasicCodeBlock* end = subgraph_.AddBasicCodeBlock("end");

  Connect(loop, body);
  Connect(body, test);
  MakeIf(test, loop, end);

  ASSERT_TRUE(BuildStructuralTree(loop));
  EXPECT_THAT(tree_.get(),
              Sequence(Repeat(Sequence(Base(loop),
                              Sequence(Base(body), Base(test)))),
                       Base(end)));
}

TEST_F(ControlFlowAnalysisTest, RepeatIfThenStructure) {
  BasicCodeBlock* loop = subgraph_.AddBasicCodeBlock("loop");
  BasicCodeBlock* then = subgraph_.AddBasicCodeBlock("then");
  BasicCodeBlock* test = subgraph_.AddBasicCodeBlock("test");
  BasicCodeBlock* end = subgraph_.AddBasicCodeBlock("end");

  MakeIf(loop, test, then);
  Connect(then, test);
  MakeIf(test, loop, end);

  ASSERT_TRUE(BuildStructuralTree(loop));
  EXPECT_THAT(tree_.get(),
              Sequence(Repeat(Sequence(IfThen(Base(loop), Base(then)),
                                       Base(test))),
                       Base(end)));
}

TEST_F(ControlFlowAnalysisTest, WhileStructure) {
  BasicCodeBlock* loop = subgraph_.AddBasicCodeBlock("loop");
  BasicCodeBlock* body = subgraph_.AddBasicCodeBlock("body");
  BasicCodeBlock* end = subgraph_.AddBasicCodeBlock("end");

  MakeIf(loop, body, end);
  Connect(body, loop);

  ASSERT_TRUE(BuildStructuralTree(loop));
  EXPECT_THAT(tree_.get(), Sequence(While(Base(loop), Base(body)),
                                    Base(end)));
}

TEST_F(ControlFlowAnalysisTest, WhileFlippedStructure) {
  BasicCodeBlock* loop = subgraph_.AddBasicCodeBlock("loop");
  BasicCodeBlock* body = subgraph_.AddBasicCodeBlock("body");
  BasicCodeBlock* end = subgraph_.AddBasicCodeBlock("end");

  MakeIf(loop, end, body);
  Connect(body, loop);

  ASSERT_TRUE(BuildStructuralTree(loop));
  EXPECT_THAT(tree_.get(), Sequence(While(Base(loop), Base(body)),
                                    Base(end)));
}

TEST_F(ControlFlowAnalysisTest, LoopStructure) {
  BasicCodeBlock* loop = subgraph_.AddBasicCodeBlock("loop");

  Connect(loop, loop);

  ASSERT_TRUE(BuildStructuralTree(loop));
  EXPECT_THAT(tree_.get(), Loop(Base(loop)));
}

TEST_F(ControlFlowAnalysisTest, ComplexLoopStructure) {
  BasicCodeBlock* loop = subgraph_.AddBasicCodeBlock("loop");
  BasicCodeBlock* then = subgraph_.AddBasicCodeBlock("then");
  BasicCodeBlock* end = subgraph_.AddBasicCodeBlock("end");

  MakeIf(loop, then, end);
  Connect(then, end);
  Connect(end, loop);

  ASSERT_TRUE(BuildStructuralTree(loop));
  EXPECT_THAT(tree_.get(), Loop(Sequence(IfThen(Base(loop), Base(then)),
                                         Base(end))));
}

TEST_F(ControlFlowAnalysisTest, IfInnerLoopStructure) {
  BasicCodeBlock* head = subgraph_.AddBasicCodeBlock("head");
  BasicCodeBlock* loop1 = subgraph_.AddBasicCodeBlock("loop1");
  BasicCodeBlock* loop2 = subgraph_.AddBasicCodeBlock("loop2");

  MakeIf(head, loop1, loop2);
  Connect(loop1, loop1);
  Connect(loop2, loop2);

  ASSERT_TRUE(BuildStructuralTree(head));
}

TEST_F(ControlFlowAnalysisTest, IrreductibleStructure) {
  BasicCodeBlock* head = subgraph_.AddBasicCodeBlock("head");
  BasicCodeBlock* body1 = subgraph_.AddBasicCodeBlock("body1");
  BasicCodeBlock* body2 = subgraph_.AddBasicCodeBlock("body2");
  BasicCodeBlock* end = subgraph_.AddBasicCodeBlock("end");

  MakeIf(head, body1, body2);
  Connect(body1, body2);
  Connect(body2, body1);

  // This control flow cannot be reduced.
  ASSERT_FALSE(BuildStructuralTree(head));
}

}  // namespace

}  // namespace analysis
}  // namespace block_graph
