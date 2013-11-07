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
#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace block_graph {
namespace analysis {

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

  void AddSuccessorBetween(Successor::Condition condition,
                           BasicCodeBlock* from,
                           BasicCodeBlock* to);

  void Connect(BasicCodeBlock* from,
               BasicCodeBlock* to);

  void MakeIf(BasicCodeBlock* root,
              Successor::Condition condition,
              BasicCodeBlock* true_stm,
              BasicCodeBlock* end_stm);

  BasicBlockSubGraph subgraph_;
  std::vector<const BasicCodeBlock*> order_;
};

void ControlFlowAnalysisTest::BuildReversePostOrder() {
  ControlFlowAnalysis::FlattenBasicBlocksInPostOrder(subgraph_.basic_blocks(),
                                                     &order_);
  ASSERT_EQ(subgraph_.basic_blocks().size(), order_.size());
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
    Successor::Condition condition,
    BasicCodeBlock* true_stm,
    BasicCodeBlock* false_stm) {
  DCHECK_NE(reinterpret_cast<BasicCodeBlock*>(NULL), root);
  DCHECK_NE(reinterpret_cast<BasicCodeBlock*>(NULL), true_stm);
  DCHECK_NE(reinterpret_cast<BasicCodeBlock*>(NULL), false_stm);

  AddSuccessorBetween(condition, root, true_stm);
  AddSuccessorBetween(Successor::InvertCondition(condition), root, false_stm);
}

TEST_F(ControlFlowAnalysisTest, SingleIfOneBranchOrdering) {
  BasicCodeBlock* if1 = subgraph_.AddBasicCodeBlock("if1");
  BasicCodeBlock* true1 = subgraph_.AddBasicCodeBlock("true1");
  BasicCodeBlock* end1 = subgraph_.AddBasicCodeBlock("end1");

  MakeIf(if1, Successor::kConditionAbove, true1, end1);
  Connect(true1, end1);

  ASSERT_NO_FATAL_FAILURE(BuildReversePostOrder());
  EXPECT_THAT(order_, testing::ElementsAre(end1, true1, if1));
}

TEST_F(ControlFlowAnalysisTest, SingleIfTwoBranchOrdering) {
  BasicCodeBlock* if1 = subgraph_.AddBasicCodeBlock("if1");
  BasicCodeBlock* true1 = subgraph_.AddBasicCodeBlock("true1");
  BasicCodeBlock* false1 = subgraph_.AddBasicCodeBlock("false1");
  BasicCodeBlock* end1 = subgraph_.AddBasicCodeBlock("end1");

  MakeIf(if1, Successor::kConditionAbove, true1, false1);
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

  MakeIf(if1, Successor::kConditionAbove, true1, if2);
  Connect(true1, if2);
  MakeIf(if2, Successor::kConditionAbove, true2, end);
  Connect(true2, end);

  ASSERT_NO_FATAL_FAILURE(BuildReversePostOrder());
  EXPECT_THAT(order_, testing::ElementsAre(end, true2, if2, true1, if1));
}

TEST_F(ControlFlowAnalysisTest, SimpleLoopOrdering) {
  BasicCodeBlock* if1 = subgraph_.AddBasicCodeBlock("if1");
  BasicCodeBlock* body1 = subgraph_.AddBasicCodeBlock("body1");
  BasicCodeBlock* end1 = subgraph_.AddBasicCodeBlock("end1");

  MakeIf(if1, Successor::kConditionAbove, body1, end1);
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

  MakeIf(if0, Successor::kConditionAbove, if1, if2);

  MakeIf(if1, Successor::kConditionAbove, body1, end);
  Connect(body1, if1);

  MakeIf(if2, Successor::kConditionAbove, body2, body3);
  Connect(body2, end);
  Connect(body3, if2);

  ASSERT_NO_FATAL_FAILURE(BuildReversePostOrder());
  EXPECT_THAT(order_,
              testing::ElementsAre(body1, end, if1, body2, body3, if2, if0));
}

}  // namespace

}  // namespace analysis
}  // namespace block_graph
