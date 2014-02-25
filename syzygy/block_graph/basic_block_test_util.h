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

#ifndef SYZYGY_BLOCK_GRAPH_BASIC_BLOCK_TEST_UTIL_H_
#define SYZYGY_BLOCK_GRAPH_BASIC_BLOCK_TEST_UTIL_H_

#include "gtest/gtest.h"
#include "syzygy/block_graph/basic_block_decomposer.h"
#include "syzygy/block_graph/basic_block_subgraph.h"
#include "syzygy/block_graph/unittest_util.h"

extern "C" {

// Functions and labels exposed from our .asm test stub.
extern int assembly_func();
extern int unreachable_label();
extern int interrupt_label();
extern int assembly_func_end();

extern int case_0();
extern int case_1();
extern int case_default();
extern int jump_table();
extern int case_table();

// Functions invoked or referred by the .asm test stub. These are defined in
// basic_block_test_util.cc.
extern int func1();
extern int func2();

}  // extern "C"

namespace testing {

// A utility class for generating test data built around the function in
// basic_block_assembly_func.asm. When assembly_func_ is decomposed as a basic
// block subgraph the layout is as follows:
//
// BB0: offset 0, code, assembly_func, 4 instructions, 0 successors
// BB1: offset 23, code/padding (unreachable code)
// BB2: offset 24, code, case_0, 2 instructions, 1 successor
// BB3: offset 31, code, sub eax to jnz, 1 instruction, 2 successors
// BB4: offset 36, code, ret, 1 instruction, 0 successors
// BB5: offset 37, code, case_1, 1 instruction, 1 successor
// BB6: offset 42, code, case_default, 2 instructions, 0 successors
// BB7: offset 49, code/padding, interrupt_label, 3 instruction, 0 successors
// BB8: offset 50, data, jump_table, 12 bytes
// BB9: offset 62, data, case_table, 256 bytes
class BasicBlockTest : public ::testing::Test {
 public:
  typedef core::RelativeAddress RelativeAddress;
  typedef block_graph::BlockGraph BlockGraph;
  typedef block_graph::BasicBlockDecomposer BasicBlockDecomposer;
  typedef block_graph::BasicBlockSubGraph BasicBlockSubGraph;
  typedef BasicBlockSubGraph::BasicBlock BasicBlock;
  typedef BasicBlockSubGraph::BlockDescription BlockDescription;
  typedef BlockGraph::Block Block;
  typedef BlockGraph::Reference Reference;
  typedef BlockGraph::Section Section;

  // The number and type of basic blocks.
  static const size_t kNumCodeBasicBlocks = 8;
  static const size_t kNumDataBasicBlocks = 2;
  static const size_t kNumEndBasicBlocks = 1;
  static const size_t kNumCodePaddingBasicBlocks = 2;
  static const size_t kNumDataPaddingBasicBlocks = 0;
  static const size_t kNumBasicBlocks =
      kNumCodeBasicBlocks + kNumDataBasicBlocks + kNumEndBasicBlocks;

  BasicBlockTest();

  // Initializes block_graph, assembly_func, func1, func2 and data. Meant to be
  // wrapped in ASSERT_NO_FATAL_FAILURE.
  void InitBlockGraph();

  // Initializes subgraph, bbs and bds. Meant to be wrapped in
  // ASSERT_NO_FATAL_FAILURE.
  // @pre InitBlockGraph must have been called successfully.
  void InitBasicBlockSubGraph();

  // Initializes block_graph_, text_section_, func1_, and func2_. Leaves
  // data_section_, assembly_func_ and data_ NULL. func2_ contains a function
  // with a debug-end label past the end of the block, and internally it calls
  // func1_.
  void InitBasicBlockSubGraphWithLabelPastEnd();

  // Initialized by InitBlockGraph.
  // @{
  // Start address of the assembly function.
  RelativeAddress start_addr_;

  testing::DummyTransformPolicy policy_;
  BlockGraph block_graph_;
  Section* text_section_;
  Section* data_section_;
  Block* assembly_func_;
  Block* func1_;
  Block* func2_;
  Block* data_;
  // @}

  // Initialized by InitBasicBlockSubGraph and
  // InitBasicBlockSubGraphWithLabelPastEnd.
  // @{
  BasicBlockSubGraph subgraph_;
  std::vector<BasicBlock*> bbs_;
  std::vector<BlockDescription*> bds_;
  // @}
};

}  // namespace testing

#endif  // SYZYGY_BLOCK_GRAPH_BASIC_BLOCK_TEST_UTIL_H_
