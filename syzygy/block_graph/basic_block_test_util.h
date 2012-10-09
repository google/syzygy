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
// basic_block_assembly_func.asm.
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

  // The number and type of basic blocks.
  // TODO(rogerm): The padding block will go away once the decomposer switches
  //     to doing a straight disassembly of the entire code region.
  static const size_t kNumCodeBasicBlocks = 7;
  static const size_t kNumDataBasicBlocks = 2;
  static const size_t kNumPaddingBasicBlocks = 1;
  static const size_t kNumBasicBlocks =
      kNumCodeBasicBlocks + kNumDataBasicBlocks + kNumPaddingBasicBlocks;

  BasicBlockTest();

  // Initializes block_graph, assembly_func, func1, func2 and data. Meant to be
  // wrapped in ASSERT_NO_FATAL_FAILURE.
  void InitBlockGraph();

  // Initializes subgraph, bbs and bds. Meant to be wrapped in
  // ASSERT_NO_FATAL_FAILURE.
  // @pre InitBlockGraph must have been called successfully.
  void InitBasicBlockSubGraph();

  // Initialized by InitBlockGraph.
  // @{
  // Start address of the assembly function.
  RelativeAddress start_addr_;

  BlockGraph block_graph_;
  Block* assembly_func_;
  Block* func1_;
  Block* func2_;
  Block* data_;
  // @}

  // Initialized by InitBasicBlockSubGraph.
  // @{
  BasicBlockSubGraph subgraph_;
  std::vector<BasicBlock*> bbs_;
  std::vector<BlockDescription*> bds_;
  // @}
};

}  // namespace testing

#endif  // SYZYGY_BLOCK_GRAPH_BASIC_BLOCK_TEST_UTIL_H_
