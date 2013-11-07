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
#ifndef SYZYGY_BLOCK_GRAPH_ANALYSIS_CONTROL_FLOW_ANALYSIS_H_
#define SYZYGY_BLOCK_GRAPH_ANALYSIS_CONTROL_FLOW_ANALYSIS_H_

#include <map>

#include "base/basictypes.h"
#include "syzygy/block_graph/basic_block.h"
#include "syzygy/block_graph/basic_block_subgraph.h"

namespace block_graph {
namespace analysis {

class ControlFlowAnalysis {
 public:
  typedef block_graph::BasicBlockSubGraph BasicBlockSubGraph;
  typedef BasicBlockSubGraph::BBCollection BBCollection;

  // Constructor.
  ControlFlowAnalysis();

  // @param subgraph Subgraph to apply the analysis.
  void Analyze(const BasicBlockSubGraph* subgraph);

  static void FlattenBasicBlocksInPostOrder(
    const BBCollection& basic_blocks,
    std::vector<const BasicCodeBlock*>* order);

 private:
  DISALLOW_COPY_AND_ASSIGN(ControlFlowAnalysis);
};

}  // namespace analysis
}  // namespace block_graph

#endif  // SYZYGY_BLOCK_GRAPH_ANALYSIS_CONTROL_FLOW_ANALYSIS_H_
