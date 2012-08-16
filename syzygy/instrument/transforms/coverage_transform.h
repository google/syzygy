// Copyright 2012 Google Inc.
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
// Declares a block-graph transform to be used by the code coverage
// instrumenter. This transform does 4 things:
//
// (1) Injects an import for the run-time code coverage library.
// (2) Grabs an entry hook and wires it up the run-time library.
// (3) Adds a read/write data section containing code coverage information.
// (4) Instruments each basic block to gather basic block visit information.

#ifndef SYZYGY_INSTRUMENT_TRANSFORMS_COVERAGE_TRANSFORM_H_
#define SYZYGY_INSTRUMENT_TRANSFORMS_COVERAGE_TRANSFORM_H_

#include <vector>

#include "syzygy/block_graph/transforms/iterative_transform.h"

namespace instrument {
namespace transforms {

class CoverageInstrumentationTransform
    : public block_graph::transforms::IterativeTransformImpl<
          CoverageInstrumentationTransform>,
      public block_graph::transforms::NamedBasicBlockSubGraphTransformImpl<
          CoverageInstrumentationTransform> {
 public:
  typedef block_graph::BlockGraph BlockGraph;
  typedef block_graph::BasicBlockSubGraph BasicBlockSubGraph;
  typedef std::vector<core::RelativeAddress> RelativeAddressVector;

  // Constructor.
  CoverageInstrumentationTransform();

  // The name of this transform.
  static const char kTransformName[];

  // BasicBlockSubGraphTransform implementation.
  virtual bool TransformBasicBlockSubGraph(
      BlockGraph* block_graph,
      BasicBlockSubGraph* basic_block_subgraph) OVERRIDE;

  // @returns the RVAs in the original image of the instrumented basic blocks.
  //    They are in the order in which they were encountered during
  //    instrumentation, such that the index of the BB in the vector serves
  //    as its unique ID.
  const RelativeAddressVector& bb_addresses() const { return bb_addresses_; }

 protected:
  friend block_graph::transforms::IterativeTransformImpl<
      CoverageInstrumentationTransform>;

  // @name IterativeTransformImpl implementation.
  // @{
  // Called prior to iterating over the blocks. This creates the coverage
  // data block, populating coverage_data_block_ and
  // basic_block_seen_array_ref_.
  bool PreBlockGraphIteration(BlockGraph* block_graph,
                              BlockGraph::Block* header_block);
  // Called after iterating over the blocks. Increments basic_block_count_ as
  // code blocks are processed.
  bool OnBlock(BlockGraph* block_graph,
               BlockGraph::Block* block);
  // Called after iterating over the blocks. Sets the basic-block count member
  // of coverage_data_block_.
  bool PostBlockGraphIteration(BlockGraph* block_graph,
                               BlockGraph::Block* header_block);
  // @}

  // Points to the block containing coverage data.
  BlockGraph::Block* coverage_data_block_;
  // Stores the RVAs in the original image for each instrumented basic block.
  RelativeAddressVector bb_addresses_;

  DISALLOW_COPY_AND_ASSIGN(CoverageInstrumentationTransform);
};

}  // namespace transforms
}  // namespace instrument

#endif  // SYZYGY_INSTRUMENT_TRANSFORMS_COVERAGE_TRANSFORM_H_
