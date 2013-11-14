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
//
// Declares utilities for building unittests dealing with BlockGraphs.

#ifndef SYZYGY_BLOCK_GRAPH_UNITTEST_UTIL_H_
#define SYZYGY_BLOCK_GRAPH_UNITTEST_UTIL_H_

#include "syzygy/block_graph/block_graph.h"
#include "syzygy/block_graph/block_graph_serializer.h"
#include "syzygy/block_graph/transform_policy.h"

namespace testing {

// TODO(chrisha): Once we transition fully to BlockGraphSerializer, remove
//     the redundant comparison functions.

// Compares two Blocks (from different BlockGraphs) to each other. Intended for
// testing BlockGraph serialization.
bool BlocksEqual(const block_graph::BlockGraph::Block& b1,
                 const block_graph::BlockGraph::Block& b2,
                 const block_graph::BlockGraphSerializer& bgs);

// Compares two BlockGraphs to each other. Intended for testing BlockGraph
// serialization.
bool BlockGraphsEqual(
    const block_graph::BlockGraph& b1,
    const block_graph::BlockGraph& b2,
    const block_graph::BlockGraphSerializer& bgs);

// Generate a block-graph to use in the tests.
bool GenerateTestBlockGraph(block_graph::BlockGraph* image);

// A dummy transform policy object for unittesting.
class DummyTransformPolicy : public block_graph::TransformPolicyInterface {
 public:
  DummyTransformPolicy() { }
  virtual ~DummyTransformPolicy() { }

  // @name TransformPolicyInterface implementation
  // @{
  virtual bool BlockIsSafeToBasicBlockDecompose(
      const BlockGraph::Block* block) const OVERRIDE;
  virtual bool ReferenceIsSafeToRedirect(
      const BlockGraph::Block* referrer,
      const BlockGraph::Reference& reference) const OVERRIDE;
  // @}

 private:
  DISALLOW_COPY_AND_ASSIGN(DummyTransformPolicy);
};

}  // namespace testing

#endif  // SYZYGY_BLOCK_GRAPH_UNITTEST_UTIL_H_
