// Copyright 2011 Google Inc.
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

namespace testing {

// Compares two Blocks (from different BlockGraphs) to each other. Intended for
// testing BlockGraph serialization.
bool BlocksEqual(const block_graph::BlockGraph::Block& b1,
                 const block_graph::BlockGraph::Block& b2);

// Compares two BlockGraphs to each other. Intended for testing BlockGraph
// serialization.
bool BlockGraphsEqual(const block_graph::BlockGraph& b1,
                      const block_graph::BlockGraph& b2);

}  // namespace testing

#endif  // SYZYGY_BLOCK_GRAPH_UNITTEST_UTIL_H_
