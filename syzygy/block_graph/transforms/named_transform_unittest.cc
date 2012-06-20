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
// Unittests for transform name implementation class.

#include "syzygy/block_graph/transforms/named_transform.h"

#include "gtest/gtest.h"

namespace block_graph {
namespace transforms {

namespace {

class MockNamedTransform : public NamedTransformImpl<MockNamedTransform> {
 public:
  bool TransformBlockGraph(BlockGraph* /*block_graph*/,
                           BlockGraph::Block* /*header_block*/) {
    return true;
  }

  static const char kTransformName[];
};

}  // namespace

const char MockNamedTransform::kTransformName[] =
    "MockNamedTransform";

TEST(NamedTransformTest, NameWork) {
  MockNamedTransform transform;
  EXPECT_EQ(std::string("MockNamedTransform"), transform.name());
}

}  // namespace transforms
}  // namespace block_graph
