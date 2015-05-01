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
// Unittests for orderer name implementation class.

#include "syzygy/block_graph/orderers/named_orderer.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace block_graph {
namespace orderers {

namespace {

class MockNamedOrderer : public NamedOrdererImpl<MockNamedOrderer> {
 public:
  bool OrderBlockGraph(OrderedBlockGraph* /*ordered_block_graph*/,
                       BlockGraph::Block* /*header_block*/) override {
    return true;
  }

  static const char kOrdererName[];
};

}  // namespace

const char MockNamedOrderer::kOrdererName[] =
    "MockNamedOrderer";

TEST(NamedOrdererTest, NameWorks) {
  testing::StrictMock<MockNamedOrderer> orderer;
  EXPECT_EQ(std::string("MockNamedOrderer"), orderer.name());
}

}  // namespace orderers
}  // namespace block_graph
