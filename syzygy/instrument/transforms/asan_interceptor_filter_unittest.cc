// Copyright 2014 Google Inc. All Rights Reserved.
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
// Unittests for the Asan interceptor filter class.

#include "syzygy/instrument/transforms/asan_interceptor_filter.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/block_graph/block_graph.h"

namespace instrument {
namespace transforms {

namespace {

using block_graph::BlockGraph;

// A derived class to expose protected members for unit-testing.
class TestAsanInterceptorFilter : public AsanInterceptorFilter {
 public:
  using AsanInterceptorFilter::AddBlockToHashMap;
  using AsanInterceptorFilter::function_hash_map_;
};

}  // namespace

TEST(InterceptorFilterTest, IsFiltered) {
  BlockGraph block_graph;
  const size_t kBlockSize = 0x20;

  BlockGraph::Block* block = block_graph.AddBlock(BlockGraph::CODE_BLOCK,
                                                  kBlockSize,
                                                  "test block");
  EXPECT_NE(reinterpret_cast<uint8*>(NULL), block->ResizeData(kBlockSize));
  ::memset(block->GetMutableData(), 0xAB, kBlockSize);

  TestAsanInterceptorFilter filter;
  EXPECT_TRUE(filter.function_hash_map_.empty());
  filter.InitializeContentHashes(kAsanIntercepts, true);
  // Only check that the CRT functions hashes have been loaded into the map, the
  // integration tests takes care of ensuring that those functions are really
  // intercepted.
  EXPECT_FALSE(filter.function_hash_map_.empty());

  EXPECT_FALSE(filter.ShouldIntercept(block));
  filter.AddBlockToHashMap(block);
  EXPECT_TRUE(filter.ShouldIntercept(block));
  block->GetMutableData()[0] = ~block->data()[0];
  EXPECT_FALSE(filter.ShouldIntercept(block));
}

}  // namespace transforms
}  // namespace instrument
