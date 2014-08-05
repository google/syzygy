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

#include "syzygy/agent/asan/block_utils.h"

#include "gtest/gtest.h"
#include "syzygy/agent/asan/asan_heap.h"
#include "syzygy/agent/asan/asan_logger.h"
#include "syzygy/agent/asan/stack_capture_cache.h"
#include "syzygy/agent/asan/unittest_util.h"

namespace agent {
namespace asan {

namespace {

typedef testing::TestWithAsanHeap BlockUtilTest;

}  // namespace

TEST_F(BlockUtilTest, IsBlockCorruptInvalidMagicNumber) {
  const size_t kAllocSize = 100;
  BlockLayout layout = {};
  BlockPlanLayout(kShadowRatio, kShadowRatio, kAllocSize, 0, 0, &layout);
  proxy_.SetQuarantineMaxSize(layout.block_size);
  proxy_.SetQuarantineMaxBlockSize(layout.block_size);
  LPVOID mem = proxy_.Alloc(0, kAllocSize);
  ASSERT_TRUE(mem != NULL);
  BlockHeader* header = BlockGetHeaderFromBody(mem);
  ASSERT_NE(reinterpret_cast<BlockHeader*>(NULL), header);

  header->magic = ~kBlockHeaderMagic;
  EXPECT_TRUE(IsBlockCorrupt(reinterpret_cast<uint8*>(header), NULL));
  header->magic = kBlockHeaderMagic;
  EXPECT_FALSE(IsBlockCorrupt(reinterpret_cast<uint8*>(header), NULL));

  ASSERT_TRUE(proxy_.Free(0, mem));
}

TEST_F(BlockUtilTest, IsBlockCorruptInvalidChecksum) {
  const size_t kAllocSize = 100;
  static const size_t kChecksumRepeatCount = 10;
  BlockLayout layout = {};
  BlockPlanLayout(kShadowRatio, kShadowRatio, kAllocSize, 0, 0, &layout);

  // This can fail because of a checksum collision. However, we run it a
  // handful of times to keep the chances as small as possible.
  for (size_t i = 0; i < kChecksumRepeatCount; ++i) {
    proxy_.SetQuarantineMaxSize(0);
    proxy_.SetQuarantineMaxSize(layout.block_size);
    proxy_.SetQuarantineMaxBlockSize(layout.block_size);
    LPVOID mem = proxy_.Alloc(0, kAllocSize);
    ASSERT_TRUE(mem != NULL);
    ASSERT_TRUE(proxy_.Free(0, mem));

    BlockHeader* header = BlockGetHeaderFromBody(mem);
    ASSERT_NE(reinterpret_cast<BlockHeader*>(NULL), header);

    // Change some of the block content and verify that the block is now being
    // seen as corrupt.
    size_t original_checksum = header->checksum;
    int32 original_value = reinterpret_cast<int32*>(mem)[0];
    reinterpret_cast<int32*>(mem)[0] = rand();

    // Try again for all but the last attempt if this appears to have failed.
    if (!IsBlockCorrupt(reinterpret_cast<uint8*>(header), NULL) &&
        i + 1 < kChecksumRepeatCount) {
      continue;
    }

    ASSERT_TRUE(IsBlockCorrupt(reinterpret_cast<uint8*>(header), NULL));
    reinterpret_cast<int32*>(mem)[0] = original_value;
    ASSERT_FALSE(IsBlockCorrupt(reinterpret_cast<uint8*>(header), NULL));
    break;
  }
}

}  // namespace asan
}  // namespace agent
