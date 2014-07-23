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

#include "syzygy/agent/asan/asan_heap_checker.h"

#include "base/rand_util.h"
#include "gtest/gtest.h"
#include "syzygy/agent/asan/asan_heap.h"
#include "syzygy/agent/asan/asan_logger.h"
#include "syzygy/agent/asan/asan_runtime.h"
#include "syzygy/agent/asan/unittest_util.h"

namespace agent {
namespace asan {

namespace {

class HeapCheckerTest : public testing::Test {
 public:
  HeapCheckerTest() {
  }

  virtual void SetUp() OVERRIDE {
    runtime_.SetUp(L"");
    ASSERT_TRUE(proxy_.Create(0, 0, 0));
    runtime_.AddHeap(&proxy_);
  }

  virtual void TearDown() OVERRIDE {
    ASSERT_TRUE(proxy_.Destroy());
    runtime_.TearDown();
  }

 protected:
  AsanLogger logger_;
  HeapProxy proxy_;
  AsanRuntime runtime_;
};

}  // namespace

TEST_F(HeapCheckerTest, IsHeapCorruptInvalidChecksum) {
  const size_t kAllocSize = 100;
  size_t real_alloc_size = HeapProxy::GetAllocSize(kAllocSize, kShadowRatio);

  // Ensures that the block will fit in the quarantine.
  proxy_.SetQuarantineMaxSize(real_alloc_size);
  proxy_.SetQuarantineMaxBlockSize(real_alloc_size);

  LPVOID block = proxy_.Alloc(0, kAllocSize);
  ASSERT_TRUE(block != NULL);
  base::RandBytes(block, kAllocSize);

  HeapChecker heap_checker(&runtime_);
  HeapChecker::CorruptRangesVector corrupt_ranges;
  EXPECT_FALSE(heap_checker.IsHeapCorrupt(&corrupt_ranges));

  // Free the block and corrupt its data.
  ASSERT_TRUE(proxy_.Free(0, block));
  BlockHeader* header = BlockGetHeaderFromBody(block);
  size_t header_checksum = header->checksum;

  // Corrupt the data in such a way that we can guarantee no hash collision.
  const size_t kMaxIterations = 10;
  size_t iteration = 0;
  uint8 original_value = reinterpret_cast<uint8*>(block)[0];
  BlockInfo block_info = {};
  EXPECT_TRUE(BlockInfoFromMemory(header, &block_info));
  do {
    reinterpret_cast<uint8*>(block)[0]++;
    BlockSetChecksum(block_info);
  } while (header->checksum == header_checksum && iteration++ < kMaxIterations);

  // Restore the checksum to make sure that the corruption gets detected.
  header->checksum = header_checksum;

  EXPECT_TRUE(heap_checker.IsHeapCorrupt(&corrupt_ranges));
  ASSERT_EQ(1, corrupt_ranges.size());
  AsanCorruptBlockRange* range_info = *corrupt_ranges.begin();

  EXPECT_EQ(1, range_info->block_count);
  ShadowWalker shadow_walker(
      false,
      reinterpret_cast<const uint8*>(range_info->address),
      reinterpret_cast<const uint8*>(range_info->address) + range_info->length);
  EXPECT_TRUE(shadow_walker.Next(&block_info));
  EXPECT_EQ(header, block_info.header);
  EXPECT_FALSE(shadow_walker.Next(&block_info));

  header->checksum = header_checksum;
  reinterpret_cast<uint8*>(block)[0] = original_value;
  EXPECT_FALSE(heap_checker.IsHeapCorrupt(&corrupt_ranges));
}

TEST_F(HeapCheckerTest, IsHeapCorruptInvalidMagicNumber) {
  const size_t kAllocSize = 100;

  LPVOID block = proxy_.Alloc(0, kAllocSize);
  base::RandBytes(block, kAllocSize);

  HeapChecker heap_checker(&runtime_);
  HeapChecker::CorruptRangesVector corrupt_ranges;
  EXPECT_FALSE(heap_checker.IsHeapCorrupt(&corrupt_ranges));

  // Corrupt the header of the block and ensure that the heap corruption gets
  // detected.
  BlockHeader* header = BlockGetHeaderFromBody(block);
  header->magic = ~header->magic;
  EXPECT_TRUE(heap_checker.IsHeapCorrupt(&corrupt_ranges));
  ASSERT_EQ(1, corrupt_ranges.size());
  AsanCorruptBlockRange* range_info = *corrupt_ranges.begin();

  EXPECT_EQ(1, range_info->block_count);
  ShadowWalker shadow_walker(
      false,
      reinterpret_cast<const uint8*>(range_info->address),
      reinterpret_cast<const uint8*>(range_info->address) + range_info->length);
  BlockInfo block_info = {};
  EXPECT_TRUE(shadow_walker.Next(&block_info));
  EXPECT_EQ(header, block_info.header);
  EXPECT_FALSE(shadow_walker.Next(&block_info));

  header->magic = ~header->magic;
  EXPECT_FALSE(heap_checker.IsHeapCorrupt(&corrupt_ranges));

  ASSERT_TRUE(proxy_.Free(0, block));
}

TEST_F(HeapCheckerTest, IsHeapCorrupt) {
  const size_t kAllocSize = 100;

  // This test assume that the blocks will be allocated back to back into the
  // memory slabs owned by |proxy_|. As there's only a few of them and they all
  // have the same size this is a safe assumption (they'll come from the same
  // bucket), but this might become invalid if the number of blocks augment. The
  // upper bound of this value seems to be 1648 for the test to pass both in
  // release and debug.
  const size_t kNumberOfBlocks = 4;
  size_t real_alloc_size = HeapProxy::GetAllocSize(kAllocSize,
      kShadowRatio);

  // Ensures that the blocks will fit in the quarantine.
  proxy_.SetQuarantineMaxSize(real_alloc_size * kNumberOfBlocks);
  proxy_.SetQuarantineMaxBlockSize(real_alloc_size * kNumberOfBlocks);

  LPVOID blocks[kNumberOfBlocks];
  BlockHeader* block_headers[kNumberOfBlocks];
  for (size_t i = 0; i < kNumberOfBlocks; ++i) {
    blocks[i] = proxy_.Alloc(0, kAllocSize);
    ASSERT_TRUE(blocks[i] != NULL);
    block_headers[i] = BlockGetHeaderFromBody(blocks[i]);
    base::RandBytes(blocks[i], kAllocSize);
  }

  HeapChecker heap_checker(&runtime_);
  HeapChecker::CorruptRangesVector corrupt_ranges;
  EXPECT_FALSE(heap_checker.IsHeapCorrupt(&corrupt_ranges));

  // Corrupt the header of the first two blocks and of the last one.
  block_headers[0]->magic++;
  block_headers[1]->magic++;
  block_headers[kNumberOfBlocks - 1]->magic++;

  EXPECT_TRUE(heap_checker.IsHeapCorrupt(&corrupt_ranges));

  // We expect the heap to contain 2 ranges of corrupt blocks, the first one
  // containing the 2 first blocks and the second one containing the last block.

  EXPECT_EQ(2, corrupt_ranges.size());

  BlockInfo block_info = {};
  ShadowWalker shadow_walker_1(
      false,
      reinterpret_cast<const uint8*>(corrupt_ranges[0]->address),
      reinterpret_cast<const uint8*>(corrupt_ranges[0]->address) +
          corrupt_ranges[0]->length);
  EXPECT_TRUE(shadow_walker_1.Next(&block_info));
  EXPECT_EQ(reinterpret_cast<const BlockHeader*>(block_info.header),
            block_headers[0]);
  EXPECT_TRUE(shadow_walker_1.Next(&block_info));
  EXPECT_EQ(reinterpret_cast<const BlockHeader*>(block_info.header),
            block_headers[1]);
  EXPECT_FALSE(shadow_walker_1.Next(&block_info));

  ShadowWalker shadow_walker_2(
      false,
      reinterpret_cast<const uint8*>(corrupt_ranges[1]->address),
      reinterpret_cast<const uint8*>(corrupt_ranges[1]->address) +
          corrupt_ranges[1]->length);
  EXPECT_TRUE(shadow_walker_2.Next(&block_info));
  EXPECT_EQ(reinterpret_cast<const BlockHeader*>(block_info.header),
            block_headers[kNumberOfBlocks - 1]);
  EXPECT_FALSE(shadow_walker_2.Next(&block_info));

  // Restore the checksum of the blocks.
  block_headers[0]->magic--;
  block_headers[1]->magic--;
  block_headers[kNumberOfBlocks - 1]->magic--;

  for (size_t i = 0; i < kNumberOfBlocks; ++i)
    ASSERT_TRUE(proxy_.Free(0, blocks[i]));
}

}  // namespace asan
}  // namespace agent
