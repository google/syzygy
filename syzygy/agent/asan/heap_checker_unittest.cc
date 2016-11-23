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

#include "syzygy/agent/asan/heap_checker.h"

#include "base/rand_util.h"
#include "gtest/gtest.h"
#include "syzygy/agent/asan/logger.h"
#include "syzygy/agent/asan/page_protection_helpers.h"
#include "syzygy/agent/asan/runtime.h"
#include "syzygy/agent/asan/unittest_util.h"

namespace agent {
namespace asan {

namespace {

typedef public testing::TestWithAsanRuntime HeapCheckerTest;

using testing::FakeAsanBlock;

}  // namespace

TEST_F(HeapCheckerTest, HeapCheckerHandlesPageProtections) {
  // Make a large allocation bigger than a couple pages. This will ensure
  // that its big enough to have page protections. The HeapChecker will have
  // to unset these in order to do its work successfully. Otherwise it will
  // cause an access violation.
  FakeAsanBlock fake_large_block(
      runtime_->shadow(), kShadowRatioLog, runtime_->stack_cache());
  fake_large_block.InitializeBlock(2 * static_cast<uint32_t>(GetPageSize()));
  base::RandBytes(fake_large_block.block_info.body, 2 * GetPageSize());
  fake_large_block.MarkBlockAsQuarantined();
  BlockProtectAll(fake_large_block.block_info, runtime_->shadow());

  HeapChecker heap_checker(runtime_->shadow());
  HeapChecker::CorruptRangesVector corrupt_ranges;
  EXPECT_FALSE(heap_checker.IsHeapCorrupt(&corrupt_ranges));

  BlockProtectNone(fake_large_block.block_info, runtime_->shadow());
}

TEST_F(HeapCheckerTest, IsHeapCorruptInvalidChecksum) {
  const size_t kAllocSize = 100;
  FakeAsanBlock fake_block(
      runtime_->shadow(), kShadowRatioLog, runtime_->stack_cache());

  fake_block.InitializeBlock(kAllocSize);
  base::RandBytes(fake_block.block_info.body, kAllocSize);

  HeapChecker heap_checker(runtime_->shadow());
  HeapChecker::CorruptRangesVector corrupt_ranges;
  EXPECT_FALSE(heap_checker.IsHeapCorrupt(&corrupt_ranges));

  // Free the block and corrupt its data.
  ASSERT_TRUE(fake_block.MarkBlockAsQuarantined());
  size_t header_checksum = fake_block.block_info.header->checksum;

  // Corrupt the data in such a way that we can guarantee no hash collision.
  const size_t kMaxIterations = 10;
  size_t iteration = 0;
  uint8_t original_value = fake_block.block_info.RawBody(0);
  do {
    fake_block.block_info.RawBody(0)++;
    BlockSetChecksum(fake_block.block_info);
  } while (fake_block.block_info.header->checksum == header_checksum &&
           iteration++ < kMaxIterations);

  // Restore the checksum to make sure that the corruption gets detected.
  fake_block.block_info.header->checksum = header_checksum;

  EXPECT_TRUE(heap_checker.IsHeapCorrupt(&corrupt_ranges));
  ASSERT_EQ(1, corrupt_ranges.size());
  AsanCorruptBlockRange range_info = *corrupt_ranges.begin();

  EXPECT_EQ(1, range_info.block_count);
  ShadowWalker shadow_walker(
      runtime_->shadow(), reinterpret_cast<const uint8_t*>(range_info.address),
      reinterpret_cast<const uint8_t*>(range_info.address) + range_info.length);
  BlockInfo block_info = {};
  EXPECT_TRUE(shadow_walker.Next(&block_info));
  EXPECT_EQ(fake_block.block_info.header, block_info.header);
  EXPECT_FALSE(shadow_walker.Next(&block_info));

  fake_block.block_info.header->checksum = header_checksum;
  fake_block.block_info.RawBody(0) = original_value;
  EXPECT_FALSE(heap_checker.IsHeapCorrupt(&corrupt_ranges));
}

TEST_F(HeapCheckerTest, IsHeapCorruptInvalidMagicNumber) {
  const size_t kAllocSize = 100;
  FakeAsanBlock fake_block(
      runtime_->shadow(), kShadowRatioLog, runtime_->stack_cache());

  fake_block.InitializeBlock(kAllocSize);
  base::RandBytes(fake_block.block_info.body, kAllocSize);

  HeapChecker heap_checker(runtime_->shadow());
  HeapChecker::CorruptRangesVector corrupt_ranges;
  EXPECT_FALSE(heap_checker.IsHeapCorrupt(&corrupt_ranges));

  // Corrupt the header of the block and ensure that the heap corruption gets
  // detected.
  fake_block.block_info.header->magic = ~fake_block.block_info.header->magic;
  EXPECT_TRUE(heap_checker.IsHeapCorrupt(&corrupt_ranges));
  ASSERT_EQ(1, corrupt_ranges.size());
  AsanCorruptBlockRange range_info = *corrupt_ranges.begin();

  EXPECT_EQ(1, range_info.block_count);
  ShadowWalker shadow_walker(
      runtime_->shadow(), reinterpret_cast<const uint8_t*>(range_info.address),
      reinterpret_cast<const uint8_t*>(range_info.address) + range_info.length);
  BlockInfo block_info = {};
  EXPECT_TRUE(shadow_walker.Next(&block_info));
  EXPECT_EQ(fake_block.block_info.header, block_info.header);
  EXPECT_FALSE(shadow_walker.Next(&block_info));

  fake_block.block_info.header->magic = ~fake_block.block_info.header->magic;
  EXPECT_FALSE(heap_checker.IsHeapCorrupt(&corrupt_ranges));
}

TEST_F(HeapCheckerTest, IsHeapCorrupt) {
  const size_t kAllocSize = 100;

  BlockLayout block_layout = {};
  EXPECT_TRUE(BlockPlanLayout(kShadowRatio, kShadowRatio, kAllocSize, 0, 0,
                              &block_layout));

  const size_t kNumberOfBlocks = 4;
  size_t total_alloc_size = block_layout.block_size * kNumberOfBlocks;
  uint8_t* global_alloc =
      reinterpret_cast<uint8_t*>(::malloc(total_alloc_size));

  uint8_t* blocks[kNumberOfBlocks];
  BlockHeader* block_headers[kNumberOfBlocks];

  for (size_t i = 0; i < kNumberOfBlocks; ++i) {
    blocks[i] = global_alloc + i * block_layout.block_size;
    BlockInfo block_info = {};
    BlockInitialize(block_layout, blocks[i], &block_info);
    runtime_->shadow()->PoisonAllocatedBlock(block_info);
    BlockSetChecksum(block_info);
    block_headers[i] = block_info.header;
    EXPECT_EQ(block_headers[i], reinterpret_cast<BlockHeader*>(blocks[i]));
  }

  HeapChecker heap_checker(runtime_->shadow());
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
      runtime_->shadow(),
      reinterpret_cast<const uint8_t*>(corrupt_ranges[0].address),
      reinterpret_cast<const uint8_t*>(corrupt_ranges[0].address) +
          corrupt_ranges[0].length);
  EXPECT_TRUE(shadow_walker_1.Next(&block_info));
  EXPECT_EQ(reinterpret_cast<const BlockHeader*>(block_info.header),
            block_headers[0]);
  EXPECT_TRUE(shadow_walker_1.Next(&block_info));
  EXPECT_EQ(reinterpret_cast<const BlockHeader*>(block_info.header),
            block_headers[1]);
  EXPECT_FALSE(shadow_walker_1.Next(&block_info));

  ShadowWalker shadow_walker_2(
      runtime_->shadow(),
      reinterpret_cast<const uint8_t*>(corrupt_ranges[1].address),
      reinterpret_cast<const uint8_t*>(corrupt_ranges[1].address) +
          corrupt_ranges[1].length);
  EXPECT_TRUE(shadow_walker_2.Next(&block_info));
  EXPECT_EQ(reinterpret_cast<const BlockHeader*>(block_info.header),
            block_headers[kNumberOfBlocks - 1]);
  EXPECT_FALSE(shadow_walker_2.Next(&block_info));

  // Restore the checksum of the blocks.
  block_headers[0]->magic--;
  block_headers[1]->magic--;
  block_headers[kNumberOfBlocks - 1]->magic--;

  runtime_->shadow()->Unpoison(global_alloc, total_alloc_size);
  ::free(global_alloc);
}

}  // namespace asan
}  // namespace agent
