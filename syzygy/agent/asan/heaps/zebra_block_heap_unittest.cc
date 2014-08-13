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

#include "syzygy/agent/asan/heaps/zebra_block_heap.h"

#include <algorithm>
#include <set>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/agent/asan/unittest_util.h"
#include "syzygy/common/align.h"


namespace agent {
namespace asan {
namespace heaps {

namespace {

using common::IsAligned;
using common::AlignDown;
using common::AlignUp;

using ::testing::_;
using ::testing::Gt;
using ::testing::NotNull;
using ::testing::AtLeast;

testing::NullMemoryNotifier null_notifier;

class TestZebraBlockHeap : public ZebraBlockHeap {
 public:
  using ZebraBlockHeap::max_number_of_allocations_;
  using ZebraBlockHeap::QuarantineInvariantIsSatisfied;
  using ZebraBlockHeap::heap_address_;

  static const size_t kInitialHeapSize = 8 * (1 << 20);

  // Creates a test heap with 8 MB initial (and maximum) memory using the
  // default memory notifier.
  TestZebraBlockHeap() : ZebraBlockHeap(kInitialHeapSize,
                                        &null_notifier) { }

  // Creates a test heap with 8 MB initial (and maximum) memory using a custom
  // memory notifier.
  explicit TestZebraBlockHeap(MemoryNotifierInterface* memory_notifier)
      : ZebraBlockHeap(kInitialHeapSize, memory_notifier) { }

  // Allows to know if the heap can handle more allocations.
  // @returns true if the heap is full (no more allocations allowed),
  // false otherwise.
  bool IsHeapFull() {
    // No free slabs.
    return free_slabs_->empty();
  }
};

}  // namespace

TEST(ZebraBlockHeapTest, FeaturesAreValid) {
  TestZebraBlockHeap h;
  EXPECT_EQ(HeapInterface::kHeapSupportsIsAllocated |
                HeapInterface::kHeapReportsReservations,
            h.GetHeapFeatures());
}

TEST(ZebraBlockHeapTest, AllocateEmptyBlock) {
  TestZebraBlockHeap h;
  BlockLayout layout = {};
  BlockInfo block = {};

  // Allocate and free a zero-sized allocation. This should succeed
  // by definition.
  void* alloc = h.AllocateBlock(0, 0, 0, &layout);
  EXPECT_NE(reinterpret_cast<void*>(NULL), alloc);
  EXPECT_TRUE(IsAligned(alloc, kShadowRatio));
  BlockInitialize(layout, alloc, false, &block);
  EXPECT_TRUE(h.FreeBlock(block));
}

TEST(ZebraBlockHeapTest, EndToEnd) {
  TestZebraBlockHeap h;
  BlockLayout layout = {};
  BlockInfo block = {};

  // Make a bunch of different sized allocations.
  std::vector<BlockInfo> blocks;
  for (size_t i = 1; i < 100; i++) {
    void* alloc = h.AllocateBlock(i, 0, 0, &layout);
    EXPECT_NE(reinterpret_cast<void*>(NULL), alloc);
    EXPECT_TRUE(IsAligned(alloc, kShadowRatio));
    BlockInitialize(layout, alloc, false, &block);
    blocks.push_back(block);
  }

  // Now free them.
  for (size_t i = 0; i < blocks.size(); ++i)
    EXPECT_TRUE(h.FreeBlock(blocks[i]));
}

TEST(ZebraBlockHeapTest, BlocksHaveCorrectAlignment) {
  TestZebraBlockHeap h;
  BlockLayout layout = {};
  BlockInfo block = {};

  // Allocate blocks with different header, body and trailer sizes .
  for (size_t header_size = 0; header_size < 100; header_size += 3) {
    for (size_t trailer_size = 0; trailer_size < 100; trailer_size += 3) {
      for (size_t body_size = 0; body_size < 100; body_size += 3) {
        void* alloc = h.AllocateBlock(body_size, header_size,
                                      trailer_size, &layout);

        EXPECT_NE(reinterpret_cast<void*>(NULL), alloc);
        EXPECT_TRUE(IsAligned(alloc, kShadowRatio));

        BlockInitialize(layout, alloc, false, &block);

        // The header (== block), body and the end of the trailer must be
        // kShadowRatio aligned.
        EXPECT_TRUE(IsAligned(block.body, kShadowRatio));
        EXPECT_TRUE(IsAligned(block.header, kShadowRatio));
        EXPECT_TRUE(IsAligned(block.block, kPageSize));
        EXPECT_TRUE(IsAligned(block.block + block.block_size, kPageSize));

        size_t right_redzone_size = (block.block + block.block_size) -
            reinterpret_cast<uint8*>(block.trailer_padding);

        EXPECT_EQ(2 * kPageSize, block.block_size);
        EXPECT_LE(kPageSize, right_redzone_size);

        size_t body_offset = AlignUp(block.trailer_padding, kPageSize) -
            block.trailer_padding;

        // The body must be as close as possible to the page.
        EXPECT_GT(kShadowRatio, body_offset);

        EXPECT_TRUE(h.FreeBlock(block));
      }
    }
  }
}

TEST(ZebraBlockHeapTest, AllocateSizeLimits) {
  TestZebraBlockHeap h;

  // Test all possible allocation sizes.
  for (size_t i = 1; i <= kPageSize; ++i) {
    uint8* alloc = reinterpret_cast<uint8*>(h.Allocate(i));
    EXPECT_NE(reinterpret_cast<uint8*>(NULL), alloc);
    EXPECT_TRUE(IsAligned(alloc, kShadowRatio));
    EXPECT_TRUE(h.Free(alloc));
  }

  // Impossible allocation sizes.
  for (size_t delta = 1; delta < 10000; delta += 7)
    EXPECT_EQ(reinterpret_cast<void*>(NULL), h.Allocate(kPageSize + delta));
}


TEST(ZebraBlockHeapTest, AllocateBlockSizeLimits) {
  TestZebraBlockHeap h;
  BlockLayout layout = {};
  BlockInfo block = {};

  const size_t kMaxAllowedBlockSize = kPageSize - sizeof(BlockHeader);

  // Allocate all possible block sizes.
  for (size_t i = 0; i <= kMaxAllowedBlockSize; ++i) {
    uint8* alloc = reinterpret_cast<uint8*>(
        h.AllocateBlock(i, sizeof(BlockHeader), sizeof(BlockTrailer), &layout));

    EXPECT_NE(reinterpret_cast<void*>(NULL), alloc);
    BlockInitialize(layout, alloc, false, &block);
    EXPECT_TRUE(h.FreeBlock(block));
  }

  // Impossible block sizes.
  for (size_t delta = 1; delta < 10000; delta += 7)
    EXPECT_EQ(reinterpret_cast<uint8*>(NULL),
              h.AllocateBlock(kMaxAllowedBlockSize + delta,
                              sizeof(BlockHeader), sizeof(BlockTrailer),
                              &layout));
}

TEST(ZebraBlockHeapTest, AllocateTwoEmptyBlocks) {
  TestZebraBlockHeap h;
  BlockLayout layout1 = {};
  BlockLayout layout2 = {};
  BlockInfo block1 = {};
  BlockInfo block2 = {};

  void* mem1 = h.AllocateBlock(0, sizeof(BlockHeader), sizeof(BlockTrailer),
      &layout1);
  EXPECT_NE(reinterpret_cast<void*>(NULL), mem1);
  EXPECT_TRUE(IsAligned(mem1, kShadowRatio));

  void* mem2 = h.AllocateBlock(0, sizeof(BlockHeader), sizeof(BlockTrailer),
      &layout2);
  EXPECT_NE(reinterpret_cast<void*>(NULL), mem2);
  EXPECT_TRUE(IsAligned(mem2, kShadowRatio));

  // Empty blocks cannot have the same address.
  EXPECT_NE(mem1, mem2);

  BlockInitialize(layout1, mem1, false, &block1);
  BlockInitialize(layout2, mem2, false, &block2);

  EXPECT_TRUE(h.FreeBlock(block1));
  EXPECT_TRUE(h.FreeBlock(block2));
}


TEST(ZebraBlockHeapTest, AllocateUntilFull) {
  TestZebraBlockHeap h;
  // Test maximum number of allocations.
  std::vector<uint8*> buffers;
  for (size_t i = 0; i < h.max_number_of_allocations_; ++i) {
    uint8* alloc = reinterpret_cast<uint8*>(h.Allocate(0xFF));
    EXPECT_NE(reinterpret_cast<uint8*>(NULL), alloc);
    EXPECT_TRUE(IsAligned(alloc, kShadowRatio));
    buffers.push_back(alloc);
  }

  // The number of allocations should match the number of even pages.
  EXPECT_EQ(h.max_number_of_allocations_, buffers.size());

  // Impossible to allocate memory on a full heap.
  EXPECT_EQ(reinterpret_cast<void*>(NULL), h.Allocate(0xFF));

  // Check that all buffers are at least page_size bytes apart.
  std::sort(buffers.begin(), buffers.end());
  for (size_t i = 1; i < buffers.size(); ++i)
    EXPECT_LE(kPageSize, static_cast<size_t>(buffers[i] - buffers[i - 1]));

  // Cleanup.
  for (size_t i = 0; i < buffers.size(); ++i)
    EXPECT_TRUE(h.Free(buffers[i]));
}

TEST(ZebraBlockHeapTest, StressAllocateFree) {
  TestZebraBlockHeap h;

  // Test maximum number of allocations.
  std::vector<uint8*> buffers;

  // Fill the heap.
  for (size_t i = 0; i < h.max_number_of_allocations_; ++i) {
    uint8* alloc = reinterpret_cast<uint8*>(h.Allocate(0xFF));
    EXPECT_NE(reinterpret_cast<uint8*>(NULL), alloc);
    EXPECT_TRUE(IsAligned(alloc, kShadowRatio));
    buffers.push_back(alloc);
  }

  // The number of allocations must match the number of even pages.
  EXPECT_EQ(h.max_number_of_allocations_, buffers.size());
  // Impossible to allocate memory on a full heap.
  EXPECT_EQ(reinterpret_cast<void*>(NULL), h.Allocate(0xFF));

  // Shuffle the allocation order deterministically.
  for (size_t i = 0; i < buffers.size(); ++i)
    std::swap(buffers[i], buffers[(3 * i) % buffers.size()]);

  // Stress Allocate/Free (the heap starts full).
  for (size_t i = 1; i < buffers.size() / 2; ++i) {
    // Free i blocks.
    for (size_t j = 0; j < i; ++j) {
      EXPECT_TRUE(h.Free(buffers.back()));
      buffers.pop_back();
    }

    // Allocates i blocks, so the heap is full again.
    for (size_t j = 0; j < i; ++j) {
      uint8* alloc = reinterpret_cast<uint8*>(h.Allocate(0xFF));
      EXPECT_NE(reinterpret_cast<uint8*>(NULL), alloc);
      buffers.push_back(alloc);
    }

    // The number of allocations must match the number of even pages.
    EXPECT_EQ(h.max_number_of_allocations_, buffers.size());
    // Impossible to allocate memory on a full heap.
    EXPECT_EQ(reinterpret_cast<void*>(NULL), h.Allocate(0xFF));
  }

  // Cleanup.
  for (size_t i = 0; i < buffers.size(); ++i)
    EXPECT_TRUE(h.Free(buffers[i]));
}

TEST(ZebraBlockHeapTest, AllocateBlockCornerCases) {
  TestZebraBlockHeap h;
  BlockLayout layout = {};
  BlockInfo block = {};

  size_t block_header_size = sizeof(BlockHeader);
  size_t block_trailer_size = sizeof(BlockTrailer);

  // Edge-case sizes for testing corner cases.
  const size_t kSizes[] = { 0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 17, 1023, 1024, 1025,
      1235, 1365, 2014, 2047, 2048, 2049, 3000, 7000, 12345,
      kPageSize - 1,
      kPageSize,
      kPageSize + 1,
      kShadowRatio - 1,
      kShadowRatio,
      kShadowRatio + 1,
      block_header_size - 1,
      block_header_size,
      block_header_size + 1,
      block_trailer_size - 1,
      block_trailer_size,
      block_trailer_size + 1,
      kPageSize - block_header_size - 1,
      kPageSize - block_header_size,
      kPageSize - block_header_size + 1,
      kPageSize - block_trailer_size - 1,
      kPageSize - block_trailer_size,
      kPageSize - block_trailer_size + 1 };

  for (size_t i = 0; i < arraysize(kSizes); ++i) {
    for (size_t j = 0; j < arraysize(kSizes); ++j) {
      for (size_t k = 0; k < arraysize(kSizes); ++k) {
        size_t header_size = kSizes[i];
        size_t body_size = kSizes[j];
        size_t trailer_size = kSizes[k];

        // Check if there is capacity to do the allocation.
        EXPECT_FALSE(h.IsHeapFull());

        void* alloc = h.AllocateBlock(body_size,
                                      header_size,
                                      trailer_size,
                                      &layout);

        if (alloc != NULL) {
          // Check that the block is well formed.
          EXPECT_TRUE(header_size + body_size <= kPageSize);
          EXPECT_TRUE(trailer_size <= kPageSize);

          size_t body_end_offset = layout.header_size +
              layout.header_padding_size + layout.body_size;

          EXPECT_EQ(kPageSize, common::AlignUp(body_end_offset, kShadowRatio));
          BlockInitialize(layout, alloc, false, &block);
          EXPECT_TRUE(h.FreeBlock(block));
        } else {
          size_t body_end_offset = layout.header_size +
              layout.header_padding_size + layout.body_size;

          // Check the cause of the unsuccessful allocation.
          EXPECT_TRUE(
              // Even page overflow.
              (header_size + body_size > kPageSize) ||
              // Odd page overflow.
              (trailer_size > kPageSize) ||
              // Incorrect body alignment.
              (kPageSize != common::AlignUp(body_end_offset, kShadowRatio)));
        }
      }
    }
  }
}

TEST(ZebraBlockHeapTest, IsAllocated) {
  TestZebraBlockHeap h;

  EXPECT_FALSE(h.IsAllocated(NULL));

  void* a = h.Allocate(100);
  EXPECT_TRUE(h.IsAllocated(a));
  EXPECT_FALSE(h.IsAllocated(reinterpret_cast<uint8*>(a) - 1));
  EXPECT_FALSE(h.IsAllocated(reinterpret_cast<uint8*>(a) + 1));

  h.Free(a);
  EXPECT_FALSE(h.IsAllocated(a));
}

TEST(ZebraBlockHeapTest, PushPopInvariant) {
  TestZebraBlockHeap h;
  BlockLayout layout = {};
  BlockInfo block = {};

  // Fill the heap.
  std::vector<BlockInfo> blocks;
  for (size_t i = 0; i < h.max_number_of_allocations_; i++) {
    void* alloc = h.AllocateBlock(0xFF, 0, 0, &layout);
    EXPECT_NE(reinterpret_cast<void*>(NULL), alloc);
    EXPECT_TRUE(IsAligned(alloc, kShadowRatio));
    BlockInitialize(layout, alloc, false, &block);
    blocks.push_back(block);
    EXPECT_TRUE(h.Push(block.header));
  }

  for (size_t i = 0; i < h.max_number_of_allocations_; i++) {
    BlockHeader* dummy;
    bool old_invariant = h.QuarantineInvariantIsSatisfied();
    if (h.Pop(&dummy)) {
      EXPECT_FALSE(old_invariant);
    } else {
      EXPECT_TRUE(old_invariant);
      EXPECT_TRUE(h.QuarantineInvariantIsSatisfied());
      break;
    }
  }

  // Clear the quarantine.
  std::vector<BlockHeader*> objects;
  h.Empty(&objects);

  // Blocks can be freed now.
  for (size_t i = 0; i < blocks.size(); i++)
    EXPECT_TRUE(h.FreeBlock(blocks[i]));
}

TEST(ZebraBlockHeapTest, MemoryNotifierIsCalled) {
  testing::MockMemoryNotifier mock_notifier;

  // Should be called by ZebraBlockHeap internal data structures.
  EXPECT_CALL(mock_notifier,
      NotifyInternalUse(NotNull(), Gt(0u)))
      .Times(AtLeast(1));

  // Should be called exactly once when reserving the initial memory.
  EXPECT_CALL(mock_notifier,
      NotifyFutureHeapUse(NotNull(), Gt(0u)))
      .Times(1);

  // Should be called in the ZebraBlockHeap destructor and in the internal
  // structures.
  EXPECT_CALL(mock_notifier,
      NotifyReturnedToOS(NotNull(), Gt(0u)))
      .Times(AtLeast(2));

  TestZebraBlockHeap h(&mock_notifier);
  h.Allocate(10);
}

}  // namespace heaps
}  // namespace asan
}  // namespace agent
