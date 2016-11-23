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

using ::common::IsAligned;
using ::common::AlignDown;
using ::common::AlignUp;

using ::testing::_;
using ::testing::Gt;
using ::testing::NotNull;
using ::testing::AtLeast;

testing::NullMemoryNotifier null_notifier;
testing::DummyHeap dummy_heap;

class TestZebraBlockHeap : public ZebraBlockHeap {
 public:
  using ZebraBlockHeap::QuarantineInvariantIsSatisfied;
  using ZebraBlockHeap::heap_address_;
  using ZebraBlockHeap::slab_count_;

  static const size_t kInitialHeapSize = 8 * (1 << 20);

  // Creates a test heap with 8 MB initial (and maximum) memory using the
  // default memory notifier.
  TestZebraBlockHeap() : ZebraBlockHeap(kInitialHeapSize,
                                        &null_notifier,
                                        &dummy_heap) { }

  // Creates a test heap with 8 MB initial (and maximum) memory using a custom
  // memory notifier.
  explicit TestZebraBlockHeap(MemoryNotifierInterface* memory_notifier)
      : ZebraBlockHeap(kInitialHeapSize, memory_notifier, &dummy_heap) { }

  // Allows to know if the heap can handle more allocations.
  // @returns true if the heap is full (no more allocations allowed),
  // false otherwise.
  bool IsHeapFull() {
    // No free slabs.
    return free_slabs_.empty();
  }
};

}  // namespace

TEST(ZebraBlockHeapTest, GetHeapTypeIsValid) {
  TestZebraBlockHeap h;
  EXPECT_EQ(kZebraBlockHeap, h.GetHeapType());
}

TEST(ZebraBlockHeapTest, FeaturesAreValid) {
  TestZebraBlockHeap h;
  EXPECT_EQ(HeapInterface::kHeapSupportsIsAllocated |
                HeapInterface::kHeapReportsReservations |
                HeapInterface::kHeapSupportsGetAllocationSize,
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
  BlockInitialize(layout, alloc, &block);
  EXPECT_TRUE(h.FreeBlock(block));
}

TEST(ZebraBlockHeapTest, EndToEnd) {
  TestZebraBlockHeap h;
  BlockLayout layout = {};
  BlockInfo block = {};

  // Make a bunch of different sized allocations.
  std::vector<BlockInfo> blocks;
  for (uint32_t i = 1; i < 100; i++) {
    void* alloc = h.AllocateBlock(i, 0, 0, &layout);
    EXPECT_NE(reinterpret_cast<void*>(NULL), alloc);
    EXPECT_TRUE(IsAligned(alloc, kShadowRatio));
    BlockInitialize(layout, alloc, &block);
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
  for (uint32_t header_size = 0; header_size < 100; header_size += 3) {
    for (uint32_t trailer_size = 0; trailer_size < 100; trailer_size += 3) {
      for (uint32_t body_size = 0; body_size < 100; body_size += 3) {
        void* alloc = h.AllocateBlock(body_size, header_size,
                                      trailer_size, &layout);

        EXPECT_NE(reinterpret_cast<void*>(NULL), alloc);
        EXPECT_TRUE(IsAligned(alloc, kShadowRatio));

        BlockInitialize(layout, alloc, &block);

        // The header (== block), body and the end of the trailer must be
        // kShadowRatio aligned.
        EXPECT_TRUE(IsAligned(block.body, kShadowRatio));
        EXPECT_TRUE(IsAligned(block.header, kShadowRatio));
        EXPECT_TRUE(IsAligned(block.header, GetPageSize()));
        EXPECT_TRUE(IsAligned(block.trailer + 1, GetPageSize()));

        uint32_t right_redzone_size = block.TotalTrailerSize();

        EXPECT_EQ(2 * GetPageSize(), block.block_size);
        EXPECT_LE(GetPageSize(), right_redzone_size);

        uint32_t body_offset = AlignUp(block.RawTrailerPadding(),
                                       GetPageSize()) -
            block.RawTrailerPadding();

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
  for (uint32_t i = 1; i <= GetPageSize(); ++i) {
    uint8_t* alloc = static_cast<uint8_t*>(h.Allocate(i));
    EXPECT_NE(static_cast<uint8_t*>(NULL), alloc);
    EXPECT_TRUE(IsAligned(alloc, kShadowRatio));
    EXPECT_TRUE(h.Free(alloc));
  }

  // Impossible allocation sizes.
  for (uint32_t delta = 1; delta < 10000; delta += 7)
    EXPECT_EQ(reinterpret_cast<void*>(NULL),
              h.Allocate(static_cast<uint32_t>(GetPageSize()) + delta));
}


TEST(ZebraBlockHeapTest, AllocateBlockSizeLimits) {
  TestZebraBlockHeap h;
  BlockLayout layout = {};
  BlockInfo block = {};

  const uint32_t kMaxAllowedBlockSize = static_cast<uint32_t>(GetPageSize()) -
      sizeof(BlockHeader);

  // Allocate all possible block sizes.
  for (uint32_t i = 0; i <= kMaxAllowedBlockSize; ++i) {
    uint8_t* alloc = reinterpret_cast<uint8_t*>(
        h.AllocateBlock(i, sizeof(BlockHeader), sizeof(BlockTrailer), &layout));

    EXPECT_NE(reinterpret_cast<void*>(NULL), alloc);
    BlockInitialize(layout, alloc, &block);
    EXPECT_TRUE(h.FreeBlock(block));
  }

  // Impossible block sizes.
  for (uint32_t delta = 1; delta < 10000; delta += 7)
    EXPECT_EQ(reinterpret_cast<uint8_t*>(NULL),
              h.AllocateBlock(kMaxAllowedBlockSize + delta, sizeof(BlockHeader),
                              sizeof(BlockTrailer), &layout));
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

  BlockInitialize(layout1, mem1, &block1);
  BlockInitialize(layout2, mem2, &block2);

  EXPECT_TRUE(h.FreeBlock(block1));
  EXPECT_TRUE(h.FreeBlock(block2));
}


TEST(ZebraBlockHeapTest, AllocateUntilFull) {
  TestZebraBlockHeap h;
  // Test maximum number of allocations.
  std::vector<uint8_t*> buffers;
  for (size_t i = 0; i < h.slab_count_; ++i) {
    uint8_t* alloc = reinterpret_cast<uint8_t*>(h.Allocate(0xFF));
    EXPECT_NE(reinterpret_cast<uint8_t*>(NULL), alloc);
    EXPECT_TRUE(IsAligned(alloc, kShadowRatio));
    buffers.push_back(alloc);
  }

  // The number of allocations should match the number of even pages.
  EXPECT_EQ(h.slab_count_, buffers.size());

  // Impossible to allocate memory on a full heap.
  EXPECT_EQ(reinterpret_cast<void*>(NULL), h.Allocate(0xFF));

  // Check that all buffers are at least page_size bytes apart.
  std::sort(buffers.begin(), buffers.end());
  for (size_t i = 1; i < buffers.size(); ++i)
    EXPECT_LE(GetPageSize(), static_cast<size_t>(buffers[i] - buffers[i - 1]));

  // Cleanup.
  for (size_t i = 0; i < buffers.size(); ++i)
    EXPECT_TRUE(h.Free(buffers[i]));
}

TEST(ZebraBlockHeapTest, StressAllocateFree) {
  TestZebraBlockHeap h;

  // Test maximum number of allocations.
  std::vector<uint8_t*> buffers;

  // Fill the heap.
  for (size_t i = 0; i < h.slab_count_; ++i) {
    uint8_t* alloc = reinterpret_cast<uint8_t*>(h.Allocate(0xFF));
    EXPECT_NE(reinterpret_cast<uint8_t*>(NULL), alloc);
    EXPECT_TRUE(IsAligned(alloc, kShadowRatio));
    buffers.push_back(alloc);
  }

  // The number of allocations must match the number of even pages.
  EXPECT_EQ(h.slab_count_, buffers.size());
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
      uint8_t* alloc = reinterpret_cast<uint8_t*>(h.Allocate(0xFF));
      EXPECT_NE(reinterpret_cast<uint8_t*>(NULL), alloc);
      buffers.push_back(alloc);
    }

    // The number of allocations must match the number of even pages.
    EXPECT_EQ(h.slab_count_, buffers.size());
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

  uint32_t block_header_size = sizeof(BlockHeader);
  uint32_t block_trailer_size = sizeof(BlockTrailer);
  uint32_t page_size = static_cast<uint32_t>(GetPageSize());

  // Edge-case sizes for testing corner cases.
  const uint32_t kSizes[] = { 0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 17, 1023, 1024,
      1025, 1235, 1365, 2014, 2047, 2048, 2049, 3000, 7000, 12345,
      page_size - 1,
      page_size,
      page_size + 1,
      kShadowRatio - 1,
      kShadowRatio,
      kShadowRatio + 1,
      block_header_size - 1,
      block_header_size,
      block_header_size + 1,
      block_trailer_size - 1,
      block_trailer_size,
      block_trailer_size + 1,
      page_size - block_header_size - 1,
      page_size - block_header_size,
      page_size - block_header_size + 1,
      page_size - block_trailer_size - 1,
      page_size - block_trailer_size,
      page_size - block_trailer_size + 1 };

  for (size_t i = 0; i < arraysize(kSizes); ++i) {
    for (size_t j = 0; j < arraysize(kSizes); ++j) {
      for (size_t k = 0; k < arraysize(kSizes); ++k) {
        uint32_t header_size = kSizes[i];
        uint32_t body_size = kSizes[j];
        uint32_t trailer_size = kSizes[k];

        // Check if there is capacity to do the allocation.
        EXPECT_FALSE(h.IsHeapFull());

        void* alloc = h.AllocateBlock(body_size,
                                      header_size,
                                      trailer_size,
                                      &layout);

        if (alloc != NULL) {
          // Check that the block is well formed.
          EXPECT_TRUE(header_size + body_size <= GetPageSize());
          EXPECT_TRUE(trailer_size <= GetPageSize());

          size_t body_end_offset = layout.header_size +
              layout.header_padding_size + layout.body_size;

          EXPECT_EQ(GetPageSize(),
                    ::common::AlignUp(body_end_offset, kShadowRatio));
          BlockInitialize(layout, alloc, &block);
          EXPECT_TRUE(h.FreeBlock(block));
        } else {
          size_t body_end_offset = layout.header_size +
              layout.header_padding_size + layout.body_size;

          // Check the cause of the unsuccessful allocation.
          EXPECT_TRUE(
              // Even page overflow.
              (header_size + body_size > GetPageSize()) ||
              // Odd page overflow.
              (trailer_size > GetPageSize()) ||
              // Incorrect body alignment.
              (GetPageSize() !=
                  ::common::AlignUp(body_end_offset, kShadowRatio)));
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
  EXPECT_FALSE(h.IsAllocated(reinterpret_cast<uint8_t*>(a) - 1));
  EXPECT_FALSE(h.IsAllocated(reinterpret_cast<uint8_t*>(a) + 1));

  h.Free(a);
  EXPECT_FALSE(h.IsAllocated(a));
}

TEST(ZebraBlockHeapTest, GetAllocationSize) {
  TestZebraBlockHeap h;

  void* alloc = h.Allocate(67);
  ASSERT_TRUE(alloc != NULL);
  EXPECT_EQ(67u, h.GetAllocationSize(alloc));
}

TEST(ZebraBlockHeapTest, PushPopInvariant) {
  TestZebraBlockHeap h;
  BlockLayout layout = {};
  BlockInfo block = {};

  // Fill the heap.
  std::vector<BlockInfo> blocks;
  for (size_t i = 0; i < h.slab_count_; i++) {
    void* alloc = h.AllocateBlock(0xFF, 0, 0, &layout);
    EXPECT_NE(reinterpret_cast<void*>(NULL), alloc);
    EXPECT_TRUE(IsAligned(alloc, kShadowRatio));
    BlockInitialize(layout, alloc, &block);
    blocks.push_back(block);
    CompactBlockInfo compact = {};
    ConvertBlockInfo(block, &compact);
    EXPECT_TRUE(h.Push(compact).push_successful);
  }

  for (size_t i = 0; i < h.slab_count_; i++) {
    CompactBlockInfo dummy = {};
    bool old_invariant = h.QuarantineInvariantIsSatisfied();
    if (h.Pop(&dummy).pop_successful) {
      EXPECT_FALSE(old_invariant);
    } else {
      EXPECT_TRUE(old_invariant);
      EXPECT_TRUE(h.QuarantineInvariantIsSatisfied());
      break;
    }
  }

  // Clear the quarantine.
  std::vector<CompactBlockInfo> objects;
  h.Empty(&objects);

  // Blocks can be freed now.
  for (size_t i = 0; i < blocks.size(); i++)
    EXPECT_TRUE(h.FreeBlock(blocks[i]));
}

TEST(ZebraBlockHeapTest, MemoryNotifierIsCalled) {
  testing::MockMemoryNotifier mock_notifier;

  // Should be called exactly once when reserving the initial memory.
  EXPECT_CALL(mock_notifier,
      NotifyFutureHeapUse(NotNull(), Gt(0u)))
      .Times(1);

  // Should be called in the ZebraBlockHeap destructor.
  EXPECT_CALL(mock_notifier,
      NotifyReturnedToOS(NotNull(), Gt(0u)))
      .Times(1);

  TestZebraBlockHeap h(&mock_notifier);
  h.Allocate(10);
}

TEST(ZebraBlockHeapTest, Lock) {
  TestZebraBlockHeap h;

  h.Lock();
  EXPECT_TRUE(h.TryLock());
  h.Unlock();
  h.Unlock();
}

}  // namespace heaps
}  // namespace asan
}  // namespace agent
