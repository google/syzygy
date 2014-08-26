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

#include "syzygy/agent/asan/heap_managers/block_heap_manager.h"

#include <vector>

#include "base/bind.h"
#include "base/compiler_specific.h"
#include "base/rand_util.h"
#include "base/sha1.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/agent/asan/asan_runtime.h"
#include "syzygy/agent/asan/heap.h"
#include "syzygy/agent/asan/unittest_util.h"

namespace agent {
namespace asan {
namespace heap_managers {

namespace {

using heaps::ZebraBlockHeap;

typedef BlockHeapManager::HeapId HeapId;

testing::NullMemoryNotifier null_memory_notifier;

// A fake ZebraBlockHeap to simplify unit testing.
// Wrapper with switches to enable/disable the quarantine and accept/refuse
// allocations.
class TestZebraBlockHeap : public heaps::ZebraBlockHeap {
 public:
  using ZebraBlockHeap::set_quarantine_ratio;
  using ZebraBlockHeap::quarantine_ratio;

  // Constructor.
  TestZebraBlockHeap() : ZebraBlockHeap(1024 * 1024, &null_memory_notifier) {
    refuse_allocations_ = false;
    refuse_push_ = false;
  }

  // Virtual destructor.
  virtual ~TestZebraBlockHeap() { }

  // Wrapper that allows easily disabling allocations.
  virtual void* AllocateBlock(size_t size,
                              size_t min_left_redzone_size,
                              size_t min_right_redzone_size,
                              BlockLayout* layout) OVERRIDE {
    if (refuse_allocations_)
      return NULL;
    return ZebraBlockHeap::AllocateBlock(size,
                                         min_left_redzone_size,
                                         min_right_redzone_size,
                                         layout);
  }

  // Wrapper that allows easily disabling the insertion of new blocks in the
  // quarantine.
  virtual bool Push(BlockHeader* const &object) OVERRIDE {
    if (refuse_push_)
      return false;
    return ZebraBlockHeap::Push(object);
  }

  // Enable/Disable future allocations.
  void set_refuse_allocations(bool value) {
    refuse_allocations_ = value;
  }

  // Enable/Disable the insertion of blocks in the quarantine.
  void set_refuse_push(bool value) {
    refuse_push_ = value;
  }

 protected:
  bool refuse_allocations_;
  bool refuse_push_;

 private:
  DISALLOW_COPY_AND_ASSIGN(TestZebraBlockHeap);
};

// A derived class to expose protected members for unit-testing.
class TestBlockHeapManager : public BlockHeapManager {
 public:
  using BlockHeapManager::FreePotentiallyCorruptBlock;
  using BlockHeapManager::HeapQuarantineMap;
  using BlockHeapManager::SetHeapErrorCallback;
  using BlockHeapManager::ShardedBlockQuarantine;
  using BlockHeapManager::TrimQuarantine;

  using BlockHeapManager::heaps_;
  using BlockHeapManager::parameters_;
  using BlockHeapManager::zebra_block_heap_;

  // A derived class to expose protected members for unit-testing. This has to
  // be nested into this one because ShardedBlockQuarantine accesses some
  // protected fields of BlockHeapManager.
  //
  // This class should only expose some members or expose new functions, no new
  // member should be added.
  class TestQuarantine : public ShardedBlockQuarantine {
   public:
    using ShardedBlockQuarantine::Node;
    using ShardedBlockQuarantine::kShardingFactor;
    using ShardedBlockQuarantine::heads_;
  };

  // Constructor.
  explicit TestBlockHeapManager(AsanRuntime* runtime)
      : BlockHeapManager(runtime) {
  }

  // Returns the quarantine associated with a heap.
  BlockQuarantineInterface* GetHeapQuarantine(HeapId heap_id) {
    TestBlockHeapManager::HeapQuarantineMap::iterator iter_heap =
        heaps_.find(reinterpret_cast<BlockHeapInterface*>(heap_id));
    if (iter_heap == heaps_.end())
      return NULL;
    return iter_heap->second;
  }
};

// A derived class to expose protected members for unit-testing.
class TestShadow : public Shadow {
 public:
  using Shadow::kShadowSize;
  using Shadow::shadow_;
};

// A utility class for manipulating a heap. This automatically delete the heap
// and its content in the destructor and provides some utility functions.
class ScopedHeap {
 public:
  typedef TestBlockHeapManager::TestQuarantine TestQuarantine;

  // Constructor.
  explicit ScopedHeap(TestBlockHeapManager* heap_manager)
      : heap_manager_(heap_manager) {
    heap_id_ = heap_manager->CreateHeap();
    EXPECT_NE(static_cast<HeapId>(NULL), heap_id_);
  }

  // Destructor. Destroy the heap, this will flush its quarantine and delete all
  // the structures associated with this heap.
  ~ScopedHeap() {
    ReleaseHeap();
  }

  void ReleaseHeap() {
    if (heap_id_ != static_cast<HeapId>(NULL)) {
      EXPECT_TRUE(heap_manager_->DestroyHeap(heap_id_));
      heap_id_ = static_cast<HeapId>(NULL);
    }
  }

  // Retrieves the quarantine associated with this heap.
  BlockQuarantineInterface* GetQuarantine() {
    return heap_manager_->GetHeapQuarantine(heap_id_);
  }

  // Allocate a block of @p size bytes.
  void* Allocate(size_t size) {
    void* alloc = heap_manager_->Allocate(heap_id_, size);
    EXPECT_NE(reinterpret_cast<void*>(NULL), alloc);
    return alloc;
  }

  // Free the block @p mem.
  bool Free(void* mem) {
    return heap_manager_->Free(heap_id_, mem);
  }

  // Flush the quarantine of this heap.
  void FlushQuarantine() {
    BlockQuarantineInterface* quarantine =  GetQuarantine();
    EXPECT_NE(static_cast<BlockQuarantineInterface*>(NULL),
              quarantine);
    BlockQuarantineInterface::ObjectVector blocks_to_free;
    quarantine->Empty(&blocks_to_free);
    BlockQuarantineInterface::ObjectVector::iterator iter_block =
        blocks_to_free.begin();
    for (; iter_block != blocks_to_free.end(); ++iter_block) {
      DCHECK_NE(reinterpret_cast<BlockHeader*>(NULL), *iter_block);
      BlockInfo block_info = {};
      CHECK(Shadow::BlockInfoFromShadow(*iter_block, &block_info));
      CHECK(heap_manager_->FreePotentiallyCorruptBlock(&block_info));
    }
  }

  // Returns the underlying heap ID.
  HeapId Id() { return heap_id_; }

  // Determines if the address @p mem corresponds to a block in the quarantine
  // of this heap.
  bool InQuarantine(const void* mem) {
    // As we'll cast an AsanShardedQuarantine directly into a TestQuarantine
    // there shouldn't be any new field defined by this class, this should only
    // act as an interface allowing to access some private fields.
    COMPILE_ASSERT(
        sizeof(TestQuarantine) ==
            sizeof(TestBlockHeapManager::ShardedBlockQuarantine),
        test_quarantine_is_not_an_interface);
    TestQuarantine* test_quarantine =
        reinterpret_cast<TestQuarantine*>(GetQuarantine());
    EXPECT_NE(reinterpret_cast<TestQuarantine*>(NULL), test_quarantine);
    // Search through all of the shards.
    for (size_t i = 0; i < test_quarantine->kShardingFactor; ++i) {
      // Search through all blocks in each shard.
      TestQuarantine::Node* current_node = test_quarantine->heads_[i];
      while (current_node != NULL) {
        BlockInfo block_info = {};
        EXPECT_TRUE(BlockInfoFromMemory(current_node->object, &block_info));
        if (block_info.body == mem) {
          EXPECT_EQ(QUARANTINED_BLOCK, current_node->object->state);
          return true;
        }
        current_node = current_node->next;
      }
    }

    return false;
  }

 private:
  // The heap manager owning the underlying heap.
  TestBlockHeapManager* heap_manager_;

  // The underlying heap.
  HeapId heap_id_;
};

class BlockHeapManagerTest : public testing::Test {
 public:
  typedef TestBlockHeapManager::ShardedBlockQuarantine ShardedBlockQuarantine;

  BlockHeapManagerTest() : heap_manager_(&runtime_),
      test_zebra_block_heap_(NULL) {
  }

  virtual void SetUp() OVERRIDE {
    runtime_.SetUp(L"");

    // Set the error callback that the manager will use.
    heap_manager_.SetHeapErrorCallback(
        base::Bind(&BlockHeapManagerTest::OnHeapError, base::Unretained(this)));

    common::AsanParameters params;
    common::SetDefaultAsanParameters(&params);
    heap_manager_.set_parameters(params);
  }

  virtual void TearDown() OVERRIDE {
    // Artificially clear the ZebraBlockHeap before releasing runtime_ to avoid
    // runtime error.
    // TearDown is called before destructing the zebra heap.
    // The blocks contains stack-related information somehow linked to the
    // runtime_ instance. If the runtime_ instance is cleared before the
    // zebra heap and there are still blocks in its quarantine, some
    // non-deterministic errors (failed DCHECKS) may arise.
    if (test_zebra_block_heap_ != NULL) {
      heap_manager_.parameters_.quarantine_size = 0;
      heap_manager_.TrimQuarantine(test_zebra_block_heap_);
    }

    runtime_.TearDown();
  }

  void OnHeapError(AsanErrorInfo* error) {
    errors_.push_back(*error);
  }

  // Calculates the ASan size for an allocation of @p user_size bytes.
  size_t GetAllocSize(size_t user_size) {
    BlockLayout layout = {};
    BlockPlanLayout(kShadowRatio,
                    kShadowRatio,
                    user_size,
                    0,
                    heap_manager_.parameters().trailer_padding_size +
                        sizeof(BlockTrailer),
                    &layout);
    return layout.block_size;
  }

  void EnableTestZebraBlockHeap() {
    // Erase previous ZebraBlockHeap.
    if (heap_manager_.zebra_block_heap_ != NULL) {
      heap_manager_.heaps_.erase(heap_manager_.zebra_block_heap_);
      delete heap_manager_.zebra_block_heap_;
    }
    // Plug a mock ZebraBlockHeap by default disabled.
    test_zebra_block_heap_ = new TestZebraBlockHeap();
    heap_manager_.zebra_block_heap_ = test_zebra_block_heap_;
    heap_manager_.heaps_.insert(std::make_pair(test_zebra_block_heap_,
        test_zebra_block_heap_));

    // Turn on the zebra_block_heap_enabled flag.
    common::AsanParameters params = heap_manager_.parameters();
    common::SetDefaultAsanParameters(&params);
    params.enable_zebra_block_heap = true;
    heap_manager_.set_parameters(params);
  }

  // Verifies that [alloc, alloc + size) is accessible, and that
  // [alloc - 1] and [alloc+size] are poisoned.
  void VerifyAllocAccess(void* alloc, size_t size) {
    uint8* mem = reinterpret_cast<uint8*>(alloc);
    ASSERT_FALSE(Shadow::IsAccessible(mem - 1));
    ASSERT_TRUE(Shadow::IsLeftRedzone(mem - 1));
    for (size_t i = 0; i < size; ++i)
      ASSERT_TRUE(Shadow::IsAccessible(mem + i));
    ASSERT_FALSE(Shadow::IsAccessible(mem + size));
  }

  // Verifies that [alloc-1, alloc+size] is poisoned.
  void VerifyFreedAccess(void* alloc, size_t size) {
    uint8* mem = reinterpret_cast<uint8*>(alloc);
    ASSERT_FALSE(Shadow::IsAccessible(mem - 1));
    ASSERT_TRUE(Shadow::IsLeftRedzone(mem - 1));
    for (size_t i = 0; i < size; ++i) {
      ASSERT_FALSE(Shadow::IsAccessible(mem + i));
      ASSERT_EQ(Shadow::GetShadowMarkerForAddress(mem + i),
                kHeapFreedMarker);
    }
    ASSERT_FALSE(Shadow::IsAccessible(mem + size));
  }

 protected:
  // The heap manager used in those tests.
  TestBlockHeapManager heap_manager_;

  // The runtime used by the heap manager.
  AsanRuntime runtime_;

  // Info about the last errors reported.
  std::vector<AsanErrorInfo> errors_;

  // The mock ZebraBlockHeap used in those tests.
  TestZebraBlockHeap* test_zebra_block_heap_;
};

}  // namespace

TEST_F(BlockHeapManagerTest, AllocAndFree) {
  const size_t kAllocSize = 17;
  HeapId heap_id = heap_manager_.CreateHeap();
  EXPECT_NE(static_cast<HeapId>(NULL), heap_id);
  void* alloc = heap_manager_.Allocate(heap_id, kAllocSize);
  EXPECT_NE(reinterpret_cast<void*>(NULL), alloc);
  EXPECT_EQ(kAllocSize, heap_manager_.Size(heap_id, alloc));
  EXPECT_TRUE(heap_manager_.Free(heap_id, alloc));
  EXPECT_TRUE(heap_manager_.DestroyHeap(heap_id));
}

TEST_F(BlockHeapManagerTest, SetQuarantinesMaxSize) {
  ScopedHeap heap(&heap_manager_);

  common::AsanParameters original_parameters = heap_manager_.parameters();
  common::AsanParameters new_parameters = original_parameters;
  new_parameters.quarantine_size = original_parameters.quarantine_size * 2;
  // Increments the quarantine max size if it was set to 0.
  if (new_parameters.quarantine_size == 0)
    new_parameters.quarantine_size++;
  heap_manager_.set_parameters(new_parameters);

  // Ensure that the maximum size of the quarantine of the 2 heaps has been
  // correctly set.
  BlockQuarantineInterface* quarantine =
      heap.GetQuarantine();
  ASSERT_NE(reinterpret_cast<BlockQuarantineInterface*>(NULL),
            quarantine);
  EXPECT_EQ(new_parameters.quarantine_size,
            heap_manager_.parameters_.quarantine_size);
}

TEST_F(BlockHeapManagerTest, PopOnSetQuarantineMaxSize) {
  const size_t kAllocSize = 100;
  size_t real_alloc_size = GetAllocSize(kAllocSize);
  ScopedHeap heap(&heap_manager_);
  void* mem = heap.Allocate(kAllocSize);
  ASSERT_FALSE(heap.InQuarantine(mem));

  common::AsanParameters parameters = heap_manager_.parameters();
  parameters.quarantine_size = real_alloc_size;
  heap_manager_.set_parameters(parameters);

  ASSERT_TRUE(heap.Free(mem));
  ASSERT_TRUE(heap.InQuarantine(mem));

  // We resize the quarantine to a smaller size, the block should pop out.
  parameters.quarantine_size = real_alloc_size - 1;
  heap_manager_.set_parameters(parameters);
  ASSERT_FALSE(heap.InQuarantine(mem));
}

TEST_F(BlockHeapManagerTest, Quarantine) {
  const size_t kAllocSize = 100;
  size_t real_alloc_size = GetAllocSize(kAllocSize);
  const size_t number_of_allocs = 16;
  ScopedHeap heap(&heap_manager_);

  common::AsanParameters parameters = heap_manager_.parameters();
  parameters.quarantine_size = real_alloc_size * number_of_allocs;
  heap_manager_.set_parameters(parameters);

  // Allocate a bunch of blocks until exactly one is removed from the
  // quarantine.
  std::vector<void*> blocks;
  for (size_t i = 0; i < number_of_allocs + 1; ++i) {
    void* mem = heap.Allocate(kAllocSize);
    ASSERT_TRUE(mem != NULL);
    heap.Free(mem);
    blocks.push_back(mem);
    if (i < number_of_allocs)
      ASSERT_TRUE(heap.InQuarantine(mem));
  }

  size_t blocks_in_quarantine = 0;
  for (size_t i = 0; i < blocks.size(); ++i) {
    if (heap.InQuarantine(blocks[i]))
      ++blocks_in_quarantine;
  }
  EXPECT_EQ(number_of_allocs, blocks_in_quarantine);
}

TEST_F(BlockHeapManagerTest, QuarantineLargeBlock) {
  const size_t kLargeAllocSize = 100;
  const size_t kSmallAllocSize = 25;
  size_t real_large_alloc_size = GetAllocSize(kLargeAllocSize);
  size_t real_small_alloc_size = GetAllocSize(kSmallAllocSize);

  ScopedHeap heap(&heap_manager_);
  common::AsanParameters parameters = heap_manager_.parameters();
  parameters.quarantine_size = real_large_alloc_size;
  parameters.quarantine_block_size = real_large_alloc_size;
  heap_manager_.set_parameters(parameters);

  // A block larger than the quarantine should not make it in.
  void* mem1 = heap.Allocate(real_large_alloc_size + 1);
  ASSERT_NE(reinterpret_cast<void*>(NULL), mem1);
  EXPECT_TRUE(heap.Free(mem1));
  EXPECT_FALSE(heap.InQuarantine(mem1));
  EXPECT_EQ(0u, heap.GetQuarantine()->GetCount());

  // A smaller block should make it because our current max block size allows
  // it.
  void* mem2 = heap.Allocate(kSmallAllocSize);
  ASSERT_NE(reinterpret_cast<void*>(NULL), mem2);
  EXPECT_TRUE(heap.Free(mem2));
  EXPECT_TRUE(heap.InQuarantine(mem2));

  parameters.quarantine_block_size = real_small_alloc_size - 1;
  heap_manager_.set_parameters(parameters);

  // A second small block should not make it in since we changed the block size.
  // However, the other block should remain in the quarantine.
  void* mem3 = heap.Allocate(kSmallAllocSize);
  ASSERT_NE(reinterpret_cast<void*>(NULL), mem3);
  EXPECT_TRUE(heap.Free(mem3));
  EXPECT_TRUE(heap.InQuarantine(mem2));
  EXPECT_FALSE(heap.InQuarantine(mem3));
}

TEST_F(BlockHeapManagerTest, UnpoisonsQuarantine) {
  const size_t kAllocSize = 100;
  const size_t real_alloc_size = GetAllocSize(kAllocSize);

  ScopedHeap heap(&heap_manager_);
  common::AsanParameters parameters = heap_manager_.parameters();
  parameters.quarantine_size = real_alloc_size;
  heap_manager_.set_parameters(parameters);

  // Allocate a memory block and directly free it, this puts it in the
  // quarantine.
  void* mem = heap.Allocate(kAllocSize);
  ASSERT_NE(reinterpret_cast<void*>(NULL), mem);
  ASSERT_TRUE(heap.Free(mem));
  ASSERT_TRUE(heap.InQuarantine(mem));

  // Assert that the shadow memory has been correctly poisoned.
  intptr_t mem_start = reinterpret_cast<intptr_t>(BlockGetHeaderFromBody(mem));
  ASSERT_EQ(0, (mem_start & 7) );
  size_t shadow_start = mem_start >> 3;
  size_t shadow_alloc_size = real_alloc_size >> 3;
  for (size_t i = shadow_start; i < shadow_start + shadow_alloc_size; ++i)
    ASSERT_NE(kHeapAddressableMarker, TestShadow::shadow_[i]);

  // Flush the quarantine.
  heap.FlushQuarantine();

  // Assert that the quarantine has been correctly unpoisoned.
  for (size_t i = shadow_start; i < shadow_start + shadow_alloc_size; ++i)
    ASSERT_EQ(kHeapAddressableMarker, TestShadow::shadow_[i]);
}

TEST_F(BlockHeapManagerTest, QuarantineIsShared) {
  const size_t kAllocSize = 100;
  const size_t real_alloc_size = GetAllocSize(kAllocSize);
  ScopedHeap heap_1(&heap_manager_);
  ScopedHeap heap_2(&heap_manager_);

  ASSERT_EQ(heap_1.GetQuarantine(), heap_2.GetQuarantine());

  common::AsanParameters parameters = heap_manager_.parameters();
  parameters.quarantine_size = real_alloc_size * 4;
  heap_manager_.set_parameters(parameters);

  void* heap_1_mem1 = heap_1.Allocate(kAllocSize);
  ASSERT_NE(reinterpret_cast<void*>(NULL), heap_1_mem1);
  void* heap_1_mem2 = heap_1.Allocate(kAllocSize);
  ASSERT_NE(reinterpret_cast<void*>(NULL), heap_1_mem2);
  void* heap_2_mem1 = heap_2.Allocate(kAllocSize);
  ASSERT_NE(reinterpret_cast<void*>(NULL), heap_2_mem1);
  void* heap_2_mem2 = heap_2.Allocate(kAllocSize);
  ASSERT_NE(reinterpret_cast<void*>(NULL), heap_2_mem2);

  EXPECT_TRUE(heap_1.Free(heap_1_mem1));
  EXPECT_TRUE(heap_1.Free(heap_1_mem2));
  EXPECT_TRUE(heap_2.Free(heap_2_mem1));
  EXPECT_TRUE(heap_2.Free(heap_2_mem2));

  EXPECT_TRUE(heap_1.InQuarantine(heap_1_mem1));
  EXPECT_TRUE(heap_1.InQuarantine(heap_1_mem2));
  EXPECT_TRUE(heap_2.InQuarantine(heap_2_mem1));
  EXPECT_TRUE(heap_2.InQuarantine(heap_2_mem2));

  BlockQuarantineInterface* quarantine = heap_1.GetQuarantine();
  EXPECT_EQ(4, quarantine->GetCount());
  heap_2.ReleaseHeap();
  EXPECT_EQ(2, quarantine->GetCount());
  heap_1.ReleaseHeap();
  EXPECT_EQ(0, quarantine->GetCount());
}

TEST_F(BlockHeapManagerTest, AllocZeroBytes) {
  ScopedHeap heap(&heap_manager_);
  void* mem1 = heap.Allocate(0);
  ASSERT_NE(reinterpret_cast<void*>(NULL), mem1);
  void* mem2 = heap.Allocate(0);
  ASSERT_NE(reinterpret_cast<void*>(NULL), mem2);
  ASSERT_NE(mem1, mem2);
  ASSERT_TRUE(heap.Free(mem1));
  ASSERT_TRUE(heap.Free(mem2));
}

TEST_F(BlockHeapManagerTest, Size) {
  const size_t kMaxAllocSize = 134584;
  ScopedHeap heap(&heap_manager_);
  for (size_t size = 10; size < kMaxAllocSize; size = size * 5 + 123) {
    void* mem = heap.Allocate(size);
    ASSERT_NE(reinterpret_cast<void*>(NULL), mem);
    ASSERT_EQ(size, heap_manager_.Size(heap.Id(), mem));
    ASSERT_TRUE(heap.Free(mem));
  }
}

TEST_F(BlockHeapManagerTest, AllocsAccessibility) {
  const size_t kMaxAllocSize = 134584;
  ScopedHeap heap(&heap_manager_);
  // Ensure that the quarantine is large enough to keep the allocated blocks in
  // this test.
  common::AsanParameters parameters = heap_manager_.parameters();
  parameters.quarantine_size = kMaxAllocSize * 2;
  heap_manager_.set_parameters(parameters);
  for (size_t size = 10; size < kMaxAllocSize; size = size * 5 + 123) {
    // Do an alloc/free and test that access is correctly managed.
    void* mem = heap.Allocate(size);
    ASSERT_NE(reinterpret_cast<void*>(NULL), mem);
    ASSERT_NO_FATAL_FAILURE(VerifyAllocAccess(mem, size));
    ASSERT_TRUE(heap.Free(mem));
    ASSERT_NO_FATAL_FAILURE(VerifyFreedAccess(mem, size));
  }
}

TEST_F(BlockHeapManagerTest, LockUnlock) {
  ScopedHeap heap(&heap_manager_);
  // We can't really test these, aside from not crashing.
  ASSERT_NO_FATAL_FAILURE(heap_manager_.Lock(heap.Id()));
  ASSERT_NO_FATAL_FAILURE(heap_manager_.Unlock(heap.Id()));
}

TEST_F(BlockHeapManagerTest, CaptureTID) {
  const size_t kAllocSize = 13;
  ScopedHeap heap(&heap_manager_);
  // Ensure that the quarantine is large enough to keep this block.
  common::AsanParameters parameters = heap_manager_.parameters();
  parameters.quarantine_size = GetAllocSize(kAllocSize);
  heap_manager_.set_parameters(parameters);
  uint8* mem = static_cast<uint8*>(heap.Allocate(kAllocSize));
  ASSERT_TRUE(heap.Free(mem));
  EXPECT_EQ(QUARANTINED_BLOCK,
            static_cast<BlockState>(BlockGetHeaderFromBody(mem)->state));

  BlockHeader* header = BlockGetHeaderFromBody(mem);
  ASSERT_NE(reinterpret_cast<BlockHeader*>(NULL), header);
  BlockInfo block_info = {};
  EXPECT_TRUE(BlockInfoFromMemory(header, &block_info));
  EXPECT_NE(reinterpret_cast<BlockTrailer*>(NULL), block_info.trailer);

  EXPECT_EQ(block_info.trailer->alloc_tid, ::GetCurrentThreadId());
  EXPECT_EQ(block_info.trailer->free_tid, ::GetCurrentThreadId());
}

TEST_F(BlockHeapManagerTest, QuarantineDoesntAlterBlockContents) {
  const size_t kAllocSize = 13;
  ScopedHeap heap(&heap_manager_);
  // Ensure that the quarantine is large enough to keep this block.
  common::AsanParameters parameters = heap_manager_.parameters();
  parameters.quarantine_size = GetAllocSize(kAllocSize);
  heap_manager_.set_parameters(parameters);
  void* mem = heap.Allocate(kAllocSize);
  ASSERT_NE(reinterpret_cast<void*>(NULL), mem);
  base::RandBytes(mem, kAllocSize);

  unsigned char sha1_before[base::kSHA1Length] = {};
  base::SHA1HashBytes(reinterpret_cast<unsigned char*>(mem),
                      kAllocSize,
                      sha1_before);

  BlockHeader* header = BlockGetHeaderFromBody(mem);

  ASSERT_TRUE(heap.Free(mem));
  EXPECT_EQ(QUARANTINED_BLOCK, static_cast<BlockState>(header->state));

  unsigned char sha1_after[base::kSHA1Length] = {};
  base::SHA1HashBytes(reinterpret_cast<unsigned char*>(mem),
                      kAllocSize,
                      sha1_after);

  EXPECT_EQ(0, memcmp(sha1_before, sha1_after, base::kSHA1Length));
}

TEST_F(BlockHeapManagerTest, SetTrailerPaddingSize) {
  const size_t kAllocSize = 13;
  ScopedHeap heap(&heap_manager_);
  // Ensure that the quarantine is large enough to keep this block with the
  // extra padding.
  common::AsanParameters parameters = heap_manager_.parameters();
  parameters.quarantine_size = GetAllocSize(kAllocSize) * 5;
  heap_manager_.set_parameters(parameters);
  size_t original_alloc_size = GetAllocSize(kAllocSize);
  common::AsanParameters original_parameter = heap_manager_.parameters();

  for (size_t padding = 0; padding < 16; ++padding) {
    common::AsanParameters new_parameter = original_parameter;
    new_parameter.trailer_padding_size =
        original_parameter.trailer_padding_size + padding;
    heap_manager_.set_parameters(new_parameter);
    size_t augmented_alloc_size = GetAllocSize(kAllocSize);
    EXPECT_GE(augmented_alloc_size, original_alloc_size);

    void* mem = heap.Allocate(kAllocSize);
    ASSERT_TRUE(mem != NULL);

    size_t offset = kAllocSize;
    for (; offset < augmented_alloc_size - sizeof(BlockHeader);
         ++offset) {
      EXPECT_FALSE(Shadow::IsAccessible(
          reinterpret_cast<const uint8*>(mem) + offset));
    }
    ASSERT_TRUE(heap.Free(mem));
  }
  heap_manager_.set_parameters(original_parameter);
}

TEST_F(BlockHeapManagerTest, BlockChecksumUpdatedWhenEnterQuarantine) {
  const size_t kAllocSize = 100;
  size_t real_alloc_size = GetAllocSize(kAllocSize);
  ScopedHeap heap(&heap_manager_);

  common::AsanParameters parameters = heap_manager_.parameters();
  parameters.quarantine_size = real_alloc_size;
  heap_manager_.set_parameters(parameters);

  void* mem = heap.Allocate(kAllocSize);
  ASSERT_NE(reinterpret_cast<void*>(NULL), mem);
  BlockInfo block_info = {};
  EXPECT_TRUE(Shadow::BlockInfoFromShadow(mem, &block_info));
  EXPECT_TRUE(BlockChecksumIsValid(block_info));
  heap.Free(mem);
  EXPECT_TRUE(BlockChecksumIsValid(block_info));
  ASSERT_TRUE(heap.InQuarantine(mem));
}

static const size_t kChecksumRepeatCount = 10;

TEST_F(BlockHeapManagerTest, CorruptAsEntersQuarantine) {
  const size_t kAllocSize = 100;
  common::AsanParameters parameters = heap_manager_.parameters();
  parameters.quarantine_size = GetAllocSize(kAllocSize);
  heap_manager_.set_parameters(parameters);

  ScopedHeap heap(&heap_manager_);
  // This can fail because of a checksum collision. However, we run it a
  // handful of times to keep the chances as small as possible.
  for (size_t i = 0; i < kChecksumRepeatCount; ++i) {
    heap.FlushQuarantine();
    void* mem = heap.Allocate(kAllocSize);
    ASSERT_NE(static_cast<void*>(NULL), mem);
    reinterpret_cast<int*>(mem)[-1] = rand();
    EXPECT_TRUE(heap.Free(mem));

    // Try again for all but the last attempt if this appears to have failed.
    if (errors_.empty() && i + 1 < kChecksumRepeatCount)
      continue;

    ASSERT_EQ(1u, errors_.size());
    ASSERT_EQ(CORRUPT_BLOCK, errors_[0].error_type);
    ASSERT_EQ(mem, errors_[0].location);

    break;
  }
}

TEST_F(BlockHeapManagerTest, CorruptAsExitsQuarantine) {
  const size_t kAllocSize = 100;
  common::AsanParameters parameters = heap_manager_.parameters();
  parameters.quarantine_size = GetAllocSize(kAllocSize);
  heap_manager_.set_parameters(parameters);

  ScopedHeap heap(&heap_manager_);
  // This can fail because of a checksum collision. However, we run it a
  // handful of times to keep the chances as small as possible.
  for (size_t i = 0; i < kChecksumRepeatCount; ++i) {
    heap.FlushQuarantine();
    void* mem = heap.Allocate(kAllocSize);
    ASSERT_NE(static_cast<void*>(NULL), mem);
    EXPECT_TRUE(heap.Free(mem));
    EXPECT_TRUE(errors_.empty());

    // Change some of the block content and then flush the quarantine. The block
    // hash should be invalid and it should cause an error to be fired.
    reinterpret_cast<int32*>(mem)[0] = rand();
    heap.FlushQuarantine();

    // Try again for all but the last attempt if this appears to have failed.
    if (errors_.empty() && i + 1 < kChecksumRepeatCount)
      continue;

    EXPECT_EQ(1u, errors_.size());
    EXPECT_EQ(CORRUPT_BLOCK, errors_[0].error_type);
    EXPECT_EQ(
        reinterpret_cast<BlockHeader*>(mem) - 1,
        reinterpret_cast<BlockHeader*>(errors_[0].location));

    break;
  }
}

TEST_F(BlockHeapManagerTest, CorruptAsExitsQuarantineOnHeapDestroy) {
  const size_t kAllocSize = 100;
  common::AsanParameters parameters = heap_manager_.parameters();
  parameters.quarantine_size = GetAllocSize(kAllocSize);
  heap_manager_.set_parameters(parameters);

  // This can fail because of a checksum collision. However, we run it a
  // handful of times to keep the chances as small as possible.
  for (size_t i = 0; i < kChecksumRepeatCount; ++i) {
    void* mem = NULL;
    {
      ScopedHeap heap(&heap_manager_);
      heap.FlushQuarantine();
      mem = heap.Allocate(kAllocSize);
      ASSERT_NE(static_cast<void*>(NULL), mem);
      EXPECT_TRUE(heap.Free(mem));
      EXPECT_TRUE(errors_.empty());

      // Change some of the block content to invalidate the block's hash.
      reinterpret_cast<int32*>(mem)[0] = rand();
    }

    // The destructor of |heap| should be called and all the quarantined blocks
    // belonging to this heap should be freed, which should trigger an error as
    // the block is now corrupt.

    // Try again for all but the last attempt if this appears to have failed.
    if (errors_.empty() && i + 1 < kChecksumRepeatCount)
      continue;

    EXPECT_EQ(1u, errors_.size());
    EXPECT_EQ(CORRUPT_BLOCK, errors_[0].error_type);
    EXPECT_EQ(reinterpret_cast<BlockHeader*>(mem) - 1,
              reinterpret_cast<BlockHeader*>(errors_[0].location));

    break;
  }
}

TEST_F(BlockHeapManagerTest, CorruptHeapOnTrimQuarantine) {
  const size_t kAllocSize = 100;
  common::AsanParameters parameters = heap_manager_.parameters();
  parameters.quarantine_size = GetAllocSize(kAllocSize);
  heap_manager_.set_parameters(parameters);

  // This can fail because of a checksum collision. However, we run it a
  // handful of times to keep the chances as small as possible.
  for (size_t i = 0; i < kChecksumRepeatCount; ++i) {
    void* mem = NULL;
    {
      ScopedHeap heap(&heap_manager_);
      heap.FlushQuarantine();
      mem = heap.Allocate(kAllocSize);
      ASSERT_NE(static_cast<void*>(NULL), mem);
      EXPECT_TRUE(heap.Free(mem));
      EXPECT_TRUE(errors_.empty());

      // Change some of the block content to invalidate the block's hash.
      reinterpret_cast<int32*>(mem)[0] = rand();
    }

    // The destructor of |heap| should be called and all the quarantined blocks
    // belonging to this heap should be freed, which should trigger an error as
    // the block is now corrupt.

    // Try again for all but the last attempt if this appears to have failed.
    if (errors_.empty() && i + 1 < kChecksumRepeatCount)
      continue;

    EXPECT_EQ(1u, errors_.size());
    EXPECT_EQ(CORRUPT_BLOCK, errors_[0].error_type);
    EXPECT_EQ(reinterpret_cast<BlockHeader*>(mem) - 1,
              reinterpret_cast<BlockHeader*>(errors_[0].location));

    break;
  }
}

TEST_F(BlockHeapManagerTest, DoubleFree) {
  const size_t kAllocSize = 100;
  common::AsanParameters parameters = heap_manager_.parameters();
  parameters.quarantine_size = GetAllocSize(kAllocSize);
  heap_manager_.set_parameters(parameters);

  ScopedHeap heap(&heap_manager_);
  void* mem = heap.Allocate(kAllocSize);
  ASSERT_NE(static_cast<void*>(NULL), mem);
  EXPECT_TRUE(heap.Free(mem));
  EXPECT_FALSE(heap.Free(mem));

  EXPECT_EQ(1u, errors_.size());
  EXPECT_EQ(DOUBLE_FREE, errors_[0].error_type);
  EXPECT_EQ(mem, errors_[0].location);
}

TEST_F(BlockHeapManagerTest, SubsampledAllocationGuards) {
  common::AsanParameters parameters = heap_manager_.parameters();
  parameters.allocation_guard_rate = 0.5;
  heap_manager_.set_parameters(parameters);
  ScopedHeap heap(&heap_manager_);

  size_t guarded_allocations = 0;
  size_t unguarded_allocations = 0;

  // Make a handful of allocations.
  const size_t kAllocationCount = 10000;
  const size_t kAllocationSizes[] = {
      1, 2, 4, 8, 14, 30, 128, 237, 500, 1000, 2036 };
  std::vector<void*> allocations;
  for (size_t i = 0; i < kAllocationCount; ++i) {
    size_t alloc_size = kAllocationSizes[i % arraysize(kAllocationSizes)];
    void* alloc = heap.Allocate(alloc_size);
    EXPECT_NE(reinterpret_cast<void*>(NULL), alloc);

    // Determine if the allocation has guards or not.
    BlockHeader* header = BlockGetHeaderFromBody(alloc);
    if (header == NULL) {
      ++unguarded_allocations;
    } else {
      ++guarded_allocations;
    }

    // Delete half of the allocations immediately, and keep half of them
    // around for longer. This puts more of a stress test on the quarantine
    // itself.
    if (base::RandDouble() < 0.5) {
      EXPECT_TRUE(heap.Free(alloc));
    } else {
      allocations.push_back(alloc);
    }
  }

  // Free the outstanding allocations.
  for (size_t i = 0; i < allocations.size(); ++i)
    EXPECT_TRUE(heap.Free(allocations[i]));

  // Clear the quarantine. This should free up the remaining instrumented
  // but quarantined blocks.
  EXPECT_NO_FATAL_FAILURE(heap.FlushQuarantine());

  // This could theoretically fail, but that would imply an extremely bad
  // implementation of the underlying random number generator. There are 10000
  // allocations. Since this is effectively a fair coin toss we expect a
  // standard deviation of 0.5 * sqrt(10000) = 50. A 10% margin is
  // 1000 / 50 = 20 standard deviations. For |z| > 20, the p-value is 5.5e-89,
  // or 89 nines of confidence. That should keep any flake largely at bay.
  // Thus, if this fails it's pretty much certain the implementation is at
  // fault.
  EXPECT_LT(4 * kAllocationCount / 10, guarded_allocations);
  EXPECT_GT(6 * kAllocationCount / 10, guarded_allocations);
}

// Ensures that the ZebraBlockHeap overrides the provided heap.
TEST_F(BlockHeapManagerTest, ZebraHeapIdInTrailerAfterAllocation) {
  EnableTestZebraBlockHeap();
  ScopedHeap heap(&heap_manager_);
  const size_t kAllocSize = 0x100;
  void* alloc = heap.Allocate(kAllocSize);
  EXPECT_NE(reinterpret_cast<void*>(NULL), alloc);
  ASSERT_NO_FATAL_FAILURE(VerifyAllocAccess(alloc, kAllocSize));

  // Get the heap_id from the block trailer.
  BlockInfo block_info = {};
  BlockHeader* header = BlockGetHeaderFromBody(alloc);
  EXPECT_TRUE(Shadow::BlockInfoFromShadow(header, &block_info));
  // The heap_id stored in the block trailer should match the ZebraBlockHeap id.
  EXPECT_EQ(reinterpret_cast<HeapId>(test_zebra_block_heap_),
      block_info.trailer->heap_id);
  EXPECT_TRUE(heap.Free(alloc));
}

// Ensures that the provided heap is used when the ZebraBlockHeap cannot handle
// the allocation.
TEST_F(BlockHeapManagerTest, DefaultHeapIdInTrailerWhenZebraHeapIsFull) {
  EnableTestZebraBlockHeap();
  ScopedHeap heap(&heap_manager_);
  const size_t kAllocSize = 0x100;
  // Refuse allocations on the ZebraBlockHeap.
  test_zebra_block_heap_->set_refuse_allocations(true);

  void* alloc = heap.Allocate(kAllocSize);
  EXPECT_NE(reinterpret_cast<void*>(NULL), alloc);
  ASSERT_NO_FATAL_FAILURE(VerifyAllocAccess(alloc, kAllocSize));

  // Get the heap_id from the block trailer.
  BlockInfo block_info = {};
  BlockHeader* header = BlockGetHeaderFromBody(alloc);
  EXPECT_TRUE(Shadow::BlockInfoFromShadow(header, &block_info));
  // The heap_id stored in the block trailer match the provided heap.
  EXPECT_EQ(heap.Id(), block_info.trailer->heap_id);
  EXPECT_TRUE(heap.Free(alloc));
}

TEST_F(BlockHeapManagerTest, AllocStress) {
  EnableTestZebraBlockHeap();
  ScopedHeap heap(&heap_manager_);
  for (size_t i = 0; i < 1000; ++i) {
    const size_t kAllocSize = 0x100 + i;
    void* alloc = heap.Allocate(kAllocSize);
    EXPECT_NE(reinterpret_cast<void*>(NULL), alloc);
    ASSERT_NO_FATAL_FAILURE(VerifyAllocAccess(alloc, kAllocSize));
    // Free should succeed, even if the block is quarantined.
    EXPECT_TRUE(heap.Free(alloc));
  }
}

// The BlockHeapManager correctly quarantines the memory after free.
TEST_F(BlockHeapManagerTest, QuarantinedAfterFree) {
  EnableTestZebraBlockHeap();
  ScopedHeap heap(&heap_manager_);
  // Always quarantine if possible.
  test_zebra_block_heap_->set_quarantine_ratio(1.0);

  const size_t kAllocSize = 0x100;
  void* alloc = heap.Allocate(kAllocSize);
  EXPECT_NE(reinterpret_cast<void*>(NULL), alloc);
  ASSERT_NO_FATAL_FAILURE(VerifyAllocAccess(alloc, kAllocSize));
  // Free should succeed, even if the block is quarantined.
  EXPECT_TRUE(heap.Free(alloc));
  // The block should be quarantined and poisoned.
  ASSERT_NO_FATAL_FAILURE(VerifyFreedAccess(alloc, kAllocSize));
  BlockInfo block_info = {};
  BlockHeader* header = BlockGetHeaderFromBody(alloc);
  EXPECT_TRUE(Shadow::BlockInfoFromShadow(header, &block_info));
  EXPECT_EQ(QUARANTINED_BLOCK, block_info.header->state);
}

// The BlockHeapManager correctly unpoison the memory after free if the
// quarantine is full.
TEST_F(BlockHeapManagerTest, NotQuarantinedAfterFree) {
  EnableTestZebraBlockHeap();
  ScopedHeap heap(&heap_manager_);
  const size_t kAllocSize = 0xFF;
  void* alloc = heap.Allocate(kAllocSize);
  EXPECT_NE(reinterpret_cast<void*>(NULL), alloc);
  ASSERT_NO_FATAL_FAILURE(VerifyAllocAccess(alloc, kAllocSize));

  // Force the ZebraBlockHeap quarantine to refuse new blocks, so the block
  // should be freed.
  test_zebra_block_heap_->set_refuse_push(true);
  BlockInfo block_info = {};
  BlockHeader* header = BlockGetHeaderFromBody(alloc);
  EXPECT_TRUE(Shadow::BlockInfoFromShadow(header, &block_info));
  EXPECT_TRUE(heap.Free(alloc));
  // Since it was refused from the quarantine it should be marked as freed.
  EXPECT_EQ(FREED_BLOCK, block_info.header->state);
}

// set_parameters should set the zebra_block_heap_quarantine_ratio flag
// correctly.
TEST_F(BlockHeapManagerTest, set_parametersSetsZebraBlockHeapQuarantineRatio) {
  EnableTestZebraBlockHeap();
  float new_ratio = 1.0f / 8;
  common::AsanParameters params = heap_manager_.parameters();
  params.zebra_block_heap_quarantine_ratio = new_ratio;
  heap_manager_.set_parameters(params);
  EXPECT_EQ(new_ratio, test_zebra_block_heap_->quarantine_ratio());
}

// Test for double free errors on ZebraBlockHeap allocations.
TEST_F(BlockHeapManagerTest, DoubleFreeOnZebraHeap) {
  EnableTestZebraBlockHeap();
  ScopedHeap heap(&heap_manager_);
  test_zebra_block_heap_->set_quarantine_ratio(1.0);

  const size_t kAllocSize = 0xFF;
  void* alloc = heap.Allocate(kAllocSize);
  EXPECT_NE(reinterpret_cast<void*>(NULL), alloc);
  ASSERT_NO_FATAL_FAILURE(VerifyAllocAccess(alloc, kAllocSize));

  EXPECT_TRUE(heap.Free(alloc));
  EXPECT_FALSE(heap.Free(alloc));

  EXPECT_EQ(1u, errors_.size());
  EXPECT_EQ(DOUBLE_FREE, errors_[0].error_type);
  EXPECT_EQ(alloc, errors_[0].location);
}

}  // namespace heap_managers
}  // namespace asan
}  // namespace agent
