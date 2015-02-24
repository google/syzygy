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
#include "base/debug/alias.h"
#include "base/synchronization/condition_variable.h"
#include "base/synchronization/lock.h"
#include "base/threading/simple_thread.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/agent/asan/asan_rtl_impl.h"
#include "syzygy/agent/asan/asan_runtime.h"
#include "syzygy/agent/asan/block.h"
#include "syzygy/agent/asan/heap.h"
#include "syzygy/agent/asan/page_protection_helpers.h"
#include "syzygy/agent/asan/unittest_util.h"
#include "syzygy/agent/asan/heaps/ctmalloc_heap.h"
#include "syzygy/agent/asan/heaps/internal_heap.h"
#include "syzygy/agent/asan/heaps/large_block_heap.h"
#include "syzygy/agent/asan/heaps/simple_block_heap.h"
#include "syzygy/agent/asan/heaps/win_heap.h"
#include "syzygy/agent/asan/heaps/zebra_block_heap.h"
#include "syzygy/agent/asan/memory_notifiers/shadow_memory_notifier.h"

namespace agent {
namespace asan {
namespace heap_managers {

namespace {

using heaps::ZebraBlockHeap;
using testing::IsAccessible;
using testing::IsNotAccessible;

typedef BlockHeapManager::HeapId HeapId;

testing::DummyHeap dummy_heap;
agent::asan::memory_notifiers::ShadowMemoryNotifier shadow_notifier;

// A fake ZebraBlockHeap to simplify unit testing.
// Wrapper with switches to enable/disable the quarantine and accept/refuse
// allocations.
class TestZebraBlockHeap : public heaps::ZebraBlockHeap {
 public:
  using ZebraBlockHeap::set_quarantine_ratio;
  using ZebraBlockHeap::quarantine_ratio;
  using ZebraBlockHeap::slab_count_;

  // Constructor.
  TestZebraBlockHeap()
      : ZebraBlockHeap(1024 * 1024, &shadow_notifier, &dummy_heap) {
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
      return nullptr;
    return ZebraBlockHeap::AllocateBlock(size,
                                         min_left_redzone_size,
                                         min_right_redzone_size,
                                         layout);
  }

  // Wrapper that allows easily disabling the insertion of new blocks in the
  // quarantine.
  virtual bool Push(const CompactBlockInfo& info) OVERRIDE {
    if (refuse_push_)
      return false;
    return ZebraBlockHeap::Push(info);
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
  using BlockHeapManager::HeapQuarantinePair;

  using BlockHeapManager::FreePotentiallyCorruptBlock;
  using BlockHeapManager::GetHeapId;
  using BlockHeapManager::GetHeapFromId;
  using BlockHeapManager::GetHeapTypeUnlocked;
  using BlockHeapManager::GetQuarantineFromId;
  using BlockHeapManager::HeapMetadata;
  using BlockHeapManager::HeapQuarantineMap;
  using BlockHeapManager::IsValidHeapIdUnlocked;
  using BlockHeapManager::SetHeapErrorCallback;
  using BlockHeapManager::ShardedBlockQuarantine;
  using BlockHeapManager::TrimQuarantine;

  using BlockHeapManager::allocation_filter_flag_tls_;
  using BlockHeapManager::heaps_;
  using BlockHeapManager::large_block_heap_id_;
  using BlockHeapManager::locked_heaps_;
  using BlockHeapManager::parameters_;
  using BlockHeapManager::rate_targeted_heaps_;
  using BlockHeapManager::rate_targeted_heaps_count_;
  using BlockHeapManager::targeted_heaps_info_;
  using BlockHeapManager::zebra_block_heap_;
  using BlockHeapManager::zebra_block_heap_id_;

  using BlockHeapManager::kRateTargetedHeapCount;
  using BlockHeapManager::kDefaultRateTargetedHeapsMinBlockSize;

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
  explicit TestBlockHeapManager(StackCaptureCache* stack_cache)
      : BlockHeapManager(stack_cache) {
  }

  // Removes the heap with the given ID.
  void RemoveHeapById(HeapId heap_id) {
    if (heap_id == 0)
      return;
    BlockHeapInterface* heap = GetHeapFromId(heap_id);
    delete heap;
    EXPECT_EQ(1, heaps_.erase(heap));
  }

  // Wrapper for the set_parameters method. This also takes care of
  // reinitializing the variables that are usually initialized in the
  // constructor of a BlockHeapManager.
  void SetParameters(const ::common::AsanParameters& params) {
    bool ctmalloc_changed = false;

    // Set the parameters.
    {
      base::AutoLock lock(lock_);
      ctmalloc_changed = params.enable_ctmalloc != parameters_.enable_ctmalloc;
      parameters_ = params;
    }

    // Reinitialize the internal and special heaps if necessary.
    if (ctmalloc_changed) {
      // Since the zebra and large block heaps use the internal heap they
      // must also be reset.
      RemoveHeapById(large_block_heap_id_);
      RemoveHeapById(zebra_block_heap_id_);
      large_block_heap_id_ = 0;
      zebra_block_heap_id_ = 0;
      for (size_t i = 0; i < kRateTargetedHeapCount; ++i) {
        RemoveHeapById(rate_targeted_heaps_[i]);
        rate_targeted_heaps_[i] = 0;
        rate_targeted_heaps_count_[i] = 0;
      }

      internal_heap_.reset();
      internal_win_heap_.reset();
      InitInternalHeap();
      InitRateTargetedHeaps();
    }

    PropagateParameters();

    // Reinitialize the process heap if necessary.
    if (ctmalloc_changed) {
      EXPECT_EQ(1, underlying_heaps_map_.erase(process_heap_));
      EXPECT_EQ(1, heaps_.erase(process_heap_));
      delete process_heap_;
      process_heap_ = nullptr;
      if (process_heap_underlying_heap_) {
        delete process_heap_underlying_heap_;
        process_heap_underlying_heap_ = nullptr;
      }
      InitProcessHeap();
    }
  }
};

// A derived class to expose protected members for unit-testing.
class TestShadow : public Shadow {
 public:
  using Shadow::kShadowSize;
  using Shadow::shadow_;
};

// A derived class to expose protected members for unit-testing.
class TestAsanRuntime : public agent::asan::AsanRuntime {
 public:
  using agent::asan::AsanRuntime::heap_manager_;
};

// A utility class for manipulating a heap. This automatically deletes the heap
// and its content in the destructor and provides some utility functions.
class ScopedHeap {
 public:
  typedef TestBlockHeapManager::TestQuarantine TestQuarantine;

  // Constructor.
  explicit ScopedHeap(TestBlockHeapManager* heap_manager)
      : heap_manager_(heap_manager) {
    heap_id_ = heap_manager->CreateHeap();
    EXPECT_NE(0u, heap_id_);
  }

  // Destructor. Destroy the heap, this will flush its quarantine and delete all
  // the structures associated with this heap.
  ~ScopedHeap() {
    ReleaseHeap();
  }

  void ReleaseHeap() {
    if (heap_id_ != 0) {
      EXPECT_TRUE(heap_manager_->DestroyHeap(heap_id_));
      heap_id_ = 0;
    }
  }

  // Retrieves the quarantine associated with this heap.
  BlockQuarantineInterface* GetQuarantine() {
    return heap_manager_->GetQuarantineFromId(heap_id_);
  }

  // Allocate a block of @p size bytes.
  void* Allocate(size_t size) {
    return heap_manager_->Allocate(heap_id_, size);
  }

  // Free the block @p mem.
  bool Free(void* mem) {
    return heap_manager_->Free(heap_id_, mem);
  }

  // Flush the quarantine of this heap.
  void FlushQuarantine() {
    BlockQuarantineInterface* quarantine =  GetQuarantine();
    EXPECT_NE(static_cast<BlockQuarantineInterface*>(nullptr),
              quarantine);
    BlockQuarantineInterface::ObjectVector blocks_to_free;
    quarantine->Empty(&blocks_to_free);
    BlockQuarantineInterface::ObjectVector::iterator iter_block =
        blocks_to_free.begin();
    for (; iter_block != blocks_to_free.end(); ++iter_block) {
      const CompactBlockInfo& compact = *iter_block;
      BlockInfo expanded = {};
      ConvertBlockInfo(compact, &expanded);
      CHECK(heap_manager_->FreePotentiallyCorruptBlock(&expanded));
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
    EXPECT_NE(static_cast<TestQuarantine*>(nullptr), test_quarantine);
    // Search through all of the shards.
    for (size_t i = 0; i < test_quarantine->kShardingFactor; ++i) {
      // Search through all blocks in each shard.
      TestQuarantine::Node* current_node = test_quarantine->heads_[i];
      while (current_node != nullptr) {
        const uint8* body = current_node->object.block +
            current_node->object.header_size;
        if (body == mem) {
          const BlockHeader* header = reinterpret_cast<BlockHeader*>(
              current_node->object.block);
          EXPECT_EQ(QUARANTINED_BLOCK, header->state);
          return true;
        }
        current_node = current_node->next;
      }
    }

    return false;
  }

  // Returns the heap supported features.
  uint32 GetHeapFeatures() {
    return heap_manager_->GetHeapFromId(heap_id_)->GetHeapFeatures();
  }

 private:
  // The heap manager owning the underlying heap.
  TestBlockHeapManager* heap_manager_;

  // The underlying heap.
  HeapId heap_id_;
};

// A value-parameterized test class for testing the BlockHeapManager class.
//
// The parameter value is used to enable/disable the usage of the CTMalloc heap.
class BlockHeapManagerTest
    : public testing::TestWithAsanRuntime,
      public testing::WithParamInterface<bool> {
 public:
  typedef TestBlockHeapManager::ShardedBlockQuarantine ShardedBlockQuarantine;
  typedef testing::TestWithAsanRuntime Super;

  BlockHeapManagerTest()
      : TestWithAsanRuntime(&test_runtime_), heap_manager_(),
        test_zebra_block_heap_(nullptr) {
  }

  virtual void SetUp() OVERRIDE {
    Super::SetUp();
    heap_manager_ = reinterpret_cast<TestBlockHeapManager*>(
        test_runtime_.heap_manager_.get());

    // Set the error callback that the manager will use.
    heap_manager_->SetHeapErrorCallback(
        base::Bind(&BlockHeapManagerTest::OnHeapError, base::Unretained(this)));

    ::common::AsanParameters params;
    ::common::SetDefaultAsanParameters(&params);
    params.enable_ctmalloc = GetParam();
    heap_manager_->SetParameters(params);
  }

  virtual void TearDown() OVERRIDE {
    heap_manager_ = nullptr;
    Super::TearDown();
  }

  void OnHeapError(AsanErrorInfo* error) {
    errors_.push_back(*error);
  }

  // Calculates the Asan size for an allocation of @p user_size bytes.
  size_t GetAllocSize(size_t user_size) {
    BlockLayout layout = {};
    EXPECT_TRUE(BlockPlanLayout(kShadowRatio, kShadowRatio, user_size, 0,
        heap_manager_->parameters().trailer_padding_size + sizeof(BlockTrailer),
        &layout));
    return layout.block_size;
  }

  void EnableTestZebraBlockHeap() {
    // Erase previous ZebraBlockHeap.
    if (heap_manager_->zebra_block_heap_ != 0) {
      heap_manager_->heaps_.erase(heap_manager_->zebra_block_heap_);
      delete heap_manager_->zebra_block_heap_;
    }
    // Plug a mock ZebraBlockHeap by default disabled.
    test_zebra_block_heap_ = new TestZebraBlockHeap();
    heap_manager_->zebra_block_heap_ = test_zebra_block_heap_;
    TestBlockHeapManager::HeapMetadata heap_metadata =
      { test_zebra_block_heap_, false };
    auto result = heap_manager_->heaps_.insert(std::make_pair(
        test_zebra_block_heap_, heap_metadata));
    heap_manager_->zebra_block_heap_id_ = heap_manager_->GetHeapId(result);

    // Turn on the zebra_block_heap_enabled flag.
    ::common::AsanParameters params = heap_manager_->parameters();
    params.enable_zebra_block_heap = true;
    heap_manager_->set_parameters(params);
  }

  void EnableLargeBlockHeap(size_t large_allocation_threshold) {
    ::common::AsanParameters params = heap_manager_->parameters();
    params.enable_large_block_heap = true;
    params.large_allocation_threshold = large_allocation_threshold;
    heap_manager_->set_parameters(params);
    CHECK_NE(0u, heap_manager_->large_block_heap_id_);
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
  // The heap manager used in these tests.
  TestBlockHeapManager* heap_manager_;

  // Info about the last errors reported.
  std::vector<AsanErrorInfo> errors_;

  // The mock ZebraBlockHeap used in the tests.
  TestZebraBlockHeap* test_zebra_block_heap_;

  // The runtime used by those tests.
  TestAsanRuntime test_runtime_;
};

}  // namespace

// Instantiate the test cases.
INSTANTIATE_TEST_CASE_P(BlockHeapManagerTests,
                        BlockHeapManagerTest,
                        ::testing::Bool());

TEST_P(BlockHeapManagerTest, AllocAndFree) {
  const size_t kAllocSize = 17;
  HeapId heap_id = heap_manager_->CreateHeap();
  EXPECT_NE(0u, heap_id);
  void* alloc = heap_manager_->Allocate(heap_id, kAllocSize);
  EXPECT_NE(static_cast<void*>(nullptr), alloc);
  EXPECT_LE(kAllocSize, heap_manager_->Size(heap_id, alloc));
  EXPECT_TRUE(heap_manager_->Free(heap_id, alloc));
  EXPECT_TRUE(heap_manager_->DestroyHeap(heap_id));
}

TEST_P(BlockHeapManagerTest, FreeNullPointer) {
  HeapId heap_id = heap_manager_->CreateHeap();
  EXPECT_NE(0u, heap_id);
  EXPECT_TRUE(heap_manager_->Free(heap_id, static_cast<void*>(nullptr)));
  EXPECT_TRUE(heap_manager_->DestroyHeap(heap_id));
}

TEST_P(BlockHeapManagerTest, FreeUnguardedAlloc) {
  const size_t kAllocSize = 100;
  ::common::AsanParameters params = heap_manager_->parameters();
  params.allocation_guard_rate = 0.0;
  heap_manager_->set_parameters(params);

  ScopedHeap heap(heap_manager_);

  void* heap_alloc = heap.Allocate(kAllocSize);
  EXPECT_NE(static_cast<void*>(nullptr), heap_alloc);

  void* process_heap_alloc = ::HeapAlloc(::GetProcessHeap(), 0, kAllocSize);
  EXPECT_NE(static_cast<void*>(nullptr), process_heap_alloc);

  BlockHeapInterface* process_heap = heap_manager_->GetHeapFromId(
      heap_manager_->process_heap());
  void* process_heap_wrapper_alloc = process_heap->Allocate(kAllocSize);
  EXPECT_NE(static_cast<void*>(nullptr), process_heap_wrapper_alloc);

  EXPECT_TRUE(heap_manager_->Free(heap.Id(), heap_alloc));
  EXPECT_TRUE(heap_manager_->Free(heap_manager_->process_heap(),
                                  process_heap_alloc));
  EXPECT_TRUE(heap_manager_->Free(heap_manager_->process_heap(),
                                  process_heap_wrapper_alloc));
}

TEST_P(BlockHeapManagerTest, PopOnSetQuarantineMaxSize) {
  const size_t kAllocSize = 100;
  size_t real_alloc_size = GetAllocSize(kAllocSize);
  ScopedHeap heap(heap_manager_);
  void* mem = heap.Allocate(kAllocSize);
  ASSERT_FALSE(heap.InQuarantine(mem));

  ::common::AsanParameters parameters = heap_manager_->parameters();
  parameters.quarantine_size = real_alloc_size;
  heap_manager_->set_parameters(parameters);

  ASSERT_TRUE(heap.Free(mem));
  ASSERT_TRUE(heap.InQuarantine(mem));

  // We resize the quarantine to a smaller size, the block should pop out.
  parameters.quarantine_size = real_alloc_size - 1;
  heap_manager_->set_parameters(parameters);
  ASSERT_FALSE(heap.InQuarantine(mem));
}

TEST_P(BlockHeapManagerTest, Quarantine) {
  const size_t kAllocSize = 100;
  size_t real_alloc_size = GetAllocSize(kAllocSize);
  const size_t number_of_allocs = 16;
  ScopedHeap heap(heap_manager_);

  ::common::AsanParameters parameters = heap_manager_->parameters();
  parameters.quarantine_size = real_alloc_size * number_of_allocs;
  heap_manager_->set_parameters(parameters);

  // Allocate a bunch of blocks until exactly one is removed from the
  // quarantine.
  std::vector<void*> blocks;
  for (size_t i = 0; i < number_of_allocs + 1; ++i) {
    void* mem = heap.Allocate(kAllocSize);
    ASSERT_TRUE(mem != nullptr);
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

TEST_P(BlockHeapManagerTest, QuarantineLargeBlock) {
  const size_t kLargeAllocSize = 100;
  const size_t kSmallAllocSize = 25;
  size_t real_large_alloc_size = GetAllocSize(kLargeAllocSize);
  size_t real_small_alloc_size = GetAllocSize(kSmallAllocSize);

  ScopedHeap heap(heap_manager_);
  ::common::AsanParameters parameters = heap_manager_->parameters();
  parameters.quarantine_size = real_large_alloc_size;
  parameters.quarantine_block_size = real_large_alloc_size;
  heap_manager_->set_parameters(parameters);

  // A block larger than the quarantine should not make it in.
  void* mem1 = heap.Allocate(real_large_alloc_size + 1);
  ASSERT_NE(static_cast<void*>(nullptr), mem1);
  EXPECT_TRUE(heap.Free(mem1));
  EXPECT_FALSE(heap.InQuarantine(mem1));
  EXPECT_EQ(0u, heap.GetQuarantine()->GetCount());

  // A smaller block should make it because our current max block size allows
  // it.
  void* mem2 = heap.Allocate(kSmallAllocSize);
  ASSERT_NE(static_cast<void*>(nullptr), mem2);
  EXPECT_TRUE(heap.Free(mem2));
  EXPECT_TRUE(heap.InQuarantine(mem2));

  parameters.quarantine_block_size = real_small_alloc_size - 1;
  heap_manager_->set_parameters(parameters);

  // A second small block should not make it in since we changed the block size.
  // However, the other block should remain in the quarantine.
  void* mem3 = heap.Allocate(kSmallAllocSize);
  ASSERT_NE(static_cast<void*>(nullptr), mem3);
  EXPECT_TRUE(heap.Free(mem3));
  EXPECT_TRUE(heap.InQuarantine(mem2));
  EXPECT_FALSE(heap.InQuarantine(mem3));
}

TEST_P(BlockHeapManagerTest, UnpoisonsQuarantine) {
  const size_t kAllocSize = 100;
  const size_t real_alloc_size = GetAllocSize(kAllocSize);

  ScopedHeap heap(heap_manager_);
  ::common::AsanParameters parameters = heap_manager_->parameters();
  parameters.quarantine_size = real_alloc_size;
  heap_manager_->set_parameters(parameters);

  // Allocate a memory block and directly free it, this puts it in the
  // quarantine.
  void* mem = heap.Allocate(kAllocSize);
  ASSERT_NE(static_cast<void*>(nullptr), mem);
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
  for (size_t i = shadow_start; i < shadow_start + shadow_alloc_size; ++i) {
    if ((heap.GetHeapFeatures() &
         HeapInterface::kHeapReportsReservations) != 0) {
      ASSERT_EQ(kAsanReservedMarker, TestShadow::shadow_[i]);
    } else {
      ASSERT_EQ(kHeapAddressableMarker, TestShadow::shadow_[i]);
    }
  }
}

TEST_P(BlockHeapManagerTest, QuarantineIsShared) {
  const size_t kAllocSize = 100;
  const size_t real_alloc_size = GetAllocSize(kAllocSize);
  ScopedHeap heap_1(heap_manager_);
  ScopedHeap heap_2(heap_manager_);

  ASSERT_EQ(heap_1.GetQuarantine(), heap_2.GetQuarantine());

  ::common::AsanParameters parameters = heap_manager_->parameters();
  parameters.quarantine_size = real_alloc_size * 4;
  heap_manager_->set_parameters(parameters);

  void* heap_1_mem1 = heap_1.Allocate(kAllocSize);
  ASSERT_NE(static_cast<void*>(nullptr), heap_1_mem1);
  void* heap_1_mem2 = heap_1.Allocate(kAllocSize);
  ASSERT_NE(static_cast<void*>(nullptr), heap_1_mem2);
  void* heap_2_mem1 = heap_2.Allocate(kAllocSize);
  ASSERT_NE(static_cast<void*>(nullptr), heap_2_mem1);
  void* heap_2_mem2 = heap_2.Allocate(kAllocSize);
  ASSERT_NE(static_cast<void*>(nullptr), heap_2_mem2);

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

TEST_P(BlockHeapManagerTest, AllocZeroBytes) {
  ScopedHeap heap(heap_manager_);
  void* mem1 = heap.Allocate(0);
  ASSERT_NE(static_cast<void*>(nullptr), mem1);
  void* mem2 = heap.Allocate(0);
  ASSERT_NE(static_cast<void*>(nullptr), mem2);
  ASSERT_NE(mem1, mem2);
  ASSERT_TRUE(heap.Free(mem1));
  ASSERT_TRUE(heap.Free(mem2));
}

TEST_P(BlockHeapManagerTest, AllocInvalidBlockSize) {
  ScopedHeap heap(heap_manager_);
  const size_t kInvalidSize = 0xffffffff;
  void* mem = heap.Allocate(0xffffffff);
  ASSERT_EQ(static_cast<void*>(nullptr), mem);
}

TEST_P(BlockHeapManagerTest, Size) {
  const size_t kMaxAllocSize = 134584;
  ScopedHeap heap(heap_manager_);
  for (size_t size = 10; size < kMaxAllocSize; size = size * 5 + 123) {
    void* mem = heap.Allocate(size);
    ASSERT_NE(static_cast<void*>(nullptr), mem);
    ASSERT_EQ(size, heap_manager_->Size(heap.Id(), mem));
    ASSERT_TRUE(heap.Free(mem));
  }
}

TEST_P(BlockHeapManagerTest, AllocsAccessibility) {
  const size_t kMaxAllocSize = 134584;
  ScopedHeap heap(heap_manager_);
  // Ensure that the quarantine is large enough to keep the allocated blocks in
  // this test.
  ::common::AsanParameters parameters = heap_manager_->parameters();
  parameters.quarantine_size = kMaxAllocSize * 2;
  heap_manager_->set_parameters(parameters);
  for (size_t size = 10; size < kMaxAllocSize; size = size * 5 + 123) {
    // Do an alloc/free and test that access is correctly managed.
    void* mem = heap.Allocate(size);
    ASSERT_NE(static_cast<void*>(nullptr), mem);
    ASSERT_NO_FATAL_FAILURE(VerifyAllocAccess(mem, size));
    ASSERT_TRUE(heap.Free(mem));
    ASSERT_NO_FATAL_FAILURE(VerifyFreedAccess(mem, size));
  }
}

TEST_P(BlockHeapManagerTest, LockUnlock) {
  ScopedHeap heap(heap_manager_);
  // We can't really test these, aside from not crashing.
  ASSERT_NO_FATAL_FAILURE(heap_manager_->Lock(heap.Id()));
  ASSERT_NO_FATAL_FAILURE(heap_manager_->Unlock(heap.Id()));
}

TEST_P(BlockHeapManagerTest, CaptureTID) {
  const size_t kAllocSize = 13;
  ScopedHeap heap(heap_manager_);
  // Ensure that the quarantine is large enough to keep this block.
  ::common::AsanParameters parameters = heap_manager_->parameters();
  parameters.quarantine_size = GetAllocSize(kAllocSize);
  heap_manager_->set_parameters(parameters);
  uint8* mem = static_cast<uint8*>(heap.Allocate(kAllocSize));
  ASSERT_TRUE(heap.Free(mem));
  EXPECT_EQ(QUARANTINED_BLOCK,
            static_cast<BlockState>(BlockGetHeaderFromBody(mem)->state));

  BlockHeader* header = BlockGetHeaderFromBody(mem);
  ASSERT_NE(static_cast<BlockHeader*>(nullptr), header);
  BlockInfo block_info = {};
  EXPECT_TRUE(BlockInfoFromMemory(header, &block_info));
  EXPECT_NE(static_cast<BlockTrailer*>(nullptr), block_info.trailer);

  EXPECT_EQ(block_info.trailer->alloc_tid, ::GetCurrentThreadId());
  EXPECT_EQ(block_info.trailer->free_tid, ::GetCurrentThreadId());
}

TEST_P(BlockHeapManagerTest, QuarantineDoesntAlterBlockContents) {
  const size_t kAllocSize = 13;
  ScopedHeap heap(heap_manager_);
  // Ensure that the quarantine is large enough to keep this block.
  ::common::AsanParameters parameters = heap_manager_->parameters();
  parameters.quarantine_size = GetAllocSize(kAllocSize);
  heap_manager_->set_parameters(parameters);
  void* mem = heap.Allocate(kAllocSize);
  ASSERT_NE(static_cast<void*>(nullptr), mem);
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

TEST_P(BlockHeapManagerTest, SetTrailerPaddingSize) {
  const size_t kAllocSize = 13;
  ScopedHeap heap(heap_manager_);
  // Ensure that the quarantine is large enough to keep this block with the
  // extra padding.
  ::common::AsanParameters parameters = heap_manager_->parameters();
  parameters.quarantine_size = GetAllocSize(kAllocSize) * 5;
  heap_manager_->set_parameters(parameters);
  size_t original_alloc_size = GetAllocSize(kAllocSize);
  ::common::AsanParameters original_parameter = heap_manager_->parameters();

  for (size_t padding = 0; padding < 16; ++padding) {
    ::common::AsanParameters new_parameter = original_parameter;
    new_parameter.trailer_padding_size =
        original_parameter.trailer_padding_size + padding;
    heap_manager_->set_parameters(new_parameter);
    size_t augmented_alloc_size = GetAllocSize(kAllocSize);
    EXPECT_GE(augmented_alloc_size, original_alloc_size);

    void* mem = heap.Allocate(kAllocSize);
    ASSERT_TRUE(mem != nullptr);

    size_t offset = kAllocSize;
    for (; offset < augmented_alloc_size - sizeof(BlockHeader);
         ++offset) {
      EXPECT_FALSE(Shadow::IsAccessible(
          reinterpret_cast<const uint8*>(mem) + offset));
    }
    ASSERT_TRUE(heap.Free(mem));
  }
  heap_manager_->set_parameters(original_parameter);
}

TEST_P(BlockHeapManagerTest, BlockChecksumUpdatedWhenEnterQuarantine) {
  const size_t kAllocSize = 100;
  size_t real_alloc_size = GetAllocSize(kAllocSize);
  ScopedHeap heap(heap_manager_);

  ::common::AsanParameters parameters = heap_manager_->parameters();
  parameters.quarantine_size = real_alloc_size;
  heap_manager_->set_parameters(parameters);

  void* mem = heap.Allocate(kAllocSize);
  ASSERT_NE(static_cast<void*>(nullptr), mem);
  BlockInfo block_info = {};
  EXPECT_TRUE(Shadow::BlockInfoFromShadow(mem, &block_info));
  EXPECT_TRUE(BlockChecksumIsValid(block_info));
  heap.Free(mem);
  EXPECT_TRUE(BlockChecksumIsValid(block_info));
  ASSERT_TRUE(heap.InQuarantine(mem));
}

static const size_t kChecksumRepeatCount = 10;

TEST_P(BlockHeapManagerTest, CorruptAsEntersQuarantine) {
  const size_t kAllocSize = 100;
  ::common::AsanParameters parameters = heap_manager_->parameters();
  parameters.quarantine_size = GetAllocSize(kAllocSize);
  heap_manager_->set_parameters(parameters);

  ScopedHeap heap(heap_manager_);
  // This can fail because of a checksum collision. However, we run it a
  // handful of times to keep the chances as small as possible.
  for (size_t i = 0; i < kChecksumRepeatCount; ++i) {
    heap.FlushQuarantine();
    void* mem = heap.Allocate(kAllocSize);
    ASSERT_NE(static_cast<void*>(nullptr), mem);
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

TEST_P(BlockHeapManagerTest, CorruptAsExitsQuarantine) {
  const size_t kAllocSize = 100;
  ::common::AsanParameters parameters = heap_manager_->parameters();
  parameters.quarantine_size = GetAllocSize(kAllocSize);
  heap_manager_->set_parameters(parameters);

  ScopedHeap heap(heap_manager_);
  // This can fail because of a checksum collision. However, we run it a
  // handful of times to keep the chances as small as possible.
  for (size_t i = 0; i < kChecksumRepeatCount; ++i) {
    heap.FlushQuarantine();
    void* mem = heap.Allocate(kAllocSize);
    ASSERT_NE(static_cast<void*>(nullptr), mem);
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

TEST_P(BlockHeapManagerTest, CorruptAsExitsQuarantineOnHeapDestroy) {
  const size_t kAllocSize = 100;
  ::common::AsanParameters parameters = heap_manager_->parameters();
  parameters.quarantine_size = GetAllocSize(kAllocSize);
  heap_manager_->set_parameters(parameters);

  // This can fail because of a checksum collision. However, we run it a
  // handful of times to keep the chances as small as possible.
  for (size_t i = 0; i < kChecksumRepeatCount; ++i) {
    void* mem = nullptr;
    {
      ScopedHeap heap(heap_manager_);
      heap.FlushQuarantine();
      mem = heap.Allocate(kAllocSize);
      ASSERT_NE(static_cast<void*>(nullptr), mem);
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

TEST_P(BlockHeapManagerTest, CorruptHeapOnTrimQuarantine) {
  const size_t kAllocSize = 100;
  ::common::AsanParameters parameters = heap_manager_->parameters();
  parameters.quarantine_size = GetAllocSize(kAllocSize);
  heap_manager_->set_parameters(parameters);

  // This can fail because of a checksum collision. However, we run it a
  // handful of times to keep the chances as small as possible.
  for (size_t i = 0; i < kChecksumRepeatCount; ++i) {
    void* mem = nullptr;
    {
      ScopedHeap heap(heap_manager_);
      heap.FlushQuarantine();
      mem = heap.Allocate(kAllocSize);
      ASSERT_NE(static_cast<void*>(nullptr), mem);
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

TEST_P(BlockHeapManagerTest, DoubleFree) {
  const size_t kAllocSize = 100;
  ::common::AsanParameters parameters = heap_manager_->parameters();
  parameters.quarantine_size = GetAllocSize(kAllocSize);
  heap_manager_->set_parameters(parameters);

  ScopedHeap heap(heap_manager_);
  void* mem = heap.Allocate(kAllocSize);
  ASSERT_NE(static_cast<void*>(nullptr), mem);
  EXPECT_TRUE(heap.Free(mem));
  EXPECT_FALSE(heap.Free(mem));

  EXPECT_EQ(1u, errors_.size());
  EXPECT_EQ(DOUBLE_FREE, errors_[0].error_type);
  EXPECT_EQ(mem, errors_[0].location);
}

TEST_P(BlockHeapManagerTest, SubsampledAllocationGuards) {
  ::common::AsanParameters parameters = heap_manager_->parameters();
  parameters.allocation_guard_rate = 0.5;
  heap_manager_->set_parameters(parameters);
  ScopedHeap heap(heap_manager_);

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
    EXPECT_NE(static_cast<void*>(nullptr), alloc);

    for (size_t i = 0; i < alloc_size; ++i)
      EXPECT_TRUE(Shadow::IsAccessible(reinterpret_cast<uint8*>(alloc) + i));

    // Determine if the allocation has guards or not.
    BlockHeader* header = BlockGetHeaderFromBody(alloc);
    if (header == nullptr) {
      ++unguarded_allocations;
    } else {
      ++guarded_allocations;
    }

    if ((heap.GetHeapFeatures() &
         HeapInterface::kHeapSupportsGetAllocationSize) != 0) {
      if ((heap.GetHeapFeatures() &
           HeapInterface::kHeapGetAllocationSizeIsUpperBound) != 0) {
        EXPECT_LE(alloc_size, heap_manager_->Size(heap.Id(), alloc));
      } else {
        EXPECT_EQ(alloc_size, heap_manager_->Size(heap.Id(), alloc));
      }
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
TEST_P(BlockHeapManagerTest, ZebraHeapIdInTrailerAfterAllocation) {
  EnableTestZebraBlockHeap();
  ScopedHeap heap(heap_manager_);
  const size_t kAllocSize = 0x100;
  void* alloc = heap.Allocate(kAllocSize);
  EXPECT_NE(static_cast<void*>(nullptr), alloc);
  ASSERT_NO_FATAL_FAILURE(VerifyAllocAccess(alloc, kAllocSize));

  // Get the heap_id from the block trailer.
  BlockInfo block_info = {};
  EXPECT_TRUE(Shadow::BlockInfoFromShadow(alloc, &block_info));

  {
    ScopedBlockAccess block_access(block_info);
    // The heap_id stored in the block trailer should match the zebra heap id.
    EXPECT_EQ(heap_manager_->zebra_block_heap_id_,
              block_info.trailer->heap_id);
  }

  EXPECT_TRUE(heap.Free(alloc));
}

// Ensures that the provided heap is used when the ZebraBlockHeap cannot handle
// the allocation.
TEST_P(BlockHeapManagerTest, DefaultHeapIdInTrailerWhenZebraHeapIsFull) {
  EnableTestZebraBlockHeap();
  ScopedHeap heap(heap_manager_);
  const size_t kAllocSize = 0x100;
  // Refuse allocations on the ZebraBlockHeap.
  test_zebra_block_heap_->set_refuse_allocations(true);

  void* alloc = heap.Allocate(kAllocSize);
  EXPECT_NE(static_cast<void*>(nullptr), alloc);
  ASSERT_NO_FATAL_FAILURE(VerifyAllocAccess(alloc, kAllocSize));

  // Get the heap_id from the block trailer.
  BlockInfo block_info = {};
  EXPECT_TRUE(Shadow::BlockInfoFromShadow(alloc, &block_info));
  {
    ScopedBlockAccess block_access(block_info);
    // The heap_id stored in the block trailer match the provided heap.
    EXPECT_EQ(heap.Id(), block_info.trailer->heap_id);
  }
  EXPECT_TRUE(heap.Free(alloc));
}

// Allocations larger than the page size (4KB) will not be served by the zebra
// heap.
TEST_P(BlockHeapManagerTest, AllocStress) {
  EnableTestZebraBlockHeap();
  ScopedHeap heap(heap_manager_);
  for (size_t i = 0; i < 3000; ++i) {
    // Sometimes allocate more than one page, to ensure that allocations get
    // spread across the ZebraBlockheap and normal heaps.
    const size_t kAllocSize = (i * 997) % (9 * 1024);
    void* alloc = heap.Allocate(kAllocSize);
    EXPECT_NE(static_cast<void*>(nullptr), alloc);
    ASSERT_NO_FATAL_FAILURE(VerifyAllocAccess(alloc, kAllocSize));
    // Free should succeed, even if the block is quarantined.
    EXPECT_TRUE(heap.Free(alloc));
  }
}

TEST_P(BlockHeapManagerTest, AllocFromRateTargetedHeap) {
  ScopedHeap heap(heap_manager_);
  std::vector<void*> alloc_to_free;
  const size_t kAllocSize1 =
      TestBlockHeapManager::kDefaultRateTargetedHeapsMinBlockSize[0];
  const size_t kAllocSize2 =
      TestBlockHeapManager::kDefaultRateTargetedHeapsMinBlockSize[1];
  const size_t kIterations = 10;

  // The first iteration will be used to initialize the allocation sites
  // frequency min and max.
  for (size_t c = 0; c < kIterations + 1; ++c) {
    void* alloc = heap.Allocate(kAllocSize1);
    EXPECT_NE(static_cast<void*>(nullptr), alloc);
    alloc = heap.Allocate(kAllocSize2);
    EXPECT_NE(static_cast<void*>(nullptr), alloc);
    alloc_to_free.push_back(alloc);
    for (size_t i = 0; i < 10; ++i) {
      void* alloc = heap.Allocate(kAllocSize1);
      EXPECT_NE(static_cast<void*>(nullptr), alloc);
      alloc_to_free.push_back(alloc);
      alloc = heap.Allocate(kAllocSize2);
      EXPECT_NE(static_cast<void*>(nullptr), alloc);
      alloc_to_free.push_back(alloc);
    }
    for (size_t i = 0; i < 100; ++i) {
      void* alloc = heap.Allocate(kAllocSize1);
      EXPECT_NE(static_cast<void*>(nullptr), alloc);
      alloc_to_free.push_back(alloc);
      alloc = heap.Allocate(kAllocSize2);
      EXPECT_NE(static_cast<void*>(nullptr), alloc);
      alloc_to_free.push_back(alloc);
    }
    for (size_t i = 0; i < 1000; ++i) {
      void* alloc = heap.Allocate(kAllocSize1);
      EXPECT_NE(static_cast<void*>(nullptr), alloc);
      alloc_to_free.push_back(alloc);
      alloc = heap.Allocate(kAllocSize2);
      EXPECT_NE(static_cast<void*>(nullptr), alloc);
      alloc_to_free.push_back(alloc);
    }
    // Remove the allocations made during the first iteration, now the
    // allocation sites frequencies should be correctly initialized and and the
    // appropriate heap will be used for each allocation.
    if (c == 0) {
      for (const auto& alloc : alloc_to_free)
        heap.Free(alloc);
      alloc_to_free.clear();
      for (size_t i = 0; i < TestBlockHeapManager::kRateTargetedHeapCount; ++i)
        heap_manager_->rate_targeted_heaps_count_[i] = 0;
    }
  }
  for (size_t i = 1, j = 0; i < 10000; i *= 10, ++j) {
    EXPECT_EQ(kIterations * i * 2,
        heap_manager_->rate_targeted_heaps_count_[j]);
  }
  for (const auto& alloc : alloc_to_free)
    heap.Free(alloc);
}

// The BlockHeapManager correctly quarantines the memory after free.
TEST_P(BlockHeapManagerTest, QuarantinedAfterFree) {
  EnableTestZebraBlockHeap();
  ScopedHeap heap(heap_manager_);
  // Always quarantine if possible.
  test_zebra_block_heap_->set_quarantine_ratio(1.0);

  const size_t kAllocSize = 0x100;
  void* alloc = heap.Allocate(kAllocSize);
  EXPECT_NE(static_cast<void*>(nullptr), alloc);
  ASSERT_NO_FATAL_FAILURE(VerifyAllocAccess(alloc, kAllocSize));
  // Free should succeed, even if the block is quarantined.
  EXPECT_TRUE(heap.Free(alloc));
  // The block should be quarantined and poisoned.
  ASSERT_NO_FATAL_FAILURE(VerifyFreedAccess(alloc, kAllocSize));
  BlockInfo block_info = {};
  EXPECT_TRUE(Shadow::BlockInfoFromShadow(alloc, &block_info));

  {
    ScopedBlockAccess block_access(block_info);
    EXPECT_EQ(QUARANTINED_BLOCK, block_info.header->state);
  }
}

// set_parameters should set the zebra_block_heap_quarantine_ratio flag
// correctly.
TEST_P(BlockHeapManagerTest, set_parametersSetsZebraBlockHeapQuarantineRatio) {
  EnableTestZebraBlockHeap();
  float new_ratio = 1.0f / 8;
  ::common::AsanParameters params = heap_manager_->parameters();
  params.zebra_block_heap_quarantine_ratio = new_ratio;
  heap_manager_->set_parameters(params);
  EXPECT_EQ(new_ratio, test_zebra_block_heap_->quarantine_ratio());
}

// Test for double free errors using the zebra heap.
TEST_P(BlockHeapManagerTest, DoubleFreeOnZebraHeap) {
  EnableTestZebraBlockHeap();
  ScopedHeap heap(heap_manager_);
  test_zebra_block_heap_->set_quarantine_ratio(1.0);

  const size_t kAllocSize = 0xFF;
  void* alloc = heap.Allocate(kAllocSize);
  EXPECT_NE(static_cast<void*>(nullptr), alloc);
  ASSERT_NO_FATAL_FAILURE(VerifyAllocAccess(alloc, kAllocSize));

  EXPECT_TRUE(heap.Free(alloc));
  EXPECT_FALSE(heap.Free(alloc));

  EXPECT_EQ(1u, errors_.size());
  EXPECT_EQ(DOUBLE_FREE, errors_[0].error_type);
  EXPECT_EQ(alloc, errors_[0].location);
}

TEST_P(BlockHeapManagerTest, AllocatedBlockIsProtected) {
  EnableTestZebraBlockHeap();
  ScopedHeap heap(heap_manager_);

  const size_t kAllocSize = 0xFF;
  void* alloc = heap.Allocate(kAllocSize);
  EXPECT_NE(static_cast<void*>(nullptr), alloc);
  ASSERT_NO_FATAL_FAILURE(VerifyAllocAccess(alloc, kAllocSize));

  BlockInfo block_info = {};
  EXPECT_TRUE(Shadow::BlockInfoFromShadow(alloc, &block_info));

  // Test the block protections before being quarantined.
  // The whole block should be unpoisoned in the shadow memory.
  for (size_t i = 0; i < block_info.body_size; ++i)
    EXPECT_TRUE(Shadow::IsAccessible(block_info.body + i));

  // Ensure that the block left redzone is page-protected.
  for (size_t i = 0; i < block_info.left_redzone_pages_size; ++i)
    EXPECT_TRUE(IsNotAccessible(block_info.left_redzone_pages + i));

  // Ensure that the block right redzone is page-protected.
  for (size_t i = 0; i < block_info.right_redzone_pages_size; ++i)
    EXPECT_TRUE(IsNotAccessible(block_info.right_redzone_pages + i));

  // The block body should be accessible.
  for (size_t i = 0; i < block_info.body_size; ++i)
    EXPECT_TRUE(IsAccessible(block_info.body + i));

  {
    ScopedBlockAccess block_access(block_info);
    EXPECT_EQ(ALLOCATED_BLOCK, block_info.header->state);
  }

  EXPECT_TRUE(heap.Free(alloc));
}

TEST_P(BlockHeapManagerTest, QuarantinedBlockIsProtected) {
  EnableTestZebraBlockHeap();
  ScopedHeap heap(heap_manager_);
  // Always quarantine if possible.
  test_zebra_block_heap_->set_quarantine_ratio(1.0);

  for (size_t i = 0; i < 20; ++i) {
    const size_t kAllocSize = 0xFF + i;
    void* alloc = heap.Allocate(kAllocSize);
    EXPECT_NE(static_cast<void*>(nullptr), alloc);
    ASSERT_NO_FATAL_FAILURE(VerifyAllocAccess(alloc, kAllocSize));

    BlockInfo block_info = {};
    EXPECT_TRUE(Shadow::BlockInfoFromShadow(alloc, &block_info));

    // The block is freed and quarantined.
    EXPECT_TRUE(heap.Free(alloc));

    // Test the block protections after being quarantined.
    // The whole block should be poisoned in the shadow memory.
    for (size_t i = 0; i < block_info.body_size; ++i)
      EXPECT_FALSE(Shadow::IsAccessible(block_info.body + i));

    // Ensure that the block left redzone is page-protected.
    for (size_t i = 0; i < block_info.left_redzone_pages_size; ++i)
      EXPECT_TRUE(IsNotAccessible(block_info.left_redzone_pages + i));

    // Ensure that the block right redzone is page-protected.
    for (size_t i = 0; i < block_info.right_redzone_pages_size; ++i)
      EXPECT_TRUE(IsNotAccessible(block_info.right_redzone_pages + i));

    // Ensure that the block body is page-protected.
    for (size_t i = 0; i < block_info.body_size; ++i)
      EXPECT_TRUE(IsNotAccessible(block_info.body + i));

    {
      ScopedBlockAccess block_access(block_info);
      EXPECT_EQ(QUARANTINED_BLOCK, block_info.header->state);
    }
  }
}

TEST_P(BlockHeapManagerTest, NonQuarantinedBlockIsMarkedAsFreed) {
  EnableTestZebraBlockHeap();
  ScopedHeap heap(heap_manager_);
  // Desaible the zebra heap quarantine.
  test_zebra_block_heap_->set_refuse_push(true);

  const size_t kAllocSize = 0x100;
  void* alloc = heap.Allocate(kAllocSize);
  EXPECT_NE(static_cast<void*>(nullptr), alloc);
  ASSERT_NO_FATAL_FAILURE(VerifyAllocAccess(alloc, kAllocSize));

  BlockInfo block_info = {};
  EXPECT_TRUE(Shadow::BlockInfoFromShadow(alloc, &block_info));

  // The block is freed but not quarantined.
  EXPECT_TRUE(heap.Free(alloc));

  // The whole block should be unpoisoned in the shadow memory, and its
  // associated pages unprotected.
  for (size_t i = 0; i < block_info.block_size; ++i) {
    ASSERT_NO_FATAL_FAILURE(Shadow::IsAccessible(block_info.block + i));
    ASSERT_FALSE(Shadow::PageIsProtected(block_info.block + i));
  }

  EXPECT_EQ(FREED_BLOCK, block_info.header->state);
}

TEST_P(BlockHeapManagerTest, ZebraBlockHeapQuarantineRatioIsRespected) {
  EnableTestZebraBlockHeap();
  ScopedHeap heap(heap_manager_);
  // Set a non-standard quarantine ratio.
  float quarantine_ratio = 0.37f;
  test_zebra_block_heap_->set_quarantine_ratio(quarantine_ratio);

  const size_t kAllocations = 2000;

  size_t zebra_heap_size = test_zebra_block_heap_->slab_count_;
  const size_t max_quarantine_size = zebra_heap_size * quarantine_ratio;

  // All allocations have a maximum size of 1KB, all are served by the zebra
  // heap.
  for (size_t i = 0; i < kAllocations; ++i) {
    const size_t kAllocSize = (0x100 + i) % 1024;
    void* alloc = heap.Allocate(kAllocSize);
    EXPECT_NE(static_cast<void*>(nullptr), alloc);

    BlockInfo block_info = {};
    EXPECT_TRUE(Shadow::BlockInfoFromShadow(alloc, &block_info));
    EXPECT_TRUE(heap.Free(alloc));

    // After Free the quarantine should be trimmed, enforcing the quarantine
    // size upper bound.
    EXPECT_LE(test_zebra_block_heap_->GetCount(), max_quarantine_size);

    {
      ScopedBlockAccess block_access(block_info);
      EXPECT_EQ(QUARANTINED_BLOCK, block_info.header->state);
    }
  }
}

// Ensures that the LargeBlockHeap overrides the provided heap if the allocation
// size exceeds the threshold.
TEST_P(BlockHeapManagerTest, LargeBlockHeapUsedForLargeAllocations) {
  EnableLargeBlockHeap(GetPageSize());

  // Disable targeted heaps as it interferes with this test.
  ::common::AsanParameters params = heap_manager_->parameters();
  params.enable_rate_targeted_heaps = false;
  heap_manager_->SetParameters(params);

  ScopedHeap heap(heap_manager_);

  const size_t kAllocSize = GetPageSize() + 0x100;
  void* alloc = heap.Allocate(kAllocSize);
  EXPECT_NE(static_cast<void*>(nullptr), alloc);
  ASSERT_NO_FATAL_FAILURE(VerifyAllocAccess(alloc, kAllocSize));

  // Get the heap_id from the block trailer.
  BlockInfo block_info = {};
  EXPECT_TRUE(Shadow::BlockInfoFromShadow(alloc, &block_info));

  {
    ScopedBlockAccess block_access(block_info);
    // The heap_id stored in the block trailer should match the large block
    // heap id.
    EXPECT_EQ(heap_manager_->large_block_heap_id_,
              block_info.trailer->heap_id);
  }

  EXPECT_TRUE(heap.Free(alloc));
}

// Ensures that the LargeBlockHeap is not used for a small allocation.
TEST_P(BlockHeapManagerTest, LargeBlockHeapNotUsedForSmallAllocations) {
  EnableLargeBlockHeap(GetPageSize());
  ScopedHeap heap(heap_manager_);

  const size_t kAllocSize = 0x100;
  void* alloc = heap.Allocate(kAllocSize);
  EXPECT_NE(static_cast<void*>(nullptr), alloc);
  ASSERT_NO_FATAL_FAILURE(VerifyAllocAccess(alloc, kAllocSize));

  // Get the heap_id from the block trailer.
  BlockInfo block_info = {};
  EXPECT_TRUE(Shadow::BlockInfoFromShadow(alloc, &block_info));

  {
    ScopedBlockAccess block_access(block_info);
    // The provided heap ID should be the one in the block trailer.
    EXPECT_EQ(heap.Id(), block_info.trailer->heap_id);
  }

  EXPECT_TRUE(heap.Free(alloc));
}

TEST_P(BlockHeapManagerTest, AllocationFilterFlag) {
  EXPECT_NE(TLS_OUT_OF_INDEXES, heap_manager_->allocation_filter_flag_tls_);
  heap_manager_->set_allocation_filter_flag(true);
  EXPECT_TRUE(heap_manager_->allocation_filter_flag());
  heap_manager_->set_allocation_filter_flag(false);
  EXPECT_FALSE(heap_manager_->allocation_filter_flag());
  heap_manager_->set_allocation_filter_flag(true);
  EXPECT_TRUE(heap_manager_->allocation_filter_flag());
}

namespace {

size_t CountLockedHeaps(HeapInterface** heaps) {
  size_t i = 0;
  while (heaps[i] != nullptr) {
    ++i;
  }
  return i;
}

}  // namespace

TEST_P(BlockHeapManagerTest, BestEffortLockAllNoLocksHeld) {
  heap_manager_->BestEffortLockAll();
  EXPECT_EQ(CountLockedHeaps(heap_manager_->locked_heaps_),
            heap_manager_->heaps_.size());
  heap_manager_->UnlockAll();
}

namespace {

// A helper thread runner for acquiring a HeapInterface lock for a certain
// amount of time.
class GrabHeapLockRunner : public base::DelegateSimpleThread::Delegate {
 public:
  explicit GrabHeapLockRunner(HeapInterface* heap)
      : heap_(heap), cv_(&cv_lock_), acquired_(false), release_(false) {
    DCHECK_NE(static_cast<HeapInterface*>(nullptr), heap);
  }

  virtual void Run() {
    DCHECK_NE(static_cast<HeapInterface*>(nullptr), heap_);
    heap_->Lock();
    SignalAcquired();
    WaitRelease();
    heap_->Unlock();
  }

  // Waits until |acquired| is true.
  void WaitAcquired() {
    while (true) {
      base::AutoLock auto_lock(cv_lock_);
      if (acquired_)
        return;
      cv_.Wait();
    }
  }

  // To be called externally to notify this runner that the lock may be
  // released and the thread torn down.
  void SignalRelease() {
    base::AutoLock auto_lock(cv_lock_);
    release_ = true;
    cv_.Broadcast();
  }

 private:
  // Notifies external observers that the lock has been acquired.
  void SignalAcquired() {
    base::AutoLock auto_lock(cv_lock_);
    acquired_ = true;
    cv_.Broadcast();
  }

  // Waits until |release| is true.
  void WaitRelease() {
    while (true) {
      base::AutoLock auto_lock(cv_lock_);
      if (release_)
        return;
      cv_.Wait();
    }
  }

  HeapInterface* heap_;
  base::Lock cv_lock_;
  base::ConditionVariable cv_;
  bool acquired_;
  bool release_;

  DISALLOW_COPY_AND_ASSIGN(GrabHeapLockRunner);
};

}  // namespace

TEST_P(BlockHeapManagerTest, BestEffortLockAllOneHeapLockHeld) {
  ASSERT_FALSE(heap_manager_->heaps_.empty());
  GrabHeapLockRunner runner(heap_manager_->heaps_.begin()->first);
  base::DelegateSimpleThread thread(&runner, "GrabHeapLockRunner");
  thread.Start();
  runner.WaitAcquired();
  heap_manager_->BestEffortLockAll();

  // Expect all but one heap lock to have been acquired.
  EXPECT_EQ(CountLockedHeaps(heap_manager_->locked_heaps_),
            heap_manager_->heaps_.size() - 1);
  heap_manager_->UnlockAll();
  runner.SignalRelease();
  thread.Join();
}

// These functions are tested explicitly because the AsanRuntime reaches in
// to use them.

TEST_P(BlockHeapManagerTest, IsValidHeapIdUnlocked) {
  ASSERT_FALSE(heap_manager_->heaps_.empty());
  EXPECT_FALSE(heap_manager_->IsValidHeapIdUnlocked(0xDEADBEEF, false));
  for (auto& hq_pair : heap_manager_->heaps_) {
    TestBlockHeapManager::HeapQuarantinePair* hq = &hq_pair;
    TestBlockHeapManager::HeapId heap_id =
        reinterpret_cast<TestBlockHeapManager::HeapId>(hq);
    EXPECT_TRUE(heap_manager_->IsValidHeapIdUnlocked(heap_id, false));
  }
}

TEST_P(BlockHeapManagerTest, GetHeapTypeUnlocked) {
  ASSERT_FALSE(heap_manager_->heaps_.empty());
  for (auto& hq_pair : heap_manager_->heaps_) {
    TestBlockHeapManager::HeapQuarantinePair* hq = &hq_pair;
    TestBlockHeapManager::HeapId heap_id =
        reinterpret_cast<TestBlockHeapManager::HeapId>(hq);
    EXPECT_NE(kUnknownHeapType, heap_manager_->GetHeapTypeUnlocked(heap_id));
  }
}

}  // namespace heap_managers
}  // namespace asan
}  // namespace agent
