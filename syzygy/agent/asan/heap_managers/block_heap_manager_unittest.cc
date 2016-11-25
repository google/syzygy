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
#include "base/synchronization/waitable_event.h"
#include "base/test/test_reg_util_win.h"
#include "base/threading/simple_thread.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/agent/asan/block.h"
#include "syzygy/agent/asan/heap.h"
#include "syzygy/agent/asan/page_protection_helpers.h"
#include "syzygy/agent/asan/rtl_impl.h"
#include "syzygy/agent/asan/runtime.h"
#include "syzygy/agent/asan/stack_capture_cache.h"
#include "syzygy/agent/asan/unittest_util.h"
#include "syzygy/agent/asan/heaps/internal_heap.h"
#include "syzygy/agent/asan/heaps/large_block_heap.h"
#include "syzygy/agent/asan/heaps/simple_block_heap.h"
#include "syzygy/agent/asan/heaps/win_heap.h"
#include "syzygy/agent/asan/heaps/zebra_block_heap.h"
#include "syzygy/agent/asan/memory_notifiers/null_memory_notifier.h"
#include "syzygy/assm/assembler.h"
#include "syzygy/assm/buffer_serializer.h"
#include "syzygy/common/asan_parameters.h"
#include "syzygy/testing/laa.h"

namespace agent {
namespace asan {
namespace heap_managers {

namespace {

using heaps::ZebraBlockHeap;
using testing::IsAccessible;
using testing::IsNotAccessible;
using testing::ScopedBlockAccess;

typedef BlockHeapManager::HeapId HeapId;

testing::DummyHeap dummy_heap;

// As the code that computes the relative stack IDs ignores any frames from
// its own module and as we statically link with the SyzyAsan CRT, all the
// allocations or crashes coming from these tests will have the same
// relative stack ID by default. To fix this we dynamically generate code that
// does the allocation. We then use the ComputeRelativeStackId seam to indicate
// that the frame is in an entirely different dummy module.
class AllocateFromHeapManagerHelper {
 public:
  AllocateFromHeapManagerHelper(BlockHeapManager* heap_manager,
                                HeapId heap_id,
                                uint32_t offset)
      : heap_manager_(heap_manager), heap_id_(heap_id), offset_(offset) {
    DCHECK_NE(static_cast<BlockHeapManager*>(nullptr), heap_manager);
    DCHECK_LT(offset, GetPageSize());

    // Allocates a page that has the executable bit set.
    allocation_code_page_ = ::VirtualAlloc(nullptr, GetPageSize(),
        MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    EXPECT_NE(nullptr, allocation_code_page_);

    assm::BufferSerializer bs(
        reinterpret_cast<uint8_t*>(allocation_code_page_) + offset,
        GetPageSize() - offset);
    assm::AssemblerImpl assembler(
        reinterpret_cast<uintptr_t>(allocation_code_page_) + offset, &bs);

    assembler.push(assm::ebp);
    assembler.mov(assm::ebp, assm::esp);

    // Push the parameters on the stack.
    assembler.push(assm::AssemblerImpl::Operand(assm::ebp,
        assm::AssemblerImpl::Displacement(0x10, assm::kSize8Bit)));
    assembler.push(assm::AssemblerImpl::Operand(assm::ebp,
        assm::AssemblerImpl::Displacement(0x0C, assm::kSize8Bit)));
    assembler.push(assm::AssemblerImpl::Operand(assm::ebp,
        assm::AssemblerImpl::Displacement(0x08, assm::kSize8Bit)));

    // Call the AllocateFromHeapManager function.
    assembler.call(assm::AssemblerImpl::Immediate(
        reinterpret_cast<uintptr_t>(&AllocateFromHeapManager), assm::kSize32Bit,
        NULL));
    assembler.mov(assm::esp, assm::ebp);
    assembler.pop(assm::ebp);
    assembler.ret();

    agent::common::StackCapture::AddFalseModule(
        "dummy_module.dll", allocation_code_page_, GetPageSize());
  }

  ~AllocateFromHeapManagerHelper() {
    EXPECT_TRUE(::VirtualFree(allocation_code_page_, 0, MEM_RELEASE));
    allocation_code_page_ = nullptr;
    agent::common::StackCapture::ClearFalseModules();
  }

  void* operator()(size_t bytes) {
    using AllocFunctionPtr = void*(*)(BlockHeapManager* heap_manager,
                                      HeapId heap_id,
                                      size_t bytes);
    uint8_t* func = reinterpret_cast<uint8_t*>(allocation_code_page_) + offset_;
    return reinterpret_cast<AllocFunctionPtr>(func)(
        heap_manager_, heap_id_, bytes);
  }

 private:
  // Do an allocation via a heap manager.
  static void* AllocateFromHeapManager(BlockHeapManager* heap_manager,
                                       HeapId heap_id,
                                       uint32_t bytes) {
    EXPECT_NE(nullptr, heap_manager);
    return heap_manager->Allocate(heap_id, bytes);
  }

  // The page that contains the dynamically generated code that does an
  // allocation via a heap manager.
  LPVOID allocation_code_page_;

  // The heap that serves the allocation.
  HeapId heap_id_;

  // The heap manager that owns the heap.
  BlockHeapManager* heap_manager_;

  // The offset within the page where the function starts. Different values of
  // this will cause different relative stack ID values.
  size_t offset_;
};

// A fake ZebraBlockHeap to simplify unit testing.
// Wrapper with switches to enable/disable the quarantine and accept/refuse
// allocations.
class TestZebraBlockHeap : public heaps::ZebraBlockHeap {
 public:
  using ZebraBlockHeap::set_quarantine_ratio;
  using ZebraBlockHeap::quarantine_ratio;
  using ZebraBlockHeap::slab_count_;

  // Constructor.
  explicit TestZebraBlockHeap(MemoryNotifierInterface* memory_notifier)
      : ZebraBlockHeap(1024 * 1024, memory_notifier, &dummy_heap) {
    refuse_allocations_ = false;
    refuse_push_ = false;
  }

  // Virtual destructor.
  virtual ~TestZebraBlockHeap() { }

  // Wrapper that allows easily disabling allocations.
  void* AllocateBlock(uint32_t size,
                      uint32_t min_left_redzone_size,
                      uint32_t min_right_redzone_size,
                      BlockLayout* layout) override {
    if (refuse_allocations_)
      return nullptr;
    return ZebraBlockHeap::AllocateBlock(size,
                                         min_left_redzone_size,
                                         min_right_redzone_size,
                                         layout);
  }

  // Wrapper that allows easily disabling the insertion of new blocks in the
  // quarantine.
  PushResult Push(const CompactBlockInfo& info) override {
    if (refuse_push_) {
      PushResult result = {false, 0};
      return result;
    }
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
  using BlockHeapManager::GetCorruptBlockHeapId;
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
  using BlockHeapManager::corrupt_block_registry_cache_;
  using BlockHeapManager::enable_page_protections_;
  using BlockHeapManager::heaps_;
  using BlockHeapManager::large_block_heap_id_;
  using BlockHeapManager::locked_heaps_;
  using BlockHeapManager::parameters_;
  using BlockHeapManager::shadow_;
  using BlockHeapManager::shared_quarantine_;
  using BlockHeapManager::zebra_block_heap_;
  using BlockHeapManager::zebra_block_heap_id_;

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
  TestBlockHeapManager(Shadow* shadow,
                       StackCaptureCache* stack_cache,
                       MemoryNotifierInterface* memory_notifier)
      : BlockHeapManager(shadow, stack_cache, memory_notifier) {}

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
    // Set the parameters.
    {
      base::AutoLock lock(lock_);
      parameters_ = params;
    }

    PropagateParameters();
  }

  // Wrapper around DeferredFreeDoWork that allows for synchronization around
  // the actual work (pause for start and signal finish).
  void DeferredFreeDoWorkWithSync(base::WaitableEvent* start_event,
                                  base::WaitableEvent* end_event) {
    start_event->Wait();
    BlockHeapManager::DeferredFreeDoWork();
    end_event->Signal();
  }

  // Enabled the deferred free thread with the above wrapper.
  void EnableDeferredFreeWithSync(base::WaitableEvent* start_event,
                                  base::WaitableEvent* end_event) {
    EnableDeferredFreeThreadWithCallback(
        base::Bind(&TestBlockHeapManager::DeferredFreeDoWorkWithSync,
                   base::Unretained(this), start_event, end_event));
  }
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
    alloc_functor_.reset(new AllocateFromHeapManagerHelper(heap_manager,
                                                           heap_id_,
                                                           13));
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
    return (*alloc_functor_)(size);
  }

  // Free the block @p mem.
  bool Free(void* mem) {
    return heap_manager_->Free(heap_id_, mem);
  }

  // Flush the quarantine of this heap.
  void FlushQuarantine() {
    BlockQuarantineInterface* quarantine = GetQuarantine();
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
    static_assert(sizeof(TestQuarantine) ==
                      sizeof(TestBlockHeapManager::ShardedBlockQuarantine),
                  "TestQuarantine isn't an interface.");
    TestQuarantine* test_quarantine =
        reinterpret_cast<TestQuarantine*>(GetQuarantine());
    EXPECT_NE(static_cast<TestQuarantine*>(nullptr), test_quarantine);
    // Search through all of the shards.
    for (size_t i = 0; i < test_quarantine->kShardingFactor; ++i) {
      // Search through all blocks in each shard.
      TestQuarantine::Node* current_node = test_quarantine->heads_[i];
      while (current_node != nullptr) {
        const uint8_t* body =
            reinterpret_cast<const uint8_t*>(current_node->object.header) +
            current_node->object.header_size;
        if (body == mem) {
          EXPECT_TRUE(
              current_node->object.header->state == QUARANTINED_BLOCK ||
              current_node->object.header->state == QUARANTINED_FLOODED_BLOCK);
          return true;
        }
        current_node = current_node->next;
      }
    }

    return false;
  }

  // Returns the heap supported features.
  uint32_t GetHeapFeatures() {
    return heap_manager_->GetHeapFromId(heap_id_)->GetHeapFeatures();
  }

 private:
  // The heap manager owning the underlying heap.
  TestBlockHeapManager* heap_manager_;

  // The underlying heap.
  HeapId heap_id_;

  // The allocation functor.
  std::unique_ptr<AllocateFromHeapManagerHelper> alloc_functor_;
};

// A value-parameterized test class for testing the BlockHeapManager class.
class BlockHeapManagerTest : public testing::TestWithAsanRuntime {
 public:
  typedef TestBlockHeapManager::ShardedBlockQuarantine ShardedBlockQuarantine;
  typedef testing::TestWithAsanRuntime Super;

  BlockHeapManagerTest()
      : TestWithAsanRuntime(&test_runtime_), heap_manager_(),
        test_zebra_block_heap_(nullptr) {
  }

  void SetUp() override {
    Super::SetUp();
    heap_manager_ = reinterpret_cast<TestBlockHeapManager*>(
        test_runtime_.heap_manager_.get());

    override_manager_.OverrideRegistry(RegistryCache::kRegistryRootKey);

    // Set the error callback that the manager will use.
    heap_manager_->SetHeapErrorCallback(
        base::Bind(&BlockHeapManagerTest::OnHeapError, base::Unretained(this)));

    ::common::AsanParameters params;
    ::common::SetDefaultAsanParameters(&params);
    heap_manager_->SetParameters(params);
  }

  void TearDown() override {
    heap_manager_ = nullptr;
    Super::TearDown();
  }

  void OnHeapError(AsanErrorInfo* error) {
    errors_.push_back(*error);
  }

  // Calculates the Asan size for an allocation of @p user_size bytes.
  uint32_t GetAllocSize(uint32_t user_size) {
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
    test_zebra_block_heap_ = new TestZebraBlockHeap(
        runtime_->memory_notifier());
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

  void EnableLargeBlockHeap(uint32_t large_allocation_threshold) {
    ::common::AsanParameters params = heap_manager_->parameters();
    params.enable_large_block_heap = true;
    params.large_allocation_threshold = large_allocation_threshold;
    heap_manager_->set_parameters(params);
    CHECK_NE(0u, heap_manager_->large_block_heap_id_);
  }

  // Verifies that [alloc, alloc + size) is accessible, and that
  // [alloc - 1] and [alloc+size] are poisoned.
  void VerifyAllocAccess(void* alloc, uint32_t size) {
    uint8_t* mem = reinterpret_cast<uint8_t*>(alloc);
    ASSERT_FALSE(runtime_->shadow()->IsAccessible(mem - 1));
    ASSERT_TRUE(runtime_->shadow()->IsLeftRedzone(mem - 1));
    for (uint32_t i = 0; i < size; ++i)
      ASSERT_TRUE(runtime_->shadow()->IsAccessible(mem + i));
    ASSERT_FALSE(runtime_->shadow()->IsAccessible(mem + size));
  }

  // Verifies that [alloc-1, alloc+size] is poisoned.
  void VerifyFreedAccess(void* alloc, uint32_t size) {
    uint8_t* mem = reinterpret_cast<uint8_t*>(alloc);
    ASSERT_FALSE(runtime_->shadow()->IsAccessible(mem - 1));
    ASSERT_TRUE(runtime_->shadow()->IsLeftRedzone(mem - 1));
    for (uint32_t i = 0; i < size; ++i) {
      ASSERT_FALSE(runtime_->shadow()->IsAccessible(mem + i));
      ASSERT_EQ(runtime_->shadow()->GetShadowMarkerForAddress(mem + i),
                kHeapFreedMarker);
    }
    ASSERT_FALSE(runtime_->shadow()->IsAccessible(mem + size));
  }

  void QuarantineAltersBlockContents(
      float quarantine_flood_fill_rate,
      size_t iterations,
      size_t min_flood_filled,
      size_t max_flood_filled) {
    const size_t kAllocSize = 13;
    ScopedHeap heap(heap_manager_);
    // Ensure that the quarantine is large enough to keep this block.
    ::common::AsanParameters parameters = heap_manager_->parameters();
    parameters.quarantine_size = GetAllocSize(kAllocSize);
    parameters.quarantine_flood_fill_rate = quarantine_flood_fill_rate;
    heap_manager_->set_parameters(parameters);

    // This test gets run repeatedly, and it is expected that some portion of
    // the blocks contents will be flood-filled.
    size_t flood_filled_count = 0;
    for (size_t i = 0; i < iterations; ++i) {
      // Allocate a block and fill it with random data.
      void* mem = heap.Allocate(kAllocSize);
      ASSERT_NE(static_cast<void*>(nullptr), mem);
      base::RandBytes(mem, kAllocSize);

      // Hash the contents of the block before being quarantined.
      unsigned char sha1_before[base::kSHA1Length] = {};
      base::SHA1HashBytes(reinterpret_cast<unsigned char*>(mem),
                          kAllocSize,
                          sha1_before);

      // Free the block and ensure it gets quarantined.
      BlockHeader* header = BlockGetHeaderFromBody(
          reinterpret_cast<BlockBody*>(mem));
      ASSERT_TRUE(heap.Free(mem));
      EXPECT_TRUE(
          static_cast<BlockState>(header->state) == QUARANTINED_BLOCK ||
          static_cast<BlockState>(header->state) == QUARANTINED_FLOODED_BLOCK);

      if (static_cast<BlockState>(header->state) == QUARANTINED_BLOCK) {
        // If the block is quarantined and not flood-filled then ensure that the
        // contents have not changed.
        unsigned char sha1_after[base::kSHA1Length] = {};
        base::SHA1HashBytes(reinterpret_cast<unsigned char*>(mem),
                            kAllocSize,
                            sha1_after);
        EXPECT_EQ(0, memcmp(sha1_before, sha1_after, base::kSHA1Length));
      } else {
        // If the block is quarantined and flood-filled then ensure that has
        // actually happened.
        EXPECT_EQ(QUARANTINED_FLOODED_BLOCK,
                  static_cast<BlockState>(header->state));
        BlockHeader* header = BlockGetHeaderFromBody(
            reinterpret_cast<BlockBody*>(mem));
        BlockInfo block_info = {};
        EXPECT_TRUE(BlockInfoFromMemory(header, &block_info));
        EXPECT_TRUE(BlockBodyIsFloodFilled(block_info));
        ++flood_filled_count;
      }

      // Ensure the quarantine is flushed. Otherwise the next block to be
      // allocated might not even make it into the quarantine because a block
      // is randomly evicted.
      heap.FlushQuarantine();
    }

    EXPECT_LE(min_flood_filled, flood_filled_count);
    EXPECT_LE(flood_filled_count, max_flood_filled);
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

  // Prevent the tests from polluting the registry.
  registry_util::RegistryOverrideManager override_manager_;
};

}  // namespace

TEST_F(BlockHeapManagerTest, AllocAndFree) {
  const size_t kAllocSize = 17;
  HeapId heap_id = heap_manager_->CreateHeap();
  EXPECT_NE(0u, heap_id);
  void* alloc = heap_manager_->Allocate(heap_id, kAllocSize);
  EXPECT_NE(static_cast<void*>(nullptr), alloc);
  EXPECT_LE(kAllocSize, heap_manager_->Size(heap_id, alloc));
  EXPECT_TRUE(heap_manager_->Free(heap_id, alloc));
  EXPECT_TRUE(heap_manager_->DestroyHeap(heap_id));
}

TEST_F(BlockHeapManagerTest, AllocAndFreeLargeBlock) {
  TEST_ONLY_SUPPORTS_4G();

  const size_t kAllocSize = 0x7000001c;
  HeapId heap_id = heap_manager_->CreateHeap();
  EXPECT_NE(0u, heap_id);
  void* alloc = heap_manager_->Allocate(heap_id, kAllocSize);
  EXPECT_NE(static_cast<void*>(nullptr), alloc);
  EXPECT_LE(kAllocSize, heap_manager_->Size(heap_id, alloc));
  EXPECT_TRUE(heap_manager_->Free(heap_id, alloc));
  EXPECT_TRUE(heap_manager_->DestroyHeap(heap_id));
}

TEST_F(BlockHeapManagerTest, AllocLargeBlockFail) {
  const size_t kAllocSize = 0x80000000;
  HeapId heap_id = heap_manager_->CreateHeap();
  EXPECT_NE(0u, heap_id);
  void* alloc = heap_manager_->Allocate(heap_id, kAllocSize);
  EXPECT_EQ(static_cast<void*>(nullptr), alloc);
  EXPECT_TRUE(heap_manager_->DestroyHeap(heap_id));
}

TEST_F(BlockHeapManagerTest, FreeNullPointer) {
  HeapId heap_id = heap_manager_->CreateHeap();
  EXPECT_NE(0u, heap_id);
  EXPECT_TRUE(heap_manager_->Free(heap_id, static_cast<void*>(nullptr)));
  EXPECT_TRUE(heap_manager_->DestroyHeap(heap_id));
}

TEST_F(BlockHeapManagerTest, FreeUnguardedAlloc) {
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

TEST_F(BlockHeapManagerTest, PopOnSetQuarantineMaxSize) {
  const size_t kAllocSize = 100;
  uint32_t real_alloc_size = GetAllocSize(kAllocSize);
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

TEST_F(BlockHeapManagerTest, Quarantine) {
  const uint32_t kAllocSize = 100;
  uint32_t real_alloc_size = GetAllocSize(kAllocSize);
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

TEST_F(BlockHeapManagerTest, QuarantineLargeBlock) {
  const uint32_t kLargeAllocSize = 100;
  const uint32_t kSmallAllocSize = 25;
  uint32_t real_large_alloc_size = GetAllocSize(kLargeAllocSize);
  uint32_t real_small_alloc_size = GetAllocSize(kSmallAllocSize);

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
  EXPECT_EQ(0u, heap.GetQuarantine()->GetCountForTesting());

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

TEST_F(BlockHeapManagerTest, UnpoisonsQuarantine) {
  const uint32_t kAllocSize = 100;
  const uint32_t real_alloc_size = GetAllocSize(kAllocSize);

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
  intptr_t mem_start = reinterpret_cast<intptr_t>(BlockGetHeaderFromBody(
      reinterpret_cast<BlockBody*>(mem)));
  ASSERT_EQ(0, (mem_start & 7) );
  size_t shadow_start = mem_start >> 3;
  size_t shadow_alloc_size = real_alloc_size >> 3;
  for (size_t i = shadow_start; i < shadow_start + shadow_alloc_size; ++i)
    ASSERT_NE(kHeapAddressableMarker, runtime_->shadow()->shadow()[i]);

  // Flush the quarantine.
  heap.FlushQuarantine();

  // Assert that the quarantine has been correctly unpoisoned.
  for (size_t i = shadow_start; i < shadow_start + shadow_alloc_size; ++i) {
    if ((heap.GetHeapFeatures() &
         HeapInterface::kHeapReportsReservations) != 0) {
      ASSERT_EQ(kAsanReservedMarker, runtime_->shadow()->shadow()[i]);
    } else {
      ASSERT_EQ(kHeapAddressableMarker, runtime_->shadow()->shadow()[i]);
    }
  }
}

TEST_F(BlockHeapManagerTest, QuarantineIsShared) {
  const uint32_t kAllocSize = 100;
  const uint32_t real_alloc_size = GetAllocSize(kAllocSize);
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
  EXPECT_EQ(4, quarantine->GetCountForTesting());
  heap_2.ReleaseHeap();
  EXPECT_EQ(2, quarantine->GetCountForTesting());
  heap_1.ReleaseHeap();
  EXPECT_EQ(0, quarantine->GetCountForTesting());
}

TEST_F(BlockHeapManagerTest, AllocZeroBytes) {
  ScopedHeap heap(heap_manager_);
  void* mem1 = heap.Allocate(0);
  ASSERT_NE(static_cast<void*>(nullptr), mem1);
  void* mem2 = heap.Allocate(0);
  ASSERT_NE(static_cast<void*>(nullptr), mem2);
  ASSERT_NE(mem1, mem2);
  ASSERT_TRUE(heap.Free(mem1));
  ASSERT_TRUE(heap.Free(mem2));
}

TEST_F(BlockHeapManagerTest, AllocInvalidBlockSize) {
  ScopedHeap heap(heap_manager_);
  const size_t kInvalidSize = SIZE_MAX;
  void* mem = heap.Allocate(kInvalidSize);
  ASSERT_EQ(static_cast<void*>(nullptr), mem);
}

TEST_F(BlockHeapManagerTest, Size) {
  const size_t kMaxAllocSize = 134584;
  ScopedHeap heap(heap_manager_);
  for (size_t size = 10; size < kMaxAllocSize; size = size * 5 + 123) {
    void* mem = heap.Allocate(size);
    ASSERT_NE(static_cast<void*>(nullptr), mem);
    ASSERT_EQ(size, heap_manager_->Size(heap.Id(), mem));
    ASSERT_TRUE(heap.Free(mem));
  }
}

TEST_F(BlockHeapManagerTest, AllocsAccessibility) {
  const uint32_t kMaxAllocSize = 134584;
  ScopedHeap heap(heap_manager_);
  // Ensure that the quarantine is large enough to keep the allocated blocks in
  // this test.
  ::common::AsanParameters parameters = heap_manager_->parameters();
  parameters.quarantine_size = kMaxAllocSize * 2;
  heap_manager_->set_parameters(parameters);
  for (uint32_t size = 10; size < kMaxAllocSize; size = size * 5 + 123) {
    // Do an alloc/free and test that access is correctly managed.
    void* mem = heap.Allocate(size);
    ASSERT_NE(static_cast<void*>(nullptr), mem);
    ASSERT_NO_FATAL_FAILURE(VerifyAllocAccess(mem, size));
    ASSERT_TRUE(heap.Free(mem));
    ASSERT_NO_FATAL_FAILURE(VerifyFreedAccess(mem, size));
  }
}

TEST_F(BlockHeapManagerTest, LockUnlock) {
  ScopedHeap heap(heap_manager_);
  // We can't really test these, aside from not crashing.
  ASSERT_NO_FATAL_FAILURE(heap_manager_->Lock(heap.Id()));
  ASSERT_NO_FATAL_FAILURE(heap_manager_->Unlock(heap.Id()));
}

TEST_F(BlockHeapManagerTest, CaptureTID) {
  const size_t kAllocSize = 13;
  ScopedHeap heap(heap_manager_);
  // Ensure that the quarantine is large enough to keep this block.
  ::common::AsanParameters parameters = heap_manager_->parameters();
  parameters.quarantine_size = GetAllocSize(kAllocSize);
  heap_manager_->set_parameters(parameters);
  uint8_t* mem = static_cast<uint8_t*>(heap.Allocate(kAllocSize));
  BlockBody* body = reinterpret_cast<BlockBody*>(mem);
  ASSERT_TRUE(heap.Free(mem));
  BlockHeader* header = BlockGetHeaderFromBody(body);
  ASSERT_NE(static_cast<BlockHeader*>(nullptr), header);
  EXPECT_TRUE(header->state == QUARANTINED_BLOCK ||
              header->state == QUARANTINED_FLOODED_BLOCK);
  BlockInfo block_info = {};
  EXPECT_TRUE(BlockInfoFromMemory(header, &block_info));
  EXPECT_NE(static_cast<BlockTrailer*>(nullptr), block_info.trailer);

  EXPECT_EQ(block_info.trailer->alloc_tid, ::GetCurrentThreadId());
  EXPECT_EQ(block_info.trailer->free_tid, ::GetCurrentThreadId());
}

TEST_F(BlockHeapManagerTest, QuarantineNeverAltersBlockContents) {
  // No blocks should be flood-filled when the feature is disabled.
  EXPECT_NO_FATAL_FAILURE(QuarantineAltersBlockContents(0.0f, 10, 0, 0));
}

TEST_F(BlockHeapManagerTest, QuarantineSometimesAltersBlockContents) {
  // 100 fair coin tosses has a stddev of 5. The flood filled count will pretty
  // much always be within 3 stddevs of half of the tests unless something went
  // terribly wrong.
  EXPECT_NO_FATAL_FAILURE(QuarantineAltersBlockContents(
      0.5f, 100, 50 - 3 * 5, 50 + 3 * 5));
}

TEST_F(BlockHeapManagerTest, QuarantineAlwaysAltersBlockContents) {
  // All blocks should be flood-filled.
  EXPECT_NO_FATAL_FAILURE(QuarantineAltersBlockContents(1.0f, 10, 10, 10));
}

TEST_F(BlockHeapManagerTest, SetTrailerPaddingSize) {
  const size_t kAllocSize = 13;
  ScopedHeap heap(heap_manager_);
  // Ensure that the quarantine is large enough to keep this block with the
  // extra padding.
  ::common::AsanParameters parameters = heap_manager_->parameters();
  parameters.quarantine_size = GetAllocSize(kAllocSize) * 5;
  heap_manager_->set_parameters(parameters);
  uint32_t original_alloc_size = GetAllocSize(kAllocSize);
  ::common::AsanParameters original_parameter = heap_manager_->parameters();

  for (uint32_t padding = 0; padding < 16; ++padding) {
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
      EXPECT_FALSE(runtime_->shadow()->IsAccessible(
          reinterpret_cast<const uint8_t*>(mem) + offset));
    }
    ASSERT_TRUE(heap.Free(mem));
  }
  heap_manager_->set_parameters(original_parameter);
}

TEST_F(BlockHeapManagerTest, BlockChecksumUpdatedWhenEnterQuarantine) {
  const uint32_t kAllocSize = 100;
  uint32_t real_alloc_size = GetAllocSize(kAllocSize);
  ScopedHeap heap(heap_manager_);

  ::common::AsanParameters parameters = heap_manager_->parameters();
  parameters.quarantine_size = real_alloc_size;
  heap_manager_->set_parameters(parameters);

  void* mem = heap.Allocate(kAllocSize);
  ASSERT_NE(static_cast<void*>(nullptr), mem);
  BlockInfo block_info = {};
  EXPECT_TRUE(runtime_->shadow()->BlockInfoFromShadow(mem, &block_info));
  EXPECT_TRUE(BlockChecksumIsValid(block_info));
  heap.Free(mem);
  EXPECT_TRUE(BlockChecksumIsValid(block_info));
  ASSERT_TRUE(heap.InQuarantine(mem));
}

static const size_t kChecksumRepeatCount = 10;

TEST_F(BlockHeapManagerTest, CorruptAsEntersQuarantine) {
  const uint32_t kAllocSize = 100;
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

TEST_F(BlockHeapManagerTest, CorruptAsExitsQuarantine) {
  const uint32_t kAllocSize = 100;
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
    reinterpret_cast<int32_t*>(mem)[0] = rand();
    heap.FlushQuarantine();

    // Try again for all but the last attempt if this appears to have failed.
    if (errors_.empty() && i + 1 < kChecksumRepeatCount)
      continue;

    EXPECT_EQ(1u, errors_.size());
    EXPECT_EQ(CORRUPT_BLOCK, errors_[0].error_type);
    EXPECT_EQ(reinterpret_cast<const BlockHeader*>(mem) - 1,
              reinterpret_cast<const BlockHeader*>(errors_[0].location));

    break;
  }
}

TEST_F(BlockHeapManagerTest, CorruptAsExitsQuarantineOnHeapDestroy) {
  const uint32_t kAllocSize = 100;
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
      reinterpret_cast<int32_t*>(mem)[0] = rand();
    }

    // The destructor of |heap| should be called and all the quarantined blocks
    // belonging to this heap should be freed, which should trigger an error as
    // the block is now corrupt.

    // Try again for all but the last attempt if this appears to have failed.
    if (errors_.empty() && i + 1 < kChecksumRepeatCount)
      continue;

    EXPECT_EQ(1u, errors_.size());
    EXPECT_EQ(CORRUPT_BLOCK, errors_[0].error_type);
    EXPECT_EQ(reinterpret_cast<const BlockHeader*>(mem) - 1,
              reinterpret_cast<const BlockHeader*>(errors_[0].location));

    break;
  }
}

TEST_F(BlockHeapManagerTest, CorruptHeapOnTrimQuarantine) {
  const uint32_t kAllocSize = 100;
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
      reinterpret_cast<int32_t*>(mem)[0] = rand();
    }

    // The destructor of |heap| should be called and all the quarantined blocks
    // belonging to this heap should be freed, which should trigger an error as
    // the block is now corrupt.

    // Try again for all but the last attempt if this appears to have failed.
    if (errors_.empty() && i + 1 < kChecksumRepeatCount)
      continue;

    EXPECT_EQ(1u, errors_.size());
    EXPECT_EQ(CORRUPT_BLOCK, errors_[0].error_type);
    EXPECT_EQ(reinterpret_cast<const BlockHeader*>(mem) - 1,
              reinterpret_cast<const BlockHeader*>(errors_[0].location));

    break;
  }
}

// Prevent this test from being optimized, otherwise the loop that does the
// blocks allocations might get unwound and they won't have the same allocation
// stack trace.
#pragma optimize("", off)
TEST_F(BlockHeapManagerTest, CorruptionIsReportedOnlyOnce) {
  const size_t kAllocSize = 100;
  const size_t kAllocs = 100;
  ASSERT_GT(kAllocs, kChecksumRepeatCount);
  ::common::AsanParameters parameters = heap_manager_->parameters();
  parameters.quarantine_size = kAllocs * GetAllocSize(kAllocSize);
  parameters.prevent_duplicate_corruption_crashes = true;
  heap_manager_->set_parameters(parameters);

  ScopedHeap heap(heap_manager_);
  std::vector<void*> allocs(kAllocs);

  // Allocate and free a lot of blocks with an identical stack id and corrupt
  // them while they're in the quarantine.
  for (size_t i = 0; i < kAllocs; ++i) {
    void* mem = heap.Allocate(kAllocSize);
    ASSERT_NE(static_cast<void*>(nullptr), mem);
    EXPECT_TRUE(heap.Free(mem));
    EXPECT_TRUE(errors_.empty());

    // Change some of the block content to corrupt it.
    reinterpret_cast<int32_t*>(mem)[0] ^= 0xFFFFFFFF;
  }

  // Empty the quarantine and free all the blocks that were in it. We should be
  // reporting an error only for the first one.
  BlockQuarantineInterface::ObjectVector blocks;
  heap.GetQuarantine()->Empty(&blocks);
  bool first_corrupt_block_has_been_found = false;
  size_t i = 0;
  for (auto block : blocks) {
    errors_.clear();
    BlockInfo block_info = {};
    ConvertBlockInfo(block, &block_info);
    heap_manager_->FreePotentiallyCorruptBlock(&block_info);
    if (!first_corrupt_block_has_been_found && i < kChecksumRepeatCount) {
      if (!errors_.empty()) {
        EXPECT_EQ(1u, errors_.size());
        EXPECT_EQ(CORRUPT_BLOCK, errors_[0].error_type);
        first_corrupt_block_has_been_found = true;
      }
    } else {
      EXPECT_TRUE(errors_.empty());
    }
    ++i;
  }
}
#pragma optimize("", on)

TEST_F(BlockHeapManagerTest, DoubleFree) {
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

TEST_F(BlockHeapManagerTest, SubsampledAllocationGuards) {
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

    for (size_t i = 0; i < alloc_size; ++i) {
      EXPECT_TRUE(runtime_->shadow()->IsAccessible(
          reinterpret_cast<uint8_t*>(alloc) + i));
    }

    // Determine if the allocation has guards or not.
    BlockHeader* header = BlockGetHeaderFromBody(
        reinterpret_cast<BlockBody*>(alloc));
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
TEST_F(BlockHeapManagerTest, ZebraHeapIdInTrailerAfterAllocation) {
  EnableTestZebraBlockHeap();
  ScopedHeap heap(heap_manager_);
  const size_t kAllocSize = 0x100;
  void* alloc = heap.Allocate(kAllocSize);
  EXPECT_NE(static_cast<void*>(nullptr), alloc);
  ASSERT_NO_FATAL_FAILURE(VerifyAllocAccess(alloc, kAllocSize));

  // Get the heap_id from the block trailer.
  BlockInfo block_info = {};
  EXPECT_TRUE(runtime_->shadow()->BlockInfoFromShadow(alloc, &block_info));

  {
    ScopedBlockAccess block_access(block_info, runtime_->shadow());
    // The heap_id stored in the block trailer should match the zebra heap id.
    EXPECT_EQ(heap_manager_->zebra_block_heap_id_,
              block_info.trailer->heap_id);
  }

  EXPECT_TRUE(heap.Free(alloc));
}

// Ensures that the provided heap is used when the ZebraBlockHeap cannot handle
// the allocation.
TEST_F(BlockHeapManagerTest, DefaultHeapIdInTrailerWhenZebraHeapIsFull) {
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
  EXPECT_TRUE(runtime_->shadow()->BlockInfoFromShadow(alloc, &block_info));
  {
    ScopedBlockAccess block_access(block_info, runtime_->shadow());
    // The heap_id stored in the block trailer match the provided heap.
    EXPECT_EQ(heap.Id(), block_info.trailer->heap_id);
  }
  EXPECT_TRUE(heap.Free(alloc));
}

// Allocations larger than the page size (4KB) will not be served by the zebra
// heap.
TEST_F(BlockHeapManagerTest, AllocStress) {
  EnableTestZebraBlockHeap();
  ScopedHeap heap(heap_manager_);
  for (size_t i = 0; i < 3000; ++i) {
    // Sometimes allocate more than one page, to ensure that allocations get
    // spread across the ZebraBlockheap and normal heaps.
    const uint32_t kAllocSize = (i * 997) % (9 * 1024);
    void* alloc = heap.Allocate(kAllocSize);
    EXPECT_NE(static_cast<void*>(nullptr), alloc);
    ASSERT_NO_FATAL_FAILURE(VerifyAllocAccess(alloc, kAllocSize));
    // Free should succeed, even if the block is quarantined.
    EXPECT_TRUE(heap.Free(alloc));
  }
}

// The BlockHeapManager correctly quarantines the memory after free.
TEST_F(BlockHeapManagerTest, QuarantinedAfterFree) {
  EnableTestZebraBlockHeap();
  ScopedHeap heap(heap_manager_);
  // Always quarantine if possible.
  test_zebra_block_heap_->set_quarantine_ratio(1.0);

  const uint32_t kAllocSize = 0x100;
  void* alloc = heap.Allocate(kAllocSize);
  EXPECT_NE(static_cast<void*>(nullptr), alloc);
  ASSERT_NO_FATAL_FAILURE(VerifyAllocAccess(alloc, kAllocSize));
  // Free should succeed, even if the block is quarantined.
  EXPECT_TRUE(heap.Free(alloc));
  // The block should be quarantined and poisoned.
  ASSERT_NO_FATAL_FAILURE(VerifyFreedAccess(alloc, kAllocSize));
  BlockInfo block_info = {};
  EXPECT_TRUE(runtime_->shadow()->BlockInfoFromShadow(alloc, &block_info));

  {
    ScopedBlockAccess block_access(block_info, runtime_->shadow());
    EXPECT_TRUE(block_info.header->state == QUARANTINED_BLOCK ||
                block_info.header->state == QUARANTINED_FLOODED_BLOCK);
  }
}

// set_parameters should set the zebra_block_heap_quarantine_ratio flag
// correctly.
TEST_F(BlockHeapManagerTest, set_parametersSetsZebraBlockHeapQuarantineRatio) {
  EnableTestZebraBlockHeap();
  float new_ratio = 1.0f / 8;
  ::common::AsanParameters params = heap_manager_->parameters();
  params.zebra_block_heap_quarantine_ratio = new_ratio;
  heap_manager_->set_parameters(params);
  EXPECT_EQ(new_ratio, test_zebra_block_heap_->quarantine_ratio());
}

// Test for double free errors using the zebra heap.
TEST_F(BlockHeapManagerTest, DoubleFreeOnZebraHeap) {
  EnableTestZebraBlockHeap();
  ScopedHeap heap(heap_manager_);
  test_zebra_block_heap_->set_quarantine_ratio(1.0);

  const uint32_t kAllocSize = 0xFF;
  void* alloc = heap.Allocate(kAllocSize);
  EXPECT_NE(static_cast<void*>(nullptr), alloc);
  ASSERT_NO_FATAL_FAILURE(VerifyAllocAccess(alloc, kAllocSize));

  EXPECT_TRUE(heap.Free(alloc));
  EXPECT_FALSE(heap.Free(alloc));

  EXPECT_EQ(1u, errors_.size());
  EXPECT_EQ(DOUBLE_FREE, errors_[0].error_type);
  EXPECT_EQ(alloc, errors_[0].location);
}

TEST_F(BlockHeapManagerTest, AllocatedBlockIsProtected) {
  EnableTestZebraBlockHeap();
  ScopedHeap heap(heap_manager_);

  const uint32_t kAllocSize = 0xFF;
  void* alloc = heap.Allocate(kAllocSize);
  EXPECT_NE(static_cast<void*>(nullptr), alloc);
  ASSERT_NO_FATAL_FAILURE(VerifyAllocAccess(alloc, kAllocSize));

  BlockInfo block_info = {};
  EXPECT_TRUE(runtime_->shadow()->BlockInfoFromShadow(alloc, &block_info));

  // Test the block protections before being quarantined.
  // The whole block should be unpoisoned in the shadow memory.
  for (uint32_t i = 0; i < block_info.body_size; ++i)
    EXPECT_TRUE(runtime_->shadow()->IsAccessible(block_info.RawBody() + i));

  // Ensure that the block left redzone is page-protected.
  for (uint32_t i = 0; i < block_info.left_redzone_pages_size; ++i)
    EXPECT_TRUE(IsNotAccessible(block_info.left_redzone_pages + i));

  // Ensure that the block right redzone is page-protected.
  for (uint32_t i = 0; i < block_info.right_redzone_pages_size; ++i)
    EXPECT_TRUE(IsNotAccessible(block_info.right_redzone_pages + i));

  // The block body should be accessible.
  for (uint32_t i = 0; i < block_info.body_size; ++i)
    EXPECT_TRUE(IsAccessible(block_info.RawBody() + i));

  {
    ScopedBlockAccess block_access(block_info, runtime_->shadow());
    EXPECT_EQ(ALLOCATED_BLOCK, block_info.header->state);
  }

  EXPECT_TRUE(heap.Free(alloc));
}

TEST_F(BlockHeapManagerTest, QuarantinedBlockIsProtected) {
  EnableTestZebraBlockHeap();
  ScopedHeap heap(heap_manager_);
  // Always quarantine if possible.
  test_zebra_block_heap_->set_quarantine_ratio(1.0);

  for (uint32_t i = 0; i < 20; ++i) {
    const uint32_t kAllocSize = 0xFF + i;
    void* alloc = heap.Allocate(kAllocSize);
    EXPECT_NE(static_cast<void*>(nullptr), alloc);
    ASSERT_NO_FATAL_FAILURE(VerifyAllocAccess(alloc, kAllocSize));

    BlockInfo block_info = {};
    EXPECT_TRUE(runtime_->shadow()->BlockInfoFromShadow(alloc, &block_info));

    // The block is freed and quarantined.
    EXPECT_TRUE(heap.Free(alloc));

    // Test the block protections after being quarantined.
    // The whole block should be poisoned in the shadow memory.
    for (uint32_t i = 0; i < block_info.body_size; ++i) {
      EXPECT_FALSE(runtime_->shadow()->IsAccessible(block_info.RawBody() + i));
    }

    // Ensure that the block left redzone is page-protected.
    for (uint32_t i = 0; i < block_info.left_redzone_pages_size; ++i)
      EXPECT_TRUE(IsNotAccessible(block_info.left_redzone_pages + i));

    // Ensure that the block right redzone is page-protected.
    for (uint32_t i = 0; i < block_info.right_redzone_pages_size; ++i)
      EXPECT_TRUE(IsNotAccessible(block_info.right_redzone_pages + i));

    // Ensure that the block body is page-protected.
    for (uint32_t i = 0; i < block_info.body_size; ++i)
      EXPECT_TRUE(IsNotAccessible(block_info.RawBody() + i));

    {
      ScopedBlockAccess block_access(block_info, runtime_->shadow());
      EXPECT_TRUE(block_info.header->state == QUARANTINED_BLOCK ||
                  block_info.header->state == QUARANTINED_FLOODED_BLOCK);
    }
  }
}

TEST_F(BlockHeapManagerTest, NonQuarantinedBlockIsMarkedAsFreed) {
  EnableTestZebraBlockHeap();
  ScopedHeap heap(heap_manager_);
  // Desaible the zebra heap quarantine.
  test_zebra_block_heap_->set_refuse_push(true);

  const uint32_t kAllocSize = 0x100;
  void* alloc = heap.Allocate(kAllocSize);
  EXPECT_NE(static_cast<void*>(nullptr), alloc);
  ASSERT_NO_FATAL_FAILURE(VerifyAllocAccess(alloc, kAllocSize));

  BlockInfo block_info = {};
  EXPECT_TRUE(runtime_->shadow()->BlockInfoFromShadow(alloc, &block_info));

  // The block is freed but not quarantined.
  EXPECT_TRUE(heap.Free(alloc));

  // The whole block should be unpoisoned in the shadow memory, and its
  // associated pages unprotected.
  for (uint32_t i = 0; i < block_info.block_size; ++i) {
    ASSERT_NO_FATAL_FAILURE(runtime_->shadow()->IsAccessible(
        block_info.RawBlock() + i));
    ASSERT_FALSE(runtime_->shadow()->PageIsProtected(
        block_info.RawBlock() + i));
  }

  EXPECT_EQ(FREED_BLOCK, block_info.header->state);
}

TEST_F(BlockHeapManagerTest, ZebraBlockHeapQuarantineRatioIsRespected) {
  EnableTestZebraBlockHeap();
  ScopedHeap heap(heap_manager_);
  // Set a non-standard quarantine ratio.
  float quarantine_ratio = 0.37f;
  test_zebra_block_heap_->set_quarantine_ratio(quarantine_ratio);

  const uint32_t kAllocations = 2000;

  size_t zebra_heap_size = test_zebra_block_heap_->slab_count_;
  const size_t max_quarantine_size = zebra_heap_size * quarantine_ratio;

  // All allocations have a maximum size of 1KB, all are served by the zebra
  // heap.
  for (size_t i = 0; i < kAllocations; ++i) {
    const uint32_t kAllocSize = (0x100 + i) % 1024;
    void* alloc = heap.Allocate(kAllocSize);
    EXPECT_NE(static_cast<void*>(nullptr), alloc);

    BlockInfo block_info = {};
    EXPECT_TRUE(runtime_->shadow()->BlockInfoFromShadow(alloc, &block_info));
    EXPECT_TRUE(heap.Free(alloc));

    // After Free the quarantine should be trimmed, enforcing the quarantine
    // size upper bound.
    EXPECT_LE(test_zebra_block_heap_->GetCountForTesting(),
              max_quarantine_size);

    {
      ScopedBlockAccess block_access(block_info, runtime_->shadow());
      EXPECT_TRUE(block_info.header->state == QUARANTINED_BLOCK ||
                  block_info.header->state == QUARANTINED_FLOODED_BLOCK);
    }
  }
}

// Ensures that the LargeBlockHeap overrides the provided heap if the allocation
// size exceeds the threshold.
TEST_F(BlockHeapManagerTest, LargeBlockHeapUsedForLargeAllocations) {
  EnableLargeBlockHeap(static_cast<uint32_t>(GetPageSize()));

  // Disable targeted heaps as it interferes with this test.
  ::common::AsanParameters params = heap_manager_->parameters();
  heap_manager_->SetParameters(params);

  ScopedHeap heap(heap_manager_);

  const uint32_t kAllocSize = static_cast<uint32_t>(GetPageSize()) + 0x100;
  void* alloc = heap.Allocate(kAllocSize);
  EXPECT_NE(static_cast<void*>(nullptr), alloc);
  ASSERT_NO_FATAL_FAILURE(VerifyAllocAccess(alloc, kAllocSize));

  // Get the heap_id from the block trailer.
  BlockInfo block_info = {};
  EXPECT_TRUE(runtime_->shadow()->BlockInfoFromShadow(alloc, &block_info));

  {
    ScopedBlockAccess block_access(block_info, runtime_->shadow());
    // The heap_id stored in the block trailer should match the large block
    // heap id.
    EXPECT_EQ(heap_manager_->large_block_heap_id_,
              block_info.trailer->heap_id);
  }

  EXPECT_TRUE(heap.Free(alloc));
}

// Ensures that the LargeBlockHeap is not used for a small allocation.
TEST_F(BlockHeapManagerTest, LargeBlockHeapNotUsedForSmallAllocations) {
  EnableLargeBlockHeap(static_cast<uint32_t>(GetPageSize()));
  ScopedHeap heap(heap_manager_);

  const uint32_t kAllocSize = 0x100;
  void* alloc = heap.Allocate(kAllocSize);
  EXPECT_NE(static_cast<void*>(nullptr), alloc);
  ASSERT_NO_FATAL_FAILURE(VerifyAllocAccess(alloc, kAllocSize));

  // Get the heap_id from the block trailer.
  BlockInfo block_info = {};
  EXPECT_TRUE(runtime_->shadow()->BlockInfoFromShadow(alloc, &block_info));

  {
    ScopedBlockAccess block_access(block_info, runtime_->shadow());
    // The provided heap ID should be the one in the block trailer.
    EXPECT_EQ(heap.Id(), block_info.trailer->heap_id);
  }

  EXPECT_TRUE(heap.Free(alloc));
}

TEST_F(BlockHeapManagerTest, AllocationFilterFlag) {
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

TEST_F(BlockHeapManagerTest, BestEffortLockAllNoLocksHeld) {
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

TEST_F(BlockHeapManagerTest, BestEffortLockAllOneHeapLockHeld) {
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

TEST_F(BlockHeapManagerTest, IsValidHeapIdUnlocked) {
  ASSERT_FALSE(heap_manager_->heaps_.empty());
  EXPECT_FALSE(heap_manager_->IsValidHeapIdUnlocked(0xDEADBEEF, false));
  for (auto& hq_pair : heap_manager_->heaps_) {
    TestBlockHeapManager::HeapQuarantinePair* hq = &hq_pair;
    TestBlockHeapManager::HeapId heap_id =
        reinterpret_cast<TestBlockHeapManager::HeapId>(hq);
    EXPECT_TRUE(heap_manager_->IsValidHeapIdUnlocked(heap_id, false));
  }
}

TEST_F(BlockHeapManagerTest, GetHeapTypeUnlocked) {
  ASSERT_FALSE(heap_manager_->heaps_.empty());
  for (auto& hq_pair : heap_manager_->heaps_) {
    TestBlockHeapManager::HeapQuarantinePair* hq = &hq_pair;
    TestBlockHeapManager::HeapId heap_id =
        reinterpret_cast<TestBlockHeapManager::HeapId>(hq);
    EXPECT_NE(kUnknownHeapType, heap_manager_->GetHeapTypeUnlocked(heap_id));
  }
}

TEST_F(BlockHeapManagerTest, ComputeRelativeStackId) {
  // This test is done here and not in stack_capture_unittest, as the latter
  // doesn't have the provision for faking the module address and would
  // therefore ignore all the frames.
  common::StackCapture stack;
  stack.InitFromStack();

  EXPECT_NE(0U, stack.relative_stack_id());
}

TEST_F(BlockHeapManagerTest, EnableDeferredFreeThreadTest) {
  ScopedHeap heap(heap_manager_);
  ASSERT_FALSE(heap_manager_->IsDeferredFreeThreadRunning());
  heap_manager_->EnableDeferredFreeThread();
  ASSERT_TRUE(heap_manager_->IsDeferredFreeThreadRunning());
  heap_manager_->DisableDeferredFreeThread();
  ASSERT_FALSE(heap_manager_->IsDeferredFreeThreadRunning());
}

TEST_F(BlockHeapManagerTest, DeferredFreeThreadTest) {
  const uint32_t kAllocSize = 100;
  const uint32_t kTargetMaxYellow = 10;
  uint32_t real_alloc_size = GetAllocSize(kAllocSize);
  ScopedHeap heap(heap_manager_);

  ::common::AsanParameters parameters = heap_manager_->parameters();
  parameters.quarantine_size = real_alloc_size * kTargetMaxYellow;
  heap_manager_->set_parameters(parameters);

  size_t max_size_yellow =
      heap_manager_->shared_quarantine_.GetMaxSizeForColorForTesting(YELLOW) /
      real_alloc_size;

  ASSERT_EQ(kTargetMaxYellow, max_size_yellow);

  // Blocks the callback until it gets signaled.
  base::WaitableEvent deferred_free_callback_start(false, false);
  // Gets signaled by the callback this it's done executing.
  base::WaitableEvent deferred_free_callback_end(false, false);
  heap_manager_->EnableDeferredFreeWithSync(&deferred_free_callback_start,
                                            &deferred_free_callback_end);
  ASSERT_TRUE(heap_manager_->IsDeferredFreeThreadRunning());

  // Overshoot the YELLOW size (into RED) then start and wait for the callback
  // to be executed. The quarantine should to be back to GREEN.
  for (int i = 0; i < max_size_yellow + 1; i++) {
    void* heap_mem = heap.Allocate(kAllocSize);
    ASSERT_NE(static_cast<void*>(nullptr), heap_mem);
    heap.Free(heap_mem);
  }

  size_t current_size = heap_manager_->shared_quarantine_.GetSizeForTesting();
  ASSERT_EQ(RED,
            heap_manager_->shared_quarantine_.GetQuarantineColor(current_size));

  // Signal the callback to execute and for it to finish.
  deferred_free_callback_start.Signal();
  deferred_free_callback_end.Wait();

  current_size = heap_manager_->shared_quarantine_.GetSizeForTesting();
  EXPECT_EQ(GREEN,
            heap_manager_->shared_quarantine_.GetQuarantineColor(current_size));

  heap_manager_->DisableDeferredFreeThread();
  EXPECT_FALSE(heap_manager_->IsDeferredFreeThreadRunning());
}

namespace {

// Helper function for extracting the two default heaps.
void GetHeapIds(TestBlockHeapManager* heap_manager,
                HeapId* large_block_heap,
                HeapId* win_heap) {
  ASSERT_TRUE(heap_manager);
  ASSERT_TRUE(large_block_heap);
  ASSERT_TRUE(win_heap);
  ASSERT_EQ(2u, heap_manager->heaps_.size());

  *large_block_heap = 0;
  *win_heap = 0;

  for (auto h = heap_manager->heaps_.begin();
       h != heap_manager->heaps_.end(); ++h) {
    HeapId heap_id = heap_manager->GetHeapId(h);
    if (h->first->GetHeapType() == kWinHeap) {
      *win_heap = heap_id;
    } else {
      ASSERT_EQ(kLargeBlockHeap, h->first->GetHeapType());
      *large_block_heap = heap_id;
    }
  }

  ASSERT_NE(0u, *large_block_heap);
  ASSERT_NE(0u, *win_heap);
}

}  // namespace

TEST_F(BlockHeapManagerTest, GetCorruptBlockHeapIdTrailerIsGood) {
  // Disable page protections so that the LBH allocated block can be
  // accessed.
  heap_manager_->enable_page_protections_ = false;

  HeapId lbh = 0;
  HeapId wh = 0;
  GetHeapIds(heap_manager_, &lbh, &wh);

  // Create a second win heap. This means that there are multiple heaps
  // not supporting IsAllocated.
  heap_manager_->CreateHeap();

  void* alloc = heap_manager_->Allocate(lbh, 64 * 4096);
  BlockInfo bi = {};
  GetBlockInfo(
      heap_manager_->shadow_, reinterpret_cast<BlockBody*>(alloc), &bi);

  // Test that the heap ID is correctly returned even in one of many
  // non-reporting heaps, given that the correct heap id is actually in the
  // trailer.
  EXPECT_EQ(lbh, heap_manager_->GetCorruptBlockHeapId(&bi));
}

TEST_F(BlockHeapManagerTest, GetCorruptBlockHeapIdInReportingHeap) {
  // Disable page protections so that the LBH allocated block can be
  // accessed.
  heap_manager_->enable_page_protections_ = false;

  HeapId lbh = 0;
  HeapId wh = 0;
  GetHeapIds(heap_manager_, &lbh, &wh);

  // Create a second win heap. This means that there are multiple heaps
  // not supporting IsAllocated.
  heap_manager_->CreateHeap();

  void* alloc = heap_manager_->Allocate(lbh, 32);
  BlockInfo bi = {};
  GetBlockInfo(
      heap_manager_->shadow_, reinterpret_cast<BlockBody*>(alloc), &bi);
  bi.trailer->heap_id = 0;

  // Test the the correct heap is found, even though there are multiple
  // non-reporting heaps and the trailer is corrupt.
  EXPECT_EQ(lbh, heap_manager_->GetCorruptBlockHeapId(&bi));
}

TEST_F(BlockHeapManagerTest, GetCorruptBlockHeapIdInSingleNonReportingHeap) {
  HeapId lbh = 0;
  HeapId wh = 0;
  GetHeapIds(heap_manager_, &lbh, &wh);

  void* alloc = heap_manager_->Allocate(wh, 32);
  BlockInfo bi = {};
  GetBlockInfo(
      heap_manager_->shadow_, reinterpret_cast<BlockBody*>(alloc), &bi);
  bi.trailer->heap_id = 0;

  // Test the the correct heap is found, even though its a non-reporting heap
  // and the trailer is corrupt.
  EXPECT_EQ(wh, heap_manager_->GetCorruptBlockHeapId(&bi));
}

TEST_F(BlockHeapManagerTest, GetCorruptBlockHeapIdNotFound) {
  HeapId lbh = 0;
  HeapId wh = 0;
  GetHeapIds(heap_manager_, &lbh, &wh);

  // Create a second win heap. This means that there are multiple heaps
  // not supporting IsAllocated.
  heap_manager_->CreateHeap();

  void* alloc = heap_manager_->Allocate(wh, 32);
  BlockInfo bi = {};
  GetBlockInfo(
      heap_manager_->shadow_, reinterpret_cast<BlockBody*>(alloc), &bi);
  bi.trailer->heap_id = 0;

  // Expect this to fail, as there are multiple non-reporting heaps and
  // the block trailer is corrupt.
  EXPECT_EQ(0u, heap_manager_->GetCorruptBlockHeapId(&bi));
}

TEST_F(BlockHeapManagerTest, FreeCorruptedBlockWorks) {
  // Enable to registry filter.
  heap_manager_->parameters_.prevent_duplicate_corruption_crashes = true;

  HeapId lbh = 0;
  HeapId wh = 0;
  GetHeapIds(heap_manager_, &lbh, &wh);

  void* alloc = heap_manager_->Allocate(wh, 32);
  BlockInfo bi = {};
  GetBlockInfo(
      heap_manager_->shadow_, reinterpret_cast<BlockBody*>(alloc), &bi);

  // Add the stack ID to the registry cache, so that it will decide not
  // to crash upon freeing.
  heap_manager_->corrupt_block_registry_cache_->AddOrUpdateStackId(
      bi.header->alloc_stack->relative_stack_id());

  // Clear the heap ID and delete the block, expecting this to succeed.
  bi.trailer->heap_id = 0;
  EXPECT_TRUE(heap_manager_->Free(wh, alloc));
}

}  // namespace heap_managers
}  // namespace asan
}  // namespace agent
