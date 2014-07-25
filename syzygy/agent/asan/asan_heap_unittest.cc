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

#include "syzygy/agent/asan/asan_heap.h"

#include <algorithm>

#include "base/bind.h"
#include "base/bits.h"
#include "base/rand_util.h"
#include "base/sha1.h"
#include "gtest/gtest.h"
#include "syzygy/agent/asan/asan_logger.h"
#include "syzygy/agent/asan/asan_runtime.h"
#include "syzygy/agent/asan/shadow.h"
#include "syzygy/agent/asan/unittest_util.h"
#include "syzygy/common/align.h"
#include "syzygy/trace/common/clock.h"

namespace agent {
namespace asan {

namespace {

// A derived class to expose protected members for unit-testing.
class TestShadow : public Shadow {
 public:
  using Shadow::kShadowSize;
  using Shadow::shadow_;
};

// A derived class to expose protected members for unit-testing.
class TestHeapProxy : public HeapProxy {
 public:
  using HeapProxy::AsanShardedQuarantine;
  using HeapProxy::GetAllocSize;
  using HeapProxy::InitializeAsanBlock;
  using HeapProxy::kDefaultAllocGranularityLog;
  using HeapProxy::quarantine_;

  TestHeapProxy() { }

  // A derived class to expose protected members for unit-testing. This has to
  // be nested into this one because AsanShardedQuarantine accesses some
  // protected fields of HeapProxy.
  //
  // This class should only expose some members or expose new functions, no new
  // member should be added.
  class TestQuarantine : public AsanShardedQuarantine {
   public:
    using AsanShardedQuarantine::Node;
    using AsanShardedQuarantine::kShardingFactor;
    using AsanShardedQuarantine::heads_;
  };

  // Calculates the underlying allocation size for an allocation of @p bytes.
  // This assume a granularity of @p kDefaultAllocGranularity bytes.
  static size_t GetAllocSize(size_t bytes) {
    return GetAllocSize(bytes, kDefaultAllocGranularity);
  }

  // Determines if the address @p mem corresponds to a block in quarantine.
  bool InQuarantine(const void* mem) {
    // As we'll cast an AsanShardedQuarantine directly into a TestQuarantine
    // there shouldn't be any new field defined by this class, this should only
    // act as an interface allowing to access some private fields.
    COMPILE_ASSERT(
        sizeof(TestQuarantine) == sizeof(TestHeapProxy::AsanShardedQuarantine),
        test_quarantine_is_not_an_interface);
    base::AutoLock lock(lock_);
    TestQuarantine* test_quarantine =
        reinterpret_cast<TestQuarantine*>(&quarantine_);
    // Search through all of the shards.
    for (size_t i = 0; i < test_quarantine->kShardingFactor; ++i) {
      // Search through all blocks in each shard.
      TestQuarantine::Node* current_node = test_quarantine->heads_[i];
      while (current_node != NULL) {
        BlockInfo block_info = {};
        EXPECT_TRUE(BlockInfoFromMemory(current_node->object, &block_info));
        if (block_info.body == mem) {
          EXPECT_TRUE(current_node->object->state == QUARANTINED_BLOCK);
          return true;
        }
        current_node = current_node->next;
      }
    }

    return false;
  }

  // This is a convoluted way of clearing the quarantine. This is necessary to
  // impose determinism for some unittests, as quarantine eviction is random.
  void PurgeQuarantine() {
    size_t max_size = quarantine_max_size();
    size_t max_block_size = quarantine_max_block_size();

    SetQuarantineMaxSize(1);
    EXPECT_EQ(0u, quarantine_.size());

    SetQuarantineMaxSize(max_size);
    SetQuarantineMaxBlockSize(max_block_size);
  }
};

class HeapTest : public testing::TestWithAsanLogger {
 public:
  HeapTest() : stack_cache_(&logger_) {
  }

  virtual void SetUp() OVERRIDE {
    testing::TestWithAsanLogger::SetUp();

    HeapProxy::Init(&stack_cache_);
    Shadow::SetUp();

    logger_.set_instance_id(instance_id());
    logger_.Init();
    ASSERT_TRUE(proxy_.Create(0, 0, 0));

    // Set the error callback that the proxy will use.
    proxy_.SetHeapErrorCallback(
        base::Bind(&HeapTest::OnHeapError, base::Unretained(this)));

    // Reset the allocation guard rate to being disabled.
    proxy_.set_allocation_guard_rate(1.0);
  }

  virtual void TearDown() OVERRIDE {
    ASSERT_TRUE(proxy_.Destroy());
    Shadow::TearDown();
    testing::TestWithAsanLogger::TearDown();
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
                Shadow::kHeapFreedByte);
    }
    ASSERT_FALSE(Shadow::IsAccessible(mem + size));
  }

  void RandomSetMemory(void* alloc, size_t size) {
    base::RandBytes(alloc, size);
  }

  void OnHeapError(AsanErrorInfo* error) {
    errors_.push_back(*error);
  }

 protected:
  // Arbitrary constant for all size limit.
  static const size_t kMaxAllocSize = 134584;

  AsanLogger logger_;
  StackCaptureCache stack_cache_;
  TestHeapProxy proxy_;

  // Info about the last errors reported.
  std::vector<AsanErrorInfo> errors_;
};

}  // namespace

TEST_F(HeapTest, SetDefaultQuarantineSizeCapsMaxBlockSize) {
  size_t max_size = proxy_.default_quarantine_max_size();
  size_t max_block_size = proxy_.default_quarantine_max_block_size();

  proxy_.set_default_quarantine_max_size(100);
  proxy_.set_default_quarantine_max_block_size(50);
  EXPECT_EQ(100u, proxy_.default_quarantine_max_size());
  EXPECT_EQ(50u, proxy_.default_quarantine_max_block_size());

  proxy_.set_default_quarantine_max_size(25);
  EXPECT_EQ(25u, proxy_.default_quarantine_max_size());
  EXPECT_EQ(25u, proxy_.default_quarantine_max_block_size());

  proxy_.set_default_quarantine_max_block_size(50);
  EXPECT_EQ(25u, proxy_.default_quarantine_max_size());
  EXPECT_EQ(25u, proxy_.default_quarantine_max_block_size());

  // Return the defaults to their true defaults for the remaining tests. This
  // prevents this unittest from having side effects.
  proxy_.set_default_quarantine_max_size(max_size);
  proxy_.set_default_quarantine_max_block_size(max_block_size);
  EXPECT_EQ(max_size, proxy_.default_quarantine_max_size());
  EXPECT_EQ(max_block_size, proxy_.default_quarantine_max_block_size());
}

TEST_F(HeapTest, ToFromHandle) {
  HANDLE handle = HeapProxy::ToHandle(&proxy_);
  ASSERT_TRUE(handle != NULL);
  ASSERT_EQ(&proxy_, HeapProxy::FromHandle(handle));
}

TEST_F(HeapTest, SetQuarantineMaxSize) {
  size_t quarantine_size = proxy_.quarantine_max_size() * 2;
  // Increments the quarantine max size if it was set to 0.
  if (quarantine_size == 0)
    quarantine_size++;
  proxy_.SetQuarantineMaxSize(quarantine_size);
  ASSERT_EQ(quarantine_size, proxy_.quarantine_max_size());
}

TEST_F(HeapTest, SetQuarantineSizeCapsMaxBlockSize) {
  proxy_.SetQuarantineMaxSize(100);
  proxy_.SetQuarantineMaxBlockSize(50);
  EXPECT_EQ(100u, proxy_.quarantine_max_size());
  EXPECT_EQ(50u, proxy_.quarantine_max_block_size());
}

TEST_F(HeapTest, PopOnSetQuarantineMaxSize) {
  const size_t kAllocSize = 100;
  const size_t real_alloc_size = TestHeapProxy::GetAllocSize(kAllocSize);
  LPVOID mem = proxy_.Alloc(0, kAllocSize);
  ASSERT_FALSE(proxy_.InQuarantine(mem));

  proxy_.SetQuarantineMaxSize(real_alloc_size);
  ASSERT_TRUE(proxy_.Free(0, mem));
  ASSERT_TRUE(proxy_.InQuarantine(mem));

  // We resize the quarantine to a smaller size, the block should pop out.
  proxy_.SetQuarantineMaxSize(real_alloc_size - 1);
  ASSERT_FALSE(proxy_.InQuarantine(mem));
}

TEST_F(HeapTest, Quarantine) {
  const size_t kAllocSize = 100;
  const size_t real_alloc_size = TestHeapProxy::GetAllocSize(kAllocSize);
  const size_t number_of_allocs = 16;
  proxy_.SetQuarantineMaxSize(real_alloc_size * number_of_allocs);

  // Allocate a bunch of blocks until exactly one is removed from the
  // quarantine.
  std::vector<LPVOID> blocks;
  for (size_t i = 0; i < number_of_allocs + 1; ++i) {
    LPVOID mem = proxy_.Alloc(0, kAllocSize);
    ASSERT_TRUE(mem != NULL);
    ASSERT_TRUE(proxy_.Free(0, mem));
    blocks.push_back(mem);
    if (i < number_of_allocs) {
      ASSERT_TRUE(proxy_.InQuarantine(mem));
    }
  }

  size_t blocks_in_quarantine = 0;
  for (size_t i = 0; i < blocks.size(); ++i) {
    if (proxy_.InQuarantine(blocks[i]))
      ++blocks_in_quarantine;
  }
  EXPECT_EQ(number_of_allocs, blocks_in_quarantine);
}

TEST_F(HeapTest, QuarantineLargeBlock) {
  proxy_.SetQuarantineMaxSize(100);
  proxy_.SetQuarantineMaxBlockSize(100);

  // A block larger than the quarantine should not make it in.
  LPVOID mem1 = proxy_.Alloc(0, 200);
  ASSERT_TRUE(mem1 != NULL);
  EXPECT_TRUE(proxy_.Free(0, mem1));
  EXPECT_FALSE(proxy_.InQuarantine(mem1));
  EXPECT_EQ(0u, proxy_.quarantine_.size());

  // A big block should make it because our current max block size allows it.
  LPVOID mem2 = proxy_.Alloc(0, 25);
  ASSERT_TRUE(mem2 != NULL);
  EXPECT_TRUE(proxy_.Free(0, mem2));
  EXPECT_TRUE(proxy_.InQuarantine(mem2));

  proxy_.SetQuarantineMaxBlockSize(20);

  // A second big block should not make it in since we changed the block size.
  // However, the other block should remain in the quarantine.
  LPVOID mem3 = proxy_.Alloc(0, 25);
  ASSERT_TRUE(mem3 != NULL);
  EXPECT_TRUE(proxy_.Free(0, mem3));
  EXPECT_TRUE(proxy_.InQuarantine(mem2));
  EXPECT_FALSE(proxy_.InQuarantine(mem3));
}

TEST_F(HeapTest, UnpoisonsQuarantine) {
  const size_t kAllocSize = 100;
  const size_t real_alloc_size = TestHeapProxy::GetAllocSize(kAllocSize);
  proxy_.SetQuarantineMaxSize(real_alloc_size);

  // Allocate a memory block and directly free it, this puts it in the
  // quarantine.
  void* mem = proxy_.Alloc(0, kAllocSize);
  ASSERT_TRUE(mem != NULL);
  ASSERT_TRUE(proxy_.Free(0, mem));
  ASSERT_TRUE(proxy_.InQuarantine(mem));

  // Assert that the shadow memory has been correctly poisoned.
  intptr_t mem_start = reinterpret_cast<intptr_t>(BlockGetHeaderFromBody(mem));
  ASSERT_EQ(0, (mem_start & 7) );
  size_t shadow_start = mem_start >> 3;
  size_t shadow_alloc_size = real_alloc_size >> 3;
  for (size_t i = shadow_start; i < shadow_start + shadow_alloc_size; ++i)
    ASSERT_NE(TestShadow::kHeapAddressableByte, TestShadow::shadow_[i]);


  // Flush the quarantine.
  proxy_.SetQuarantineMaxSize(0);

  // Assert that the quarantine has been correctly unpoisoned.
  for (size_t i = shadow_start; i < shadow_start + shadow_alloc_size; ++i)
    ASSERT_EQ(TestShadow::kHeapAddressableByte, TestShadow::shadow_[i]);

}

TEST_F(HeapTest, Realloc) {
  const size_t kAllocSize = 100;
  // As a special case, a realloc with a NULL input should succeed.
  LPVOID mem = proxy_.ReAlloc(0, NULL, kAllocSize);
  ASSERT_TRUE(mem != NULL);
  mem = proxy_.ReAlloc(0, mem, kAllocSize + 5);
  ASSERT_TRUE(mem != NULL);

  // We always fail reallocs with the in-place flag.
  ASSERT_EQ(NULL,
            proxy_.ReAlloc(HEAP_REALLOC_IN_PLACE_ONLY, NULL, kAllocSize));
  ASSERT_EQ(NULL,
            proxy_.ReAlloc(HEAP_REALLOC_IN_PLACE_ONLY, mem, kAllocSize - 10));
  ASSERT_EQ(NULL,
            proxy_.ReAlloc(HEAP_REALLOC_IN_PLACE_ONLY, mem, kAllocSize + 10));

  ASSERT_TRUE(proxy_.Free(0, mem));
}

TEST_F(HeapTest, AllocFree) {
  const size_t kAllocSize = 100;
  LPVOID mem = proxy_.Alloc(0, kAllocSize);
  ASSERT_TRUE(mem != NULL);
  ASSERT_EQ(kAllocSize, proxy_.Size(0, mem));
  const size_t kReAllocSize = 2 * kAllocSize;
  mem = proxy_.ReAlloc(0, mem, kReAllocSize);
  ASSERT_EQ(kReAllocSize, proxy_.Size(0, mem));
  ASSERT_TRUE(proxy_.Free(0, mem));
}

TEST_F(HeapTest, DoubleFree) {
  const size_t kAllocSize = 100;
  // Ensure that the quarantine is large enough to keep this block, this is
  // needed for the use-after-free check.
  proxy_.SetQuarantineMaxSize(TestHeapProxy::GetAllocSize(kAllocSize));
  LPVOID mem = proxy_.Alloc(0, kAllocSize);
  ASSERT_TRUE(mem != NULL);
  ASSERT_TRUE(proxy_.Free(0, mem));
  EXPECT_EQ(QUARANTINED_BLOCK,
            static_cast<BlockState>(BlockGetHeaderFromBody(mem)->state));

  ASSERT_TRUE(errors_.empty());
  ASSERT_FALSE(proxy_.Free(0, mem));
  ASSERT_EQ(1u, errors_.size());
  EXPECT_EQ(DOUBLE_FREE, errors_[0].error_type);
  EXPECT_EQ(mem, errors_[0].location);
}

static const size_t kChecksumRepeatCount = 10;

TEST_F(HeapTest, CorruptAsEntersQuarantine) {
  // This can fail because of a checksum collision. However, we run it a
  // handful of times to keep the chances as small as possible.
  for (size_t i = 0; i < kChecksumRepeatCount; ++i) {
    const size_t kAllocSize = 100;
    proxy_.SetQuarantineMaxSize(0);
    proxy_.SetQuarantineMaxSize(TestHeapProxy::GetAllocSize(kAllocSize));
    LPVOID mem = proxy_.Alloc(0, kAllocSize);
    ASSERT_TRUE(mem != NULL);
    reinterpret_cast<int*>(mem)[-1] = rand();
    ASSERT_TRUE(proxy_.Free(0, mem));

    // Try again for all but the last attempt if this appears to have failed.
    if (errors_.empty() && i + 1 < kChecksumRepeatCount)
      continue;

    ASSERT_EQ(1u, errors_.size());
    ASSERT_EQ(CORRUPT_BLOCK, errors_[0].error_type);
    ASSERT_EQ(mem, errors_[0].location);

    break;
  }
}

TEST_F(HeapTest, CorruptAsExitsQuarantine) {
  const size_t kAllocSize = 100;

  // This can fail because of a checksum collision. However, we run it a
  // handful of times to keep the chances as small as possible.
  for (size_t i = 0; i < kChecksumRepeatCount; ++i) {
    proxy_.SetQuarantineMaxSize(TestHeapProxy::GetAllocSize(kAllocSize));
    LPVOID mem = proxy_.Alloc(0, kAllocSize);
    ASSERT_TRUE(mem != NULL);
    ASSERT_TRUE(proxy_.Free(0, mem));
    ASSERT_TRUE(errors_.empty());

    // Change some of the block content and then force the quarantine to be
    // trimmed. The block hash should be invalid and it should cause an error to
    // be fired.
    reinterpret_cast<int32*>(mem)[0] = rand();
    proxy_.SetQuarantineMaxSize(0);

    // Try again for all but the last attempt if this appears to have failed.
    if (errors_.empty() && i + 1 < kChecksumRepeatCount)
      continue;

    ASSERT_EQ(1u, errors_.size());
    ASSERT_EQ(CORRUPT_BLOCK, errors_[0].error_type);
    ASSERT_EQ(
        reinterpret_cast<BlockHeader*>(mem) - 1,
        reinterpret_cast<BlockHeader*>(errors_[0].location));

    break;
  }
}

TEST_F(HeapTest, AllocsAccessibility) {
  // Ensure that the quarantine is large enough to keep the allocated blocks in
  // this test.
  proxy_.SetQuarantineMaxSize(kMaxAllocSize * 2);
  for (size_t size = 10; size < kMaxAllocSize; size = size * 5 + 123) {
    // Do an alloc/realloc/free and test that access is correctly managed.
    void* mem = proxy_.Alloc(0, size);
    ASSERT_TRUE(mem != NULL);
    ASSERT_NO_FATAL_FAILURE(VerifyAllocAccess(mem, size));
    RandomSetMemory(mem, size);

    size_t new_size = size;
    while (new_size == size)
      new_size = base::RandInt(size / 2, size * 2);

    unsigned char sha1_before[base::kSHA1Length] = {};
    base::SHA1HashBytes(reinterpret_cast<unsigned char*>(mem),
                        std::min(size, new_size),
                        sha1_before);

    void* new_mem = proxy_.ReAlloc(0, mem, size * 2);
    ASSERT_TRUE(new_mem != NULL);
    ASSERT_NE(mem, new_mem);

    unsigned char sha1_after[base::kSHA1Length] = {};
    base::SHA1HashBytes(reinterpret_cast<unsigned char*>(new_mem),
                        std::min(size, new_size),
                        sha1_after);
    ASSERT_EQ(0, memcmp(sha1_before, sha1_after, base::kSHA1Length));

    ASSERT_NO_FATAL_FAILURE(VerifyFreedAccess(mem, size));
    ASSERT_NO_FATAL_FAILURE(VerifyAllocAccess(new_mem, size * 2));

    // Purge the quarantine entirely. This is the only way to guarantee that
    // this block will enter it.
    proxy_.PurgeQuarantine();

    ASSERT_TRUE(proxy_.Free(0, new_mem));
    ASSERT_NO_FATAL_FAILURE(VerifyFreedAccess(new_mem, size * 2));
  }
}

TEST_F(HeapTest, AllocZeroBytes) {
  void* mem1 = proxy_.Alloc(0, 0);
  ASSERT_TRUE(mem1 != NULL);
  void* mem2 = proxy_.Alloc(0, 0);
  ASSERT_TRUE(mem2 != NULL);
  ASSERT_NE(mem1, mem2);
  ASSERT_TRUE(proxy_.Free(0, mem1));
  ASSERT_TRUE(proxy_.Free(0, mem2));
}

TEST_F(HeapTest, Size) {
  for (size_t size = 10; size < kMaxAllocSize; size = size * 5 + 123) {
    void* mem = proxy_.Alloc(0, size);
    ASSERT_FALSE(mem == NULL);
    ASSERT_EQ(size, proxy_.Size(0, mem));
    ASSERT_TRUE(proxy_.Free(0, mem));
  }
}

TEST_F(HeapTest, Validate) {
  for (size_t size = 10; size < kMaxAllocSize; size = size * 5 + 123) {
    void* mem = proxy_.Alloc(0, size);
    ASSERT_FALSE(mem == NULL);
    ASSERT_TRUE(proxy_.Validate(0, mem));
    ASSERT_TRUE(proxy_.Free(0, mem));
  }
}

TEST_F(HeapTest, Compact) {
  // Compact should return a non-zero size.
  ASSERT_LT(0U, proxy_.Compact(0));

  // TODO(siggi): It may not be possible to allocate the size returned due
  //     to padding - fix and test.
}

TEST_F(HeapTest, LockUnlock) {
  // We can't really test these, aside from not crashing.
  ASSERT_TRUE(proxy_.Lock());
  ASSERT_TRUE(proxy_.Unlock());
}

TEST_F(HeapTest, Walk) {
  // We assume at least two entries to walk through.
  PROCESS_HEAP_ENTRY entry = {};
  ASSERT_TRUE(proxy_.Walk(&entry));
  ASSERT_TRUE(proxy_.Walk(&entry));
}

TEST_F(HeapTest, UseHeap) {
  TestHeapProxy heap_proxy;
  HANDLE heap_handle = ::GetProcessHeap();
  heap_proxy.UseHeap(heap_handle);
  ASSERT_EQ(heap_handle, heap_proxy.heap());
  ASSERT_TRUE(heap_proxy.Destroy());
}

TEST_F(HeapTest, SetQueryInformation) {
  ULONG compat_flag = -1;
  unsigned long ret = 0;
  // Get the current value of the compat flag.
  ASSERT_TRUE(
      proxy_.QueryInformation(::HeapCompatibilityInformation,
                              &compat_flag, sizeof(compat_flag), &ret));
  ASSERT_EQ(sizeof(compat_flag), ret);
  ASSERT_NE(~0U, compat_flag);

  // Put the heap in LFH, which should always succeed, except when a debugger
  // is attached. When a debugger is attached, the heap is wedged in certain
  // debug settings.
  if (base::debug::BeingDebugged()) {
    LOG(WARNING) << "Can't test HeapProxy::SetInformation under debugger.";
    return;
  }

  compat_flag = 2;
  ASSERT_TRUE(
      proxy_.SetInformation(::HeapCompatibilityInformation,
                            &compat_flag, sizeof(compat_flag)));

  // Ensure that the compatibility information has been correctly set.
  size_t compat_flag_val = 0;
  ASSERT_TRUE(
      proxy_.QueryInformation(::HeapCompatibilityInformation,
                              &compat_flag_val, sizeof(compat_flag_val), &ret));
  ASSERT_EQ(sizeof(compat_flag), ret);
  ASSERT_EQ(compat_flag, compat_flag_val);
}

namespace {

// Here's the block layout created in this fixture:
// +-----+------+-----+-----+-----+-----+-----+-----+-----+------+-----+-----+
// |     |      |     | BH3 | DB3 | BT3 | BH4 | DB4 | BT4 | GAP2 |     |     |
// |     | GAP1 | BH2 +-----+-----+-----+-----+-----+-----+------+ BT2 |     |
// | BH1 |      |     |                   DB2                    |     | BT1 |
// |     |------+-----+------------------------------------------+-----+     |
// |     |                             DB1                             |     |
// +-----+-------------------------------------------------------------+-----+
// Legend:
//   - BHX: Block header of the block X.
//   - DBX: Data block of the block X.
//   - BTX: Block trailer of the block X.
//   - GAP1: Memory gap between the header of block 1 and that of block 2. This
//     is due to the fact that block 2 has a non standard alignment and the
//     beginning of its header is aligned to this value.
//   - GAP2: Memory gap between block 4 and the trailer of block 2.
// Remarks:
//   - Block 1, 3 and 4 are 8 bytes aligned.
//   - Block 2 is 64 bytes aligned.
//   - Block 3 and 4 are both contained in block 2, which is contained in
//     block 1.
class NestedBlocksTest : public HeapTest {
 public:
  typedef HeapTest Super;

  virtual void SetUp() OVERRIDE {
    Super::SetUp();

    InitializeBlockLayout();
  }

  virtual void TearDown() OVERRIDE {
    Shadow::Unpoison(aligned_buffer_,
                     kBufferSize - (aligned_buffer_ - buffer_));
    Super::TearDown();
  }

  void InitializeBlockLayout() {
    inner_blocks_size_ =
        TestHeapProxy::GetAllocSize(kInternalAllocSize, kInnerBlockAlignment);
    block_2_size_ = TestHeapProxy::GetAllocSize(
        inner_blocks_size_ * 2 + kGapSize, kBlock2Alignment);
    const size_t kAlignMaxGap = kBlock2Alignment;
    block_1_size_ = TestHeapProxy::GetAllocSize(block_2_size_ + kAlignMaxGap,
                                                kBlock1Alignment);

    aligned_buffer_ = reinterpret_cast<uint8*>(common::AlignUp(
        reinterpret_cast<size_t>(buffer_), kShadowRatio));

    ASSERT_GT(kBufferSize - (aligned_buffer_ - buffer_), block_1_size_);

    StackCapture stack;
    stack.InitFromStack();

    // Initialize block 1.
    data_block_1_ = reinterpret_cast<uint8*>(HeapProxy::InitializeAsanBlock(
        aligned_buffer_,
        block_2_size_ + kAlignMaxGap,
        base::bits::Log2Floor(kBlock1Alignment),
        false,
        stack));
    ASSERT_NE(reinterpret_cast<uint8*>(NULL), data_block_1_);
    block_1_ = BlockGetHeaderFromBody(data_block_1_);
    ASSERT_NE(reinterpret_cast<BlockHeader*>(NULL), block_1_);
    ASSERT_TRUE(BlockInfoFromMemory(block_1_, &block_info_1_));

    size_t data_block_1_aligned = common::AlignUp(reinterpret_cast<size_t>(
        data_block_1_), kBlock2Alignment);
    // Initialize block 2.
    data_block_2_ = reinterpret_cast<uint8*>(HeapProxy::InitializeAsanBlock(
        reinterpret_cast<uint8*>(data_block_1_aligned),
        inner_blocks_size_ * 2 + kGapSize,
        base::bits::Log2Floor(kBlock2Alignment),
        true,
        stack));
    ASSERT_NE(reinterpret_cast<uint8*>(NULL), data_block_2_);
    block_2_ = BlockGetHeaderFromBody(data_block_2_);
    ASSERT_NE(reinterpret_cast<BlockHeader*>(NULL), block_2_);
    ASSERT_TRUE(BlockInfoFromMemory(block_2_, &block_info_2_));

    // Initialize block 3.
    data_block_3_ = reinterpret_cast<uint8*>(HeapProxy::InitializeAsanBlock(
        reinterpret_cast<uint8*>(data_block_2_),
        kInternalAllocSize,
        base::bits::Log2Floor(kInnerBlockAlignment),
        true,
        stack));
    ASSERT_NE(reinterpret_cast<uint8*>(NULL), data_block_3_);
    block_3_ = BlockGetHeaderFromBody(data_block_3_);
    ASSERT_NE(reinterpret_cast<BlockHeader*>(NULL), block_3_);
    ASSERT_TRUE(BlockInfoFromMemory(block_3_, &block_info_3_));

    // Initialize block 4.
    data_block_4_ = reinterpret_cast<uint8*>(HeapProxy::InitializeAsanBlock(
        reinterpret_cast<uint8*>(data_block_2_) + inner_blocks_size_,
        kInternalAllocSize,
        base::bits::Log2Floor(kInnerBlockAlignment),
        true,
        stack));
    ASSERT_NE(reinterpret_cast<uint8*>(NULL), data_block_4_);
    block_4_ = BlockGetHeaderFromBody(data_block_4_);
    ASSERT_NE(reinterpret_cast<BlockHeader*>(NULL), block_4_);
    ASSERT_TRUE(BlockInfoFromMemory(block_4_, &block_info_4_));
  }

 protected:
  static const size_t kBufferSize = 512;
  static const size_t kBlock1Alignment = 8;
  static const size_t kBlock2Alignment = 64;
  static const size_t kInnerBlockAlignment = 8;
  static const size_t kInternalAllocSize = 13;
  static const size_t kGapSize = 5;

  uint8 buffer_[kBufferSize];
  uint8* aligned_buffer_;

  uint8* data_block_1_;
  uint8* data_block_2_;
  uint8* data_block_3_;
  uint8* data_block_4_;

  size_t block_1_size_;
  size_t block_2_size_;
  size_t inner_blocks_size_;

  BlockHeader* block_1_;
  BlockHeader* block_2_;
  BlockHeader* block_3_;
  BlockHeader* block_4_;

  BlockInfo block_info_1_;
  BlockInfo block_info_2_;
  BlockInfo block_info_3_;
  BlockInfo block_info_4_;
};

}  // namespace

TEST_F(HeapTest, CaptureTID) {
  const size_t kAllocSize = 13;
  // Ensure that the quarantine is large enough to keep this block.
  proxy_.SetQuarantineMaxSize(TestHeapProxy::GetAllocSize(kAllocSize));
  uint8* mem = static_cast<uint8*>(proxy_.Alloc(0, kAllocSize));
  ASSERT_TRUE(proxy_.Free(0, mem));
  EXPECT_EQ(QUARANTINED_BLOCK,
            static_cast<BlockState>(BlockGetHeaderFromBody(mem)->state));

  BlockHeader* header = BlockGetHeaderFromBody(mem);
  ASSERT_TRUE(header != NULL);
  BlockInfo block_info = {};
  EXPECT_TRUE(BlockInfoFromMemory(header, &block_info));
  EXPECT_NE(reinterpret_cast<BlockTrailer*>(NULL), block_info.trailer);

  EXPECT_EQ(block_info.trailer->alloc_tid, ::GetCurrentThreadId());
  EXPECT_EQ(block_info.trailer->free_tid, ::GetCurrentThreadId());
}

TEST_F(HeapTest, QuarantineDoesntAlterBlockContents) {
  const size_t kAllocSize = 13;
  // Ensure that the quarantine is large enough to keep this block.
  proxy_.SetQuarantineMaxSize(TestHeapProxy::GetAllocSize(kAllocSize));
  void* mem = proxy_.Alloc(0, kAllocSize);
  ASSERT_TRUE(mem != NULL);
  RandomSetMemory(mem, kAllocSize);

  unsigned char sha1_before[base::kSHA1Length] = {};
  base::SHA1HashBytes(reinterpret_cast<unsigned char*>(mem),
                      kAllocSize,
                      sha1_before);

  BlockHeader* header = BlockGetHeaderFromBody(mem);

  ASSERT_TRUE(proxy_.Free(0, mem));
  EXPECT_EQ(QUARANTINED_BLOCK, static_cast<BlockState>(header->state));

  unsigned char sha1_after[base::kSHA1Length] = {};
  base::SHA1HashBytes(reinterpret_cast<unsigned char*>(mem),
                      kAllocSize,
                      sha1_after);

  EXPECT_EQ(0, memcmp(sha1_before, sha1_after, base::kSHA1Length));
}

TEST_F(HeapTest, InternalStructureArePoisoned) {
  EXPECT_EQ(Shadow::kAsanMemoryByte,
            Shadow::GetShadowMarkerForAddress(TestShadow::shadow_));

  const size_t kAllocSize = 13;
  // Ensure that the quarantine is large enough to keep this block.
  proxy_.SetQuarantineMaxSize(TestHeapProxy::GetAllocSize(kAllocSize));
  uint8* mem = static_cast<uint8*>(proxy_.Alloc(0, kAllocSize));
  BlockHeader* header = BlockGetHeaderFromBody(mem);

  ASSERT_TRUE(header != NULL);
  const void* alloc_stack_cache_addr =
      reinterpret_cast<const void*>(header->alloc_stack);
  EXPECT_EQ(Shadow::kAsanMemoryByte,
            Shadow::GetShadowMarkerForAddress(alloc_stack_cache_addr));

  ASSERT_TRUE(proxy_.Free(0, mem));
}

TEST_F(HeapTest, GetNullTerminatedArraySize) {
  // Ensure that the quarantine is large enough to keep the allocated blocks in
  // this test.
  proxy_.SetQuarantineMaxSize(kMaxAllocSize * 2);
  const char* test_strings[] = { "", "abc", "abcdefg", "abcdefghijklmno" };

  for (size_t i = 0; i < arraysize(test_strings); ++i) {
    size_t string_size = ::strlen(test_strings[i]);
    char* mem = reinterpret_cast<char*>(
        proxy_.Alloc(0, string_size + 1));
    ASSERT_TRUE(mem != NULL);
    ::strcpy(static_cast<char*>(mem), test_strings[i]);
    size_t size = 0;
    EXPECT_TRUE(Shadow::GetNullTerminatedArraySize<char>(mem, 0U, &size));
    EXPECT_EQ(string_size, size - 1);
    char last_char = mem[string_size + 1];
    mem[string_size] = 'a';
    mem[string_size + 1] = 0;
    EXPECT_FALSE(Shadow::GetNullTerminatedArraySize<char>(mem, 0U, &size));
    mem[string_size] = 0;
    mem[string_size + 1] = last_char;
    EXPECT_EQ(string_size, size - 1);
    ASSERT_TRUE(proxy_.Free(0, mem));
  }

  const wchar_t* test_wstrings[] = { L"", L"abc", L"abcde", L"abcdefghijklmn" };

  for (size_t i = 0; i < arraysize(test_wstrings); ++i) {
    size_t string_size = ::wcslen(test_wstrings[i]);
    wchar_t* mem = reinterpret_cast<wchar_t*>(
        proxy_.Alloc(0, (string_size + 1) * sizeof(wchar_t)));
    ASSERT_TRUE(mem != NULL);
    ::wcscpy(static_cast<wchar_t*>(mem), test_wstrings[i]);
    size_t size = 0;
    EXPECT_TRUE(Shadow::GetNullTerminatedArraySize<wchar_t>(mem, 0U, &size));
    EXPECT_EQ((string_size + 1) * sizeof(wchar_t) - 1, size - 1);
    wchar_t last_char = mem[string_size + 1];
    mem[string_size] = L'a';
    mem[string_size + 1] = 0;
    EXPECT_FALSE(Shadow::GetNullTerminatedArraySize<wchar_t>(mem, 0U, &size));
    mem[string_size] = 0;
    mem[string_size + 1] = last_char;
    EXPECT_EQ((string_size + 1) * sizeof(wchar_t) - 1, size - 1);
    ASSERT_TRUE(proxy_.Free(0, mem));
  }
}

TEST_F(HeapTest, SetTrailerPaddingSize) {
  const size_t kAllocSize = 100;
  // As we're playing with the padding size in these tests, we need to make sure
  // that the blocks don't end up in the quarantine, otherwise we won't be able
  // to unpoison them correctly (we don't keep the padding size in the blocks).
  proxy_.SetQuarantineMaxSize(kAllocSize - 1);
  size_t original_alloc_size = TestHeapProxy::GetAllocSize(kAllocSize);
  size_t original_trailer_padding_size = TestHeapProxy::trailer_padding_size();

  for (size_t padding = 0; padding < 16; ++padding) {
    size_t augmented_trailer_padding_size = original_trailer_padding_size +
        padding;
    proxy_.set_trailer_padding_size(augmented_trailer_padding_size);
    size_t augmented_alloc_size = TestHeapProxy::GetAllocSize(kAllocSize);
    EXPECT_GE(augmented_alloc_size, original_alloc_size);

    LPVOID mem = proxy_.Alloc(0, kAllocSize);
    ASSERT_TRUE(mem != NULL);

    size_t offset = kAllocSize;
    for (; offset < augmented_alloc_size - sizeof(BlockHeader);
         ++offset) {
      EXPECT_FALSE(Shadow::IsAccessible(
          reinterpret_cast<const uint8*>(mem) + offset));
    }
    ASSERT_TRUE(proxy_.Free(0, mem));
  }
  proxy_.set_trailer_padding_size(original_trailer_padding_size);
}

TEST_F(HeapTest, InitializeAsanBlock) {
  for (size_t alloc_alignment_log = kShadowRatioLog;
       alloc_alignment_log <= testing::FakeAsanBlock::kMaxAlignmentLog;
       ++alloc_alignment_log) {
    testing::FakeAsanBlock fake_block(&proxy_, alloc_alignment_log);
    const size_t kAllocSize = 100;
    EXPECT_TRUE(fake_block.InitializeBlock(kAllocSize));
    EXPECT_TRUE(fake_block.TestBlockMetadata());
  }
}

TEST_F(HeapTest, MarkBlockAsQuarantined) {
  for (size_t alloc_alignment_log = kShadowRatioLog;
       alloc_alignment_log <= testing::FakeAsanBlock::kMaxAlignmentLog;
       ++alloc_alignment_log) {
    testing::FakeAsanBlock fake_block(&proxy_, alloc_alignment_log);
    const size_t kAllocSize = 100;
    EXPECT_TRUE(fake_block.InitializeBlock(kAllocSize));
    EXPECT_TRUE(fake_block.TestBlockMetadata());
    EXPECT_TRUE(fake_block.MarkBlockAsQuarantined());
  }
}

TEST_F(HeapTest, DestroyAsanBlock) {
  for (size_t alloc_alignment_log = kShadowRatioLog;
       alloc_alignment_log <= testing::FakeAsanBlock::kMaxAlignmentLog;
       ++alloc_alignment_log) {
    testing::FakeAsanBlock fake_block(&proxy_, alloc_alignment_log);
    const size_t kAllocSize = 100;
    EXPECT_TRUE(fake_block.InitializeBlock(kAllocSize));
    EXPECT_TRUE(fake_block.TestBlockMetadata());
    EXPECT_TRUE(fake_block.MarkBlockAsQuarantined());

    BlockHeader* block_header = BlockGetHeaderFromBody(fake_block.user_ptr);
    EXPECT_NE(reinterpret_cast<BlockHeader*>(NULL), block_header);
    StackCapture* alloc_stack = const_cast<StackCapture*>(
        block_header->alloc_stack);
    StackCapture* free_stack = const_cast<StackCapture*>(
        block_header->free_stack);

    ASSERT_TRUE(alloc_stack != NULL);
    ASSERT_TRUE(free_stack != NULL);
    EXPECT_EQ(1U, alloc_stack->ref_count());
    EXPECT_EQ(1U, free_stack->ref_count());
    alloc_stack->AddRef();
    free_stack->AddRef();
    EXPECT_EQ(2U, alloc_stack->ref_count());
    EXPECT_EQ(2U, free_stack->ref_count());

    proxy_.DestroyAsanBlock(fake_block.buffer_align_begin);

    EXPECT_EQ(FREED_BLOCK, static_cast<BlockState>(block_header->state));
    EXPECT_EQ(1U, alloc_stack->ref_count());
    EXPECT_EQ(1U, free_stack->ref_count());
    alloc_stack->RemoveRef();
    free_stack->RemoveRef();
  }
}

TEST_F(HeapTest, CloneBlock) {
  for (size_t alloc_alignment_log = kShadowRatioLog;
       alloc_alignment_log <= testing::FakeAsanBlock::kMaxAlignmentLog;
       ++alloc_alignment_log) {
    // Create a fake block and mark it as quarantined.
    testing::FakeAsanBlock fake_block(&proxy_, alloc_alignment_log);
    const size_t kAllocSize = 100;
    EXPECT_TRUE(fake_block.InitializeBlock(kAllocSize));
    EXPECT_TRUE(fake_block.TestBlockMetadata());
    // Fill the block with a non zero value.
    ::memset(fake_block.user_ptr, 0xEE, kAllocSize);
    EXPECT_TRUE(fake_block.MarkBlockAsQuarantined());

    size_t asan_alloc_size = fake_block.asan_alloc_size;

    // Get the current count of the alloc and free stack traces.
    BlockHeader* block_header = BlockGetHeaderFromBody(fake_block.user_ptr);
    StackCapture* alloc_stack = const_cast<StackCapture*>(
        block_header->alloc_stack);
    StackCapture* free_stack = const_cast<StackCapture*>(
        block_header->free_stack);

    ASSERT_TRUE(alloc_stack != NULL);
    ASSERT_TRUE(free_stack != NULL);

    size_t alloc_stack_count = alloc_stack->ref_count();
    size_t free_stack_count = alloc_stack->ref_count();

    // Clone the fake block into a second one.
    testing::FakeAsanBlock fake_block_2(&proxy_, alloc_alignment_log);
    proxy_.CloneObject(fake_block.buffer_align_begin,
                       fake_block_2.buffer_align_begin);
    fake_block_2.asan_alloc_size = asan_alloc_size;

    // Ensure that the stack trace counts have been incremented.
    EXPECT_EQ(alloc_stack_count + 1, alloc_stack->ref_count());
    EXPECT_EQ(free_stack_count + 1, free_stack->ref_count());

    for (size_t i = 0; i < asan_alloc_size; ++i) {
      // Ensure that the blocks have the same content.
      EXPECT_EQ(fake_block.buffer_align_begin[i],
                fake_block_2.buffer_align_begin[i]);
      EXPECT_EQ(
          Shadow::GetShadowMarkerForAddress(fake_block.buffer_align_begin + i),
          Shadow::GetShadowMarkerForAddress(
              fake_block_2.buffer_align_begin + i));
    }
  }
}

TEST_F(HeapTest, ErrorInfoGetBadAccessInformation) {
}

TEST_F(HeapTest, GetBadAccessInformationNestedBlock) {
}

TEST_F(HeapTest, GetAllocSizeViaShadow) {
  const size_t kAllocSize = 100;
  LPVOID mem = proxy_.Alloc(0, kAllocSize);
  ASSERT_TRUE(mem != NULL);
  ASSERT_EQ(kAllocSize, proxy_.Size(0, mem));
  size_t real_alloc_size = TestHeapProxy::GetAllocSize(kAllocSize);
  uint8* header_begin = reinterpret_cast<uint8*>(BlockGetHeaderFromBody(mem));
  for (size_t i = 0; i < real_alloc_size; ++i)
    EXPECT_EQ(real_alloc_size, Shadow::GetAllocSize(header_begin + i));

  ASSERT_TRUE(proxy_.Free(0, mem));
}

TEST_F(HeapTest, SubsampledAllocationGuards) {
  proxy_.set_allocation_guard_rate(0.5);

  size_t guarded_allocations = 0;
  size_t unguarded_allocations = 0;

  // Make a handful of allocations.
  const size_t kAllocationCount = 10000;
  const size_t kAllocationSizes[] = {
      1, 2, 4, 8, 14, 30, 128, 237, 500, 1000, 2036 };
  std::vector<void*> allocations;
  for (size_t i = 0; i < kAllocationCount; ++i) {
    size_t alloc_size = kAllocationSizes[i % arraysize(kAllocationSizes)];
    void* alloc = proxy_.Alloc(0, alloc_size);
    EXPECT_TRUE(alloc != NULL);

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
      EXPECT_TRUE(proxy_.Free(0, alloc));
    } else {
      allocations.push_back(alloc);
    }
  }

  // Free the outstanding allocations.
  for (size_t i = 0; i < allocations.size(); ++i)
    EXPECT_TRUE(proxy_.Free(0, allocations[i]));

  // Clear the quarantine. This should free up the remaining instrumented
  // but quarantined blocks.
  EXPECT_NO_FATAL_FAILURE(proxy_.PurgeQuarantine());

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

TEST_F(HeapTest, WalkBlocksWithShadowWalker) {
  const size_t kAllocSize = 100;
  size_t real_alloc_size = TestHeapProxy::GetAllocSize(kAllocSize);

  // In this test we'll manually initialize 3 blocks inside a heap allocation,
  // ensuring that the blocks are all in the same heap slab.

  const size_t kNumberOfBlocks = 3;
  size_t outer_block_size = kNumberOfBlocks * real_alloc_size;

  // The outer block that will contain the 3 blocks.
  scoped_ptr<uint8> outer_block(new uint8[outer_block_size]);

  // The user pointers to the nested blocks.
  uint8* user_pointers[kNumberOfBlocks];

  StackCapture stack;
  stack.InitFromStack();

  // Initialize the blocks with random data.
  for (size_t i = 0; i < kNumberOfBlocks; ++i) {
    user_pointers[i] = reinterpret_cast<uint8*>(
        TestHeapProxy::InitializeAsanBlock(
            outer_block.get() + i * real_alloc_size,
        kAllocSize,
        kShadowRatioLog,
        false,
        stack));
    base::RandBytes(user_pointers[i], kAllocSize);
  }

  ShadowWalker walker(false, outer_block.get(),
                      outer_block.get() + outer_block_size);

  BlockInfo block_info = {};
  for (size_t i = 0; i < kNumberOfBlocks; ++i) {
    EXPECT_TRUE(walker.Next(&block_info));
    EXPECT_EQ(BlockGetHeaderFromBody(user_pointers[i]), block_info.header);
  }

  EXPECT_FALSE(walker.Next(&block_info));

  walker.Reset();
  EXPECT_TRUE(walker.Next(&block_info));
  EXPECT_EQ(BlockGetHeaderFromBody(user_pointers[0]), block_info.header);

  // Clear the shadow memory. As those blocks have been manually initialized
  // they can't go into the quarantine and we need to clean their metadata
  // manually.
  Shadow::Unpoison(outer_block.get(), outer_block_size);
}

}  // namespace asan
}  // namespace agent
