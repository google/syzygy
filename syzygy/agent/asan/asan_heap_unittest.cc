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

#include "base/rand_util.h"
#include "base/sha1.h"
#include "gtest/gtest.h"
#include "syzygy/agent/asan/asan_logger.h"
#include "syzygy/agent/asan/asan_shadow.h"
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
  using HeapProxy::BlockHeader;
  using HeapProxy::BlockTrailer;
  using HeapProxy::AsanPointerToUserPointer;
  using HeapProxy::BlockHeaderToAsanPointer;
  using HeapProxy::BlockHeaderToBlockTrailer;
  using HeapProxy::BlockHeaderToUserPointer;
  using HeapProxy::FindAddressBlock;
  using HeapProxy::GetAllocSize;
  using HeapProxy::GetBadAccessKind;
  using HeapProxy::GetTimeSinceFree;
  using HeapProxy::InitializeAsanBlock;
  using HeapProxy::MarkBlockAsQuarantined;
  using HeapProxy::ReleaseASanBlock;
  using HeapProxy::UserPointerToBlockHeader;
  using HeapProxy::UserPointerToAsanPointer;
  using HeapProxy::kDefaultAllocGranularityLog;

  TestHeapProxy() { }

  // Calculates the underlying allocation size for an allocation of @p bytes.
  // This assume a granularity of @p kDefaultAllocGranularity bytes.
  static size_t GetAllocSize(size_t bytes) {
    return GetAllocSize(bytes, kDefaultAllocGranularity);
  }

  // Verify that the access to @p addr contained in @p header is an underflow.
  bool IsUnderflowAccess(uint8* addr, BlockHeader* header) {
    return GetBadAccessKind(addr, header) == HEAP_BUFFER_UNDERFLOW;
  }

  // Verify that the access to @p addr contained in @p header is an overflow.
  bool IsOverflowAccess(uint8* addr, BlockHeader* header) {
    return GetBadAccessKind(addr, header) == HEAP_BUFFER_OVERFLOW;
  }

  // Verify that the access to @p addr contained in @p header is an use after
  // free.
  bool IsUseAfterAccess(uint8* addr, BlockHeader* header) {
    return GetBadAccessKind(addr, header) == USE_AFTER_FREE;
  }

  bool IsQuarantined(BlockHeader* header) {
    EXPECT_TRUE(header != NULL);
    return header->state == QUARANTINED;
  }

  bool IsFreed(BlockHeader* header) {
    EXPECT_TRUE(header != NULL);
    return header->state == FREED;
  }

  // Determines if the address @p mem corresponds to a block in quarantine.
  bool InQuarantine(const void* mem) {
    base::AutoLock lock(lock_);
    BlockHeader* current_block = head_;
    while (current_block != NULL) {
      void* block_alloc = static_cast<void*>(
          BlockHeaderToUserPointer(current_block));
      EXPECT_TRUE(block_alloc != NULL);
      if (block_alloc == mem) {
        EXPECT_TRUE(current_block->state == QUARANTINED);
        return true;
      }
      current_block = BlockHeaderToBlockTrailer(current_block)->next_free_block;
    }
    return false;
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
    ASSERT_EQ(Shadow::GetShadowMarkerForAddress(mem - 1),
              Shadow::kHeapLeftRedzone);
    for (size_t i = 0; i < size; ++i)
      ASSERT_TRUE(Shadow::IsAccessible(mem + i));
    ASSERT_FALSE(Shadow::IsAccessible(mem + size));
  }

  // Verifies that [alloc-1, alloc+size] is poisoned.
  void VerifyFreedAccess(void* alloc, size_t size) {
    uint8* mem = reinterpret_cast<uint8*>(alloc);
    ASSERT_FALSE(Shadow::IsAccessible(mem - 1));
    ASSERT_EQ(Shadow::GetShadowMarkerForAddress(mem - 1),
              Shadow::kHeapLeftRedzone);
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

 protected:
  // Arbitrary constant for all size limit.
  static const size_t kMaxAllocSize = 134584;

  AsanLogger logger_;
  StackCaptureCache stack_cache_;
  TestHeapProxy proxy_;
};

}  // namespace

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

TEST_F(HeapTest, PopOnSetQuarantineMaxSize) {
  const size_t kAllocSize = 100;
  const size_t real_alloc_size = TestHeapProxy::GetAllocSize(kAllocSize);
  LPVOID mem = proxy_.Alloc(0, kAllocSize);
  ASSERT_FALSE(proxy_.InQuarantine(mem));
  proxy_.SetQuarantineMaxSize(real_alloc_size);
  ASSERT_TRUE(proxy_.Free(0, mem));
  // The quarantine is just large enough to keep this block.
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

  LPVOID mem = proxy_.Alloc(0, kAllocSize);
  ASSERT_TRUE(mem != NULL);
  ASSERT_TRUE(proxy_.Free(0, mem));
  // Allocate a bunch of blocks until the first one is pushed out of the
  // quarantine.
  for (size_t i = 0; i < number_of_allocs; ++i) {
    ASSERT_TRUE(proxy_.InQuarantine(mem));
    LPVOID mem2 = proxy_.Alloc(0, kAllocSize);
    ASSERT_TRUE(mem2 != NULL);
    ASSERT_TRUE(proxy_.Free(0, mem2));
    ASSERT_TRUE(proxy_.InQuarantine(mem2));
  }

  ASSERT_FALSE(proxy_.InQuarantine(mem));
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
  intptr_t mem_start = reinterpret_cast<intptr_t>(
      proxy_.UserPointerToBlockHeader(mem));
  ASSERT_EQ(0, (mem_start & 7) );
  size_t shadow_start = mem_start >> 3;
  size_t shadow_alloc_size = real_alloc_size >> 3;
  for (size_t i = shadow_start; i < shadow_start + shadow_alloc_size; ++i) {
    ASSERT_NE(TestShadow::kHeapAddressableByte, TestShadow::shadow_[i]);
  }

  // Flush the quarantine.
  proxy_.SetQuarantineMaxSize(0);

  // Assert that the quarantine has been correctly unpoisoned.
  for (size_t i = shadow_start; i < shadow_start + shadow_alloc_size; ++i) {
    ASSERT_EQ(TestShadow::kHeapAddressableByte, TestShadow::shadow_[i]);
  }
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
  ASSERT_TRUE(proxy_.IsQuarantined(proxy_.UserPointerToBlockHeader(mem)));
  ASSERT_FALSE(proxy_.Free(0, mem));
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

TEST_F(HeapTest, SetQueryInformation) {
  ULONG compat_flag = -1;
  unsigned long ret = 0;
  // Get the current value of the compat flag.
  ASSERT_TRUE(
      proxy_.QueryInformation(HeapCompatibilityInformation,
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
      proxy_.SetInformation(HeapCompatibilityInformation,
                            &compat_flag, sizeof(compat_flag)));
}

TEST_F(HeapTest, FindAddressBlock) {
  const size_t kAllocSize = 100;
  void* mem = proxy_.Alloc(0, kAllocSize);
  ASSERT_FALSE(mem == NULL);
  ASSERT_FALSE(proxy_.FindAddressBlock(static_cast<const uint8*>(mem)) == NULL);
  uint8* out_of_bounds_address =
      static_cast<uint8*>(mem) + kAllocSize * 2;
  ASSERT_TRUE(proxy_.FindAddressBlock(out_of_bounds_address) == NULL);
  ASSERT_TRUE(proxy_.Free(0, mem));
}

TEST_F(HeapTest, GetBadAccessKind) {
  const size_t kAllocSize = 100;
  // Ensure that the quarantine is large enough to keep this block, this is
  // needed for the use-after-free check.
  proxy_.SetQuarantineMaxSize(TestHeapProxy::GetAllocSize(kAllocSize));
  uint8* mem = static_cast<uint8*>(proxy_.Alloc(0, kAllocSize));
  ASSERT_FALSE(mem == NULL);
  TestHeapProxy::BlockHeader* header =
      const_cast<TestHeapProxy::BlockHeader*>(
          proxy_.UserPointerToBlockHeader(mem));
  uint8* heap_underflow_address = mem - 1;
  uint8* heap_overflow_address = mem + kAllocSize * sizeof(uint8);
  ASSERT_TRUE(proxy_.IsUnderflowAccess(heap_underflow_address, header));
  ASSERT_TRUE(proxy_.IsOverflowAccess(heap_overflow_address, header));
  ASSERT_TRUE(proxy_.Free(0, mem));
  ASSERT_TRUE(proxy_.IsQuarantined(header));
  ASSERT_TRUE(proxy_.IsUseAfterAccess(mem, header));
}

TEST_F(HeapTest, GetTimeSinceFree) {
  const size_t kAllocSize = 100;
  const size_t kSleepTime = 25;

  // Ensure that the quarantine is large enough to keep this block.
  proxy_.SetQuarantineMaxSize(TestHeapProxy::GetAllocSize(kAllocSize));
  uint8* mem = static_cast<uint8*>(proxy_.Alloc(0, kAllocSize));
  TestHeapProxy::BlockHeader* header =
      const_cast<TestHeapProxy::BlockHeader*>(
          proxy_.UserPointerToBlockHeader(mem));

  base::TimeTicks time_before_free = base::TimeTicks::HighResNow();
  ASSERT_EQ(0U, proxy_.GetTimeSinceFree(header));
  ASSERT_TRUE(proxy_.Free(0, mem));
  ASSERT_TRUE(proxy_.IsQuarantined(header));
  ::Sleep(kSleepTime);
  uint64 time_since_free = proxy_.GetTimeSinceFree(header);
  ASSERT_NE(0U, time_since_free);

  base::TimeDelta time_delta = base::TimeTicks::HighResNow() - time_before_free;
  ASSERT_GT(time_delta.ToInternalValue(), 0U);
  uint64 time_delta_us = static_cast<uint64>(time_delta.ToInternalValue());
  trace::common::ClockInfo clock_info = {};
  trace::common::GetClockInfo(&clock_info);
  if (clock_info.tsc_info.frequency == 0)
    time_delta_us += HeapProxy::kSleepTimeForApproximatingCPUFrequency;

  ASSERT_GE(time_delta_us, time_since_free);
}

TEST_F(HeapTest, CaptureTID) {
  const size_t kAllocSize = 13;
  // Ensure that the quarantine is large enough to keep this block.
  proxy_.SetQuarantineMaxSize(TestHeapProxy::GetAllocSize(kAllocSize));
  uint8* mem = static_cast<uint8*>(proxy_.Alloc(0, kAllocSize));
  ASSERT_TRUE(proxy_.Free(0, mem));
  ASSERT_TRUE(proxy_.IsQuarantined(proxy_.UserPointerToBlockHeader(mem)));

  TestHeapProxy::BlockHeader* header =
      const_cast<TestHeapProxy::BlockHeader*>(
          proxy_.UserPointerToBlockHeader(mem));
  ASSERT_TRUE(header != NULL);
  TestHeapProxy::BlockTrailer* trailer =
      const_cast<TestHeapProxy::BlockTrailer*>(
          proxy_.BlockHeaderToBlockTrailer(header));
  ASSERT_TRUE(trailer != NULL);

  ASSERT_EQ(trailer->alloc_tid, ::GetCurrentThreadId());
  ASSERT_EQ(trailer->free_tid, ::GetCurrentThreadId());
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

  TestHeapProxy::BlockHeader* header =
      const_cast<TestHeapProxy::BlockHeader*>(
          proxy_.UserPointerToBlockHeader(mem));

  ASSERT_TRUE(proxy_.Free(0, mem));
  ASSERT_TRUE(proxy_.IsQuarantined(header));

  unsigned char sha1_after[base::kSHA1Length] = {};
  base::SHA1HashBytes(reinterpret_cast<unsigned char*>(mem),
                      kAllocSize,
                      sha1_after);

  ASSERT_EQ(0, memcmp(sha1_before, sha1_after, base::kSHA1Length));
}

TEST_F(HeapTest, InternalStructureArePoisoned) {
  EXPECT_EQ(Shadow::kAsanMemoryByte,
            Shadow::GetShadowMarkerForAddress(TestShadow::shadow_));

  const size_t kAllocSize = 13;
  // Ensure that the quarantine is large enough to keep this block.
  proxy_.SetQuarantineMaxSize(TestHeapProxy::GetAllocSize(kAllocSize));
  uint8* mem = static_cast<uint8*>(proxy_.Alloc(0, kAllocSize));
  TestHeapProxy::BlockHeader* header =
      const_cast<TestHeapProxy::BlockHeader*>(
          proxy_.UserPointerToBlockHeader(mem));

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
    size_t string_size = strlen(test_strings[i]);
    char* mem = reinterpret_cast<char*>(
        proxy_.Alloc(0, string_size + 1));
    ASSERT_TRUE(mem != NULL);
    strcpy(static_cast<char*>(mem), test_strings[i]);
    size_t size = 0;
    EXPECT_TRUE(Shadow::GetNullTerminatedArraySize(mem, &size, 0U));
    EXPECT_EQ(string_size, size - 1);
    mem[string_size] = 'a';
    mem[string_size + 1] = 0;
    EXPECT_FALSE(Shadow::GetNullTerminatedArraySize(mem, &size, 0U));
    EXPECT_EQ(string_size, size - 1);
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
    for (; offset < augmented_alloc_size - sizeof(TestHeapProxy::BlockHeader);
         ++offset) {
      EXPECT_FALSE(Shadow::IsAccessible(
          reinterpret_cast<const uint8*>(mem) + offset));
    }
    ASSERT_TRUE(proxy_.Free(0, mem));
  }
  proxy_.set_trailer_padding_size(original_trailer_padding_size);
}

namespace {

// A unittest fixture to test the bookkeeping functions.
struct FakeAsanBlock {
  static const size_t kBufferSize = 8192;
  static const uint8 kBufferHeaderValue = 0xAE;
  static const uint8 kBufferTrailerValue = 0xEA;

  FakeAsanBlock(TestHeapProxy* proxy, size_t alloc_alignment_log)
      : proxy(proxy),
        is_initialized(false),
        alloc_alignment_log(alloc_alignment_log),
        alloc_alignment(1 << alloc_alignment_log),
        buffer_align_begin(NULL),
        user_ptr(NULL) {
  }
  ~FakeAsanBlock() {
    Shadow::Unpoison(buffer_align_begin, asan_alloc_size);
  }

  // Initialize an ASan block in the buffer.
  // @param alloc_size The user size of the ASan block.
  // @returns true on success, false otherwise.
  bool InitializeBlock(size_t alloc_size) {
    asan_alloc_size = proxy->GetAllocSize(alloc_size,
                                          alloc_alignment);

    // Align the beginning of the buffer to the current granularity. Ensure that
    // there's room to store magic bytes in front of this block.
    buffer_align_begin = reinterpret_cast<uint8*>(common::AlignUp(
        reinterpret_cast<size_t>(buffer) + 1, alloc_alignment));

    // Calculate the size of the zone of the buffer that we use to ensure that
    // we don't corrupt the heap.
    buffer_header_size = buffer_align_begin - buffer;
    buffer_trailer_size = kBufferSize - buffer_header_size -
        asan_alloc_size;
    EXPECT_GE(kBufferSize, asan_alloc_size + buffer_header_size);

    // Initialize the buffer header and trailer.
    memset(buffer, kBufferHeaderValue, buffer_header_size);
    memset(buffer_align_begin + asan_alloc_size,
           kBufferTrailerValue,
           buffer_trailer_size);

    StackCapture stack;
    stack.InitFromStack();
    // Initialize the ASan block.
    user_ptr = proxy->InitializeAsanBlock(buffer_align_begin,
                                          alloc_size,
                                          asan_alloc_size,
                                          alloc_alignment_log,
                                          stack);
    EXPECT_TRUE(user_ptr != NULL);
    EXPECT_TRUE(common::IsAligned(reinterpret_cast<size_t>(user_ptr),
                                  alloc_alignment));
    EXPECT_TRUE(common::IsAligned(
        reinterpret_cast<size_t>(buffer_align_begin) + asan_alloc_size,
        Shadow::kShadowGranularity));
    EXPECT_TRUE(proxy->UserPointerToAsanPointer(user_ptr) ==
        buffer_align_begin);
    EXPECT_TRUE(proxy->AsanPointerToUserPointer(buffer_align_begin) ==
        user_ptr);

    void* expected_user_ptr = reinterpret_cast<void*>(
        buffer_align_begin + std::max(sizeof(TestHeapProxy::BlockHeader),
                                      alloc_alignment));
    EXPECT_TRUE(user_ptr == expected_user_ptr);

    size_t i = 0;
    // Ensure that the buffer header is accessible and correctly tagged.
    for (; i < buffer_header_size; ++i) {
      EXPECT_EQ(kBufferHeaderValue, buffer[i]);
      EXPECT_TRUE(Shadow::IsAccessible(buffer + i));
    }
    size_t user_block_offset = reinterpret_cast<uint8*>(user_ptr) - buffer;
    // Ensure that the block header isn't accessible.
    for (; i < user_block_offset; ++i) {
      EXPECT_FALSE(Shadow::IsAccessible(buffer + i));
    }
    // Ensure that the user block is accessible.
    size_t block_trailer_offset = i + alloc_size;
    for (; i < block_trailer_offset; ++i) {
      EXPECT_TRUE(Shadow::IsAccessible(buffer + i));
    }
    // Ensure that the block trailer isn't accessible.
    for (; i < buffer_header_size + asan_alloc_size; ++i) {
      EXPECT_FALSE(Shadow::IsAccessible(buffer + i));
    }
    // Ensure that the buffer trailer is accessible and correctly tagged.
    for (; i < kBufferSize; ++i) {
      EXPECT_EQ(kBufferTrailerValue, buffer[i]);
      EXPECT_TRUE(Shadow::IsAccessible(buffer + i));
    }

    is_initialized = true;
    return true;
  }

  // Ensures that this block has a valid block header.
  bool TestBlockHeader() {
    if (!is_initialized)
      return false;

    // Ensure that the block header is valid. UserPointerToBlockHeader takes
    // care of checking the magic number in the signature of the block.
    TestHeapProxy::BlockHeader* block_header = proxy->UserPointerToBlockHeader(
        user_ptr);
    EXPECT_TRUE(block_header != NULL);
    TestHeapProxy::BlockTrailer* block_trailer =
        TestHeapProxy::BlockHeaderToBlockTrailer(block_header);
    EXPECT_EQ(::GetCurrentThreadId(), block_trailer->alloc_tid);
    EXPECT_TRUE(block_header->alloc_stack != NULL);

    // Test the various accessors.
    EXPECT_TRUE(proxy->BlockHeaderToUserPointer(block_header) == user_ptr);
    EXPECT_TRUE(proxy->BlockHeaderToAsanPointer(block_header) ==
        buffer_align_begin);

    return true;
  }

  // Mark the current ASan block as quarantined.
  bool MarkBlockAsQuarantined() {
    if (!is_initialized)
      return false;

    TestHeapProxy::BlockHeader* block_header = proxy->UserPointerToBlockHeader(
        user_ptr);
    TestHeapProxy::BlockTrailer* block_trailer =
        proxy->BlockHeaderToBlockTrailer(block_header);
    EXPECT_TRUE(block_header->free_stack == NULL);
    EXPECT_TRUE(block_trailer != NULL);
    EXPECT_EQ(0U, block_trailer->free_tid);

    StackCapture stack;
    stack.InitFromStack();
    // Mark the block as quarantined.
    EXPECT_TRUE(proxy->MarkBlockAsQuarantined(block_header, stack));
    EXPECT_TRUE(block_header->free_stack != NULL);
    EXPECT_EQ(::GetCurrentThreadId(), block_trailer->free_tid);

    size_t i = 0;
    // Ensure that the buffer header is accessible and correctly tagged.
    for (; i < buffer_header_size; ++i) {
      EXPECT_EQ(kBufferHeaderValue, buffer[i]);
      EXPECT_TRUE(Shadow::IsAccessible(buffer + i));
    }
    // Ensure that the whole block isn't accessible.
    for (; i < buffer_header_size + asan_alloc_size; ++i) {
      EXPECT_FALSE(Shadow::IsAccessible(buffer + i));
    }
    // Ensure that the buffer trailer is accessible and correctly tagged.
    for (; i < kBufferSize; ++i) {
      EXPECT_EQ(kBufferTrailerValue, buffer[i]);
      EXPECT_TRUE(Shadow::IsAccessible(buffer + i));
    }
    return true;
  }

  // The buffer we use internally.
  uint8 buffer[kBufferSize];

  // The heap proxy we delegate to.
  TestHeapProxy* proxy;

  // The alignment of the current allocation.
  size_t alloc_alignment;
  size_t alloc_alignment_log;

  // The sizes of the different sub-structures in the buffer.
  size_t asan_alloc_size;
  size_t buffer_header_size;
  size_t buffer_trailer_size;

  // The pointers to the different sub-structures in the buffer.
  uint8* buffer_align_begin;
  void* user_ptr;

  // Indicate if the buffer has been initialized.
  bool is_initialized;
};

}  // namespace

TEST_F(HeapTest, InitializeAsanBlock) {
  for (size_t alloc_alignment_log = Shadow::kShadowGranularityLog;
       alloc_alignment_log < 12;
       ++alloc_alignment_log) {
    FakeAsanBlock fake_block(&proxy_, alloc_alignment_log);
    const size_t kAllocSize = 100;
    EXPECT_TRUE(fake_block.InitializeBlock(kAllocSize));
    EXPECT_TRUE(fake_block.TestBlockHeader());
  }
}

TEST_F(HeapTest, MarkBlockAsQuarantined) {
  for (size_t alloc_alignment_log = Shadow::kShadowGranularityLog;
       alloc_alignment_log < 12;
       ++alloc_alignment_log) {
    FakeAsanBlock fake_block(&proxy_, alloc_alignment_log);
    const size_t kAllocSize = 100;
    EXPECT_TRUE(fake_block.InitializeBlock(kAllocSize));
    EXPECT_TRUE(fake_block.TestBlockHeader());
    EXPECT_TRUE(fake_block.MarkBlockAsQuarantined());
  }
}

TEST_F(HeapTest, ReleaseASanBlock) {
  for (size_t alloc_alignment_log = Shadow::kShadowGranularityLog;
       alloc_alignment_log < 12;
       ++alloc_alignment_log) {
    FakeAsanBlock fake_block(&proxy_, alloc_alignment_log);
    const size_t kAllocSize = 100;
    EXPECT_TRUE(fake_block.InitializeBlock(kAllocSize));
    EXPECT_TRUE(fake_block.TestBlockHeader());
    EXPECT_TRUE(fake_block.MarkBlockAsQuarantined());

    TestHeapProxy::BlockHeader* block_header = proxy_.UserPointerToBlockHeader(
        fake_block.user_ptr);
    TestHeapProxy::BlockTrailer* block_trailer =
        proxy_.BlockHeaderToBlockTrailer(block_header);
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

    proxy_.ReleaseASanBlock(block_header, block_trailer);

    EXPECT_TRUE(proxy_.IsFreed(block_header));
    EXPECT_EQ(1U, alloc_stack->ref_count());
    EXPECT_EQ(1U, free_stack->ref_count());
    alloc_stack->RemoveRef();
    free_stack->RemoveRef();
  }
}

}  // namespace asan
}  // namespace agent
