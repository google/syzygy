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

#include "base/float_util.h"
#include "base/hash.h"
#include "base/logging.h"
#include "base/string_util.h"
#include "base/stringprintf.h"
#include "base/time.h"
#include "base/debug/alias.h"
#include "base/debug/stack_trace.h"
#include "base/strings/sys_string_conversions.h"
#include "syzygy/agent/asan/asan_runtime.h"
#include "syzygy/agent/asan/asan_shadow.h"
#include "syzygy/common/align.h"
#include "syzygy/common/asan_parameters.h"
#include "syzygy/trace/common/clock.h"

namespace agent {
namespace asan {
namespace {

typedef StackCapture::StackId StackId;

// The first 64kB of the memory are not addressable.
const uint8* kAddressLowerLimit = reinterpret_cast<uint8*>(0x10000);

// Utility class which implements an auto lock for a HeapProxy.
class HeapLocker {
 public:
  explicit HeapLocker(HeapProxy* const heap) : heap_(heap) {
    DCHECK(heap != NULL);
    if (!heap->Lock()) {
      LOG(ERROR) << "Unable to lock the heap.";
    }
  }

  ~HeapLocker() {
    DCHECK(heap_ != NULL);
    if (!heap_->Unlock()) {
      LOG(ERROR) << "Unable to lock the heap.";
    }
  }

 private:
  HeapProxy* const heap_;

  DISALLOW_COPY_AND_ASSIGN(HeapLocker);
};

// Returns the number of CPU cycles per microsecond.
double GetCpuCyclesPerUs() {
  trace::common::TimerInfo tsc_info = {};
  trace::common::GetTscTimerInfo(&tsc_info);

  if (tsc_info.frequency != 0) {
    return (tsc_info.frequency /
        static_cast<double>(base::Time::kMicrosecondsPerSecond));
  } else {
    uint64 cycle_start = trace::common::GetTsc();
    ::Sleep(HeapProxy::kSleepTimeForApproximatingCPUFrequency);
    return (trace::common::GetTsc() - cycle_start) /
        (HeapProxy::kSleepTimeForApproximatingCPUFrequency *
             static_cast<double>(base::Time::kMicrosecondsPerSecond));
  }
}

// Verify that the memory range [mem, mem + len[ is accessible.
bool MemoryRangeIsAccessible(uint8* mem, size_t len) {
  for (size_t i = 0; i < len; ++i) {
    if (!Shadow::IsAccessible(mem + i))
      return false;
  }
  return true;
}

// Combine the bits of a uint32 into the number of bits used to store the
// block checksum.
// @param val The value to combined with the checksum.
// @param checksum A pointer to the checksum to update.
void CombineUInt32IntoBlockChecksum(uint32 val, uint32* checksum) {
  DCHECK_NE(reinterpret_cast<uint32*>(NULL), checksum);
  while (val != 0) {
    *checksum ^= val;
    val >>= HeapProxy::kChecksumBits;
  }
  *checksum &= ((1 << HeapProxy::kChecksumBits) - 1);
}

}  // namespace

StackCaptureCache* HeapProxy::stack_cache_ = NULL;
double HeapProxy::cpu_cycles_per_us_ = std::numeric_limits<double>::quiet_NaN();
// The default quarantine and block size for a new Heap.
size_t HeapProxy::default_quarantine_max_size_ = common::kDefaultQuarantineSize;
size_t HeapProxy::default_quarantine_max_block_size_ =
    common::kDefaultQuarantineBlockSize;
size_t HeapProxy::trailer_padding_size_ = common::kDefaultTrailerPaddingSize;
const char* HeapProxy::kHeapUseAfterFree = "heap-use-after-free";
const char* HeapProxy::kHeapBufferUnderFlow = "heap-buffer-underflow";
const char* HeapProxy::kHeapBufferOverFlow = "heap-buffer-overflow";
const char* HeapProxy::kAttemptingDoubleFree = "attempting double-free";
const char* HeapProxy::kInvalidAddress = "invalid-address";
const char* HeapProxy::kWildAccess = "wild-access";
const char* HeapProxy::kHeapUnknownError = "heap-unknown-error";
const char* HeapProxy::kHeapCorruptedBlock = "corrupted-block";
const char* HeapProxy::kCorruptedHeap = "corrupted-heap";

HeapProxy::HeapProxy()
    : heap_(NULL),
      quarantine_size_(0),
      quarantine_max_size_(0),
      quarantine_max_block_size_(0),
      owns_heap_(false) {
  ::memset(heads_, 0, sizeof(heads_));
  ::memset(tails_, 0, sizeof(tails_));
}

HeapProxy::~HeapProxy() {
  if (heap_ != NULL)
    Destroy();

  DCHECK(heap_ == NULL);
}

void HeapProxy::Init(StackCaptureCache* cache) {
  DCHECK(cache != NULL);
  default_quarantine_max_size_ = common::kDefaultQuarantineSize;
  default_quarantine_max_block_size_ = common::kDefaultQuarantineBlockSize;
  trailer_padding_size_ = common::kDefaultTrailerPaddingSize;
  stack_cache_ = cache;
}

HANDLE HeapProxy::ToHandle(HeapProxy* proxy) {
  DCHECK(proxy != NULL);
  return proxy;
}

HeapProxy* HeapProxy::FromHandle(HANDLE heap) {
  DCHECK(heap != NULL);
  return reinterpret_cast<HeapProxy*>(heap);
}

bool HeapProxy::Create(DWORD options,
                       size_t initial_size,
                       size_t maximum_size) {
  DCHECK(heap_ == NULL);

  SetQuarantineMaxSize(default_quarantine_max_size_);
  SetQuarantineMaxBlockSize(default_quarantine_max_block_size_);

  HANDLE heap_new = ::HeapCreate(options, initial_size, maximum_size);
  if (heap_new == NULL)
    return false;

  owns_heap_ = true;
  heap_ = heap_new;

  return true;
}

void HeapProxy::UseHeap(HANDLE underlying_heap) {
  DCHECK(heap_ == NULL);
  SetQuarantineMaxSize(default_quarantine_max_size_);
  SetQuarantineMaxBlockSize(default_quarantine_max_block_size_);
  heap_ = underlying_heap;
  owns_heap_ = false;
}

void HeapProxy::SetBlockChecksum(BlockHeader* block_header) {
  DCHECK_NE(reinterpret_cast<BlockHeader*>(NULL), block_header);

  block_header->checksum = 0;
  uint32 block_checksum = 0;

  if (block_header->state == ALLOCATED) {
    // If the block is allocated then we don't want to include the content of
    // the block in the checksum, we just use the header and trailer.
    const uint8* header_begin = BlockHeaderToAsanPointer(block_header);
    const uint8* header_end = BlockHeaderToUserPointer(block_header);
    uint32 header_checksum =
        base::SuperFastHash(reinterpret_cast<const char*>(header_begin),
                            header_end - header_begin);
    const uint8* block_end = header_end + block_header->block_size;
    const uint8* trailer_end = reinterpret_cast<const uint8*>(
        common::AlignUp(reinterpret_cast<const size_t>(block_end) +
            sizeof(BlockTrailer) + trailer_padding_size_,
                Shadow::kShadowGranularity));
    uint32 trailer_checksum =
        base::SuperFastHash(reinterpret_cast<const char*>(block_end),
        trailer_end - block_end);
    CombineUInt32IntoBlockChecksum(header_checksum ^ trailer_checksum,
                                   &block_checksum);
  } else if (block_header->state == QUARANTINED) {
    // If the block is quarantined then we also include the content of the block
    // in the calculation. We ignore the pointer to the next free block as it is
    // modified when entering and exiting the quarantine.
    // TODO(chrisha): Remove the next free block pointer from the block trailer
    //     and store it out of band in the quarantine itself. This will make us
    //     more resistant to heap corruption.
    BlockTrailer* block_trailer = BlockHeaderToBlockTrailer(block_header);
    char* begin1 = reinterpret_cast<char*>(block_header);
    char* end = begin1 + GetAllocSize(block_header->block_size,
                                      1 << block_header->alignment_log);
    size_t length1 = reinterpret_cast<char*>(&block_trailer->next_free_block) -
        begin1;
    char* begin2 = reinterpret_cast<char*>(block_trailer + 1);
    size_t length2 = end - begin2;

    uint32 checksum1 = base::SuperFastHash(begin1, length1);
    uint32 checksum2 = base::SuperFastHash(begin2, length2);

    CombineUInt32IntoBlockChecksum(checksum1 ^ checksum2, &block_checksum);
  } else {
    NOTREACHED();
  }

  block_header->checksum = block_checksum;
}

bool HeapProxy::Destroy() {
  DCHECK(heap_ != NULL);

  // Flush the quarantine.
  SetQuarantineMaxSize(0);

  if (owns_heap_ && !::HeapDestroy(heap_))
    return false;

  heap_ = NULL;
  return true;
}

void* HeapProxy::Alloc(DWORD flags, size_t bytes) {
  DCHECK(heap_ != NULL);

  size_t alloc_size = GetAllocSize(bytes, kDefaultAllocGranularity);

  // GetAllocSize can return a smaller value if the alloc size is incorrect
  // (i.e. 0xffffffff).
  if (alloc_size < bytes)
    return NULL;

  uint8* block_mem = reinterpret_cast<uint8*>(
      ::HeapAlloc(heap_, flags, alloc_size));

  // Capture the current stack. InitFromStack is inlined to preserve the
  // greatest number of stack frames.
  StackCapture stack;
  stack.InitFromStack();

  return InitializeAsanBlock(block_mem,
                             bytes,
                             alloc_size,
                             kDefaultAllocGranularityLog,
                             stack);
}

void* HeapProxy::InitializeAsanBlock(uint8* asan_pointer,
                                     size_t user_size,
                                     size_t asan_size,
                                     size_t alloc_granularity_log,
                                     const StackCapture& stack) {
  if (asan_pointer == NULL)
    return NULL;

  // Here's the layout of an ASan block:
  //
  // +----------------------+--------------+-------+---------------+---------+
  // | Block Header Padding | Block Header | Block | Block Trailer | Padding |
  // +----------------------+--------------+-------+---------------+---------+
  //
  // Block Header padding (optional): This is only present when the block has an
  //     alignment bigger than the size of the BlockHeader structure. In this
  //     case the size of the padding will be stored at the beginning of this
  //     zone. This zone is poisoned.
  // Block Header: A structure containing some of the metadata about this block.
  //     This zone is poisoned.
  // Block: The user space. This zone isn't poisoned.
  // Block Trailer: A structure containing some of the metadata about this
  //     block. This zone is poisoned.
  // Padding (optional): Some padding to align the size of the whole structure
  //     to the block alignment. This zone is poisoned.

  if (alloc_granularity_log < Shadow::kShadowGranularityLog)
    alloc_granularity_log = Shadow::kShadowGranularityLog;

  size_t header_size = common::AlignUp(sizeof(BlockHeader),
                                       1 << alloc_granularity_log);

  BlockHeader* block_header = reinterpret_cast<BlockHeader*>(
      asan_pointer + header_size - sizeof(BlockHeader));

  // Check if we need the block header padding size at the beginning of the
  // block.
  if (header_size > sizeof(BlockHeader)) {
    size_t padding_size = header_size - sizeof(BlockHeader);
    DCHECK_GE(padding_size, sizeof(padding_size));
    *(reinterpret_cast<size_t*>(asan_pointer)) = padding_size;
  }

  // Poison the block header.
  Shadow::Poison(asan_pointer,
                 header_size - sizeof(BlockHeader),
                 Shadow::kHeapLeftRedzone);
  Shadow::Poison(block_header,
                 sizeof(BlockHeader),
                 Shadow::kHeapBlockHeaderByte);

  // Initialize the block fields.
  block_header->magic_number = kBlockHeaderSignature;
  block_header->block_size = user_size;
  block_header->state = ALLOCATED;
  block_header->alloc_stack = stack_cache_->SaveStackTrace(stack);
  block_header->free_stack = NULL;
  block_header->alignment_log = alloc_granularity_log;

  BlockTrailer* block_trailer = BlockHeaderToBlockTrailer(block_header);
  block_trailer->free_tid = 0;
  block_trailer->next_free_block = NULL;
  block_trailer->alloc_tid = ::GetCurrentThreadId();

  uint8* block_alloc = BlockHeaderToUserPointer(block_header);
  DCHECK(MemoryRangeIsAccessible(block_alloc, user_size));

  // Poison the block trailer.
  size_t trailer_size = asan_size - user_size - header_size;
  Shadow::Poison(block_alloc + user_size,
                 trailer_size,
                 Shadow::kHeapRightRedzone);

  SetBlockChecksum(block_header);

  return block_alloc;
}

void* HeapProxy::ReAlloc(DWORD flags, void* mem, size_t bytes) {
  DCHECK(heap_ != NULL);

  // Always fail in-place reallocation requests.
  if ((flags & HEAP_REALLOC_IN_PLACE_ONLY) != 0)
    return NULL;

  void *new_mem = Alloc(flags, bytes);
  // Bail early if the new allocation didn't succeed
  // and avoid freeing the existing allocation.
  if (new_mem == NULL)
    return NULL;

  if (mem != NULL) {
    memcpy(new_mem, mem, std::min(bytes, Size(0, mem)));
    Free(flags, mem);
  }

  return new_mem;
}

bool HeapProxy::Free(DWORD flags, void* mem) {
  DCHECK_NE(reinterpret_cast<HANDLE>(NULL), heap_);

  // The standard allows to call free on a null pointer.
  if (mem == NULL)
    return true;

  BlockHeader* block = UserPointerToBlockHeader(mem);
  DCHECK(BlockHeaderToUserPointer(block) == mem);

  if (!VerifyChecksum(block)) {
    // The free stack hasn't yet been set, but may have been filled with junk.
    // Reset it.
    block->free_stack = NULL;

    // Report the error.
    ReportHeapError(mem, CORRUPTED_BLOCK);

    // Try to clean up the block anyways.
    if (!FreeCorruptedBlock(mem, NULL))
      return false;
    return true;
  }

  // Capture the current stack.
  StackCapture stack;
  stack.InitFromStack();

  // Mark the block as quarantined.
  if (!MarkBlockAsQuarantined(block, stack)) {
    ReportHeapError(mem, DOUBLE_FREE);
    return false;
  }

  QuarantineBlock(block);

  return true;
}

void HeapProxy::MarkBlockAsQuarantined(void* asan_pointer,
                                       const StackCapture& stack) {
  DCHECK_NE(reinterpret_cast<void*>(NULL), asan_pointer);
  BlockHeader* block_header = AsanPointerToBlockHeader(asan_pointer);

  MarkBlockAsQuarantined(block_header, stack);
}

bool HeapProxy::MarkBlockAsQuarantined(BlockHeader* block_header,
                                       const StackCapture& stack) {
  if (block_header->state != ALLOCATED) {
    // We're not supposed to see another kind of block here, the FREED state
    // is only applied to block after invalidating their magic number and freed
    // them.
    DCHECK(block_header->state == QUARANTINED);
    return false;
  }

  block_header->free_stack = stack_cache_->SaveStackTrace(stack);

  BlockTrailer* trailer = BlockHeaderToBlockTrailer(block_header);
  trailer->free_timestamp = trace::common::GetTsc();
  trailer->free_tid = ::GetCurrentThreadId();

  block_header->state = QUARANTINED;

  // Poison the released alloc (marked as freed) and quarantine the block.
  // Note that the original data is left intact. This may make it easier
  // to debug a crash report/dump on access to a quarantined block.
  uint8* mem = BlockHeaderToUserPointer(block_header);
  Shadow::MarkAsFreed(mem, block_header->block_size);

  // TODO(chrisha): Poison the memory by XORing it?

  SetBlockChecksum(block_header);

  return true;
}

size_t HeapProxy::Size(DWORD flags, const void* mem) {
  DCHECK(heap_ != NULL);
  BlockHeader* block = UserPointerToBlockHeader(mem);
  if (block == NULL)
    return -1;

  return block->block_size;
}

bool HeapProxy::Validate(DWORD flags, const void* mem) {
  DCHECK(heap_ != NULL);
  return ::HeapValidate(heap_, flags, UserPointerToBlockHeader(mem)) == TRUE;
}

size_t HeapProxy::Compact(DWORD flags) {
  DCHECK(heap_ != NULL);
  return ::HeapCompact(heap_, flags);
}

bool HeapProxy::Lock() {
  DCHECK(heap_ != NULL);
  return ::HeapLock(heap_) == TRUE;
}

bool HeapProxy::Unlock() {
  DCHECK(heap_ != NULL);
  return ::HeapUnlock(heap_) == TRUE;
}

bool HeapProxy::Walk(PROCESS_HEAP_ENTRY* entry) {
  DCHECK(heap_ != NULL);
  return ::HeapWalk(heap_, entry) == TRUE;
}

bool HeapProxy::SetInformation(HEAP_INFORMATION_CLASS info_class,
                               void* info,
                               size_t info_length) {
  DCHECK(heap_ != NULL);
  // We don't allow the HeapEnableTerminationOnCorruption flag to be set, as we
  // prefer to catch and report these ourselves.
  if (info_class = ::HeapEnableTerminationOnCorruption)
    return true;
  return ::HeapSetInformation(heap_, info_class, info, info_length) == TRUE;
}

bool HeapProxy::QueryInformation(HEAP_INFORMATION_CLASS info_class,
                                 void* info,
                                 size_t info_length,
                                 unsigned long* return_length) {
  DCHECK(heap_ != NULL);
  return ::HeapQueryInformation(heap_,
                                info_class,
                                info,
                                info_length,
                                return_length) == TRUE;
}

void HeapProxy::SetQuarantineMaxSize(size_t quarantine_max_size) {
  {
    base::AutoLock lock(lock_);
    quarantine_max_size_ = quarantine_max_size;

    // This also acts as a cap on the maximum size of a block that can enter the
    // quarantine.
    quarantine_max_block_size_ = std::min(quarantine_max_block_size_,
                                          quarantine_max_size_);
  }

  TrimQuarantine();
}

void HeapProxy::SetQuarantineMaxBlockSize(size_t quarantine_max_block_size) {
  {
    base::AutoLock lock(lock_);

    // Use the current max quarantine size as a cap.
    quarantine_max_block_size_ = std::min(quarantine_max_block_size,
                                          quarantine_max_size_);

    // TODO(chrisha): Clean up existing blocks that exceed that size? This will
    //     require an entirely new TrimQuarantine function. Since this is never
    //     changed at runtime except in our unittests, this is not clearly
    //     useful.
  }
}

bool HeapProxy::TrimQuarantine() {
  size_t size_of_block_just_freed = 0;
  bool success = true;

  while (true) {
    BlockHeader* free_block = NULL;
    BlockTrailer* trailer = NULL;

    // Randomly choose a quarantine shard from which to remove an element.
    // TODO(chrisha): Do we want this to be truly random, or hashed off of the
    //      block address and/or contents itself? Do we want to expose multiple
    //      eviction strategies?
    size_t i = rand() % kQuarantineShards;

    // This code runs under a critical lock. Try to keep as much work out of
    // this scope as possible!
    {
      base::AutoLock lock(lock_);

      // We subtract this here under the lock because we actually calculate the
      // size of the block outside of the lock when we validate the checksum.
      DCHECK_GE(quarantine_size_, size_of_block_just_freed);
      quarantine_size_ -= size_of_block_just_freed;

      // Stop when the quarantine is back down to a reasonable size.
      if (quarantine_size_ <= quarantine_max_size_)
        return success;

      // Make sure we haven't chosen an empty shard.
      while (heads_[i] == NULL) {
        ++i;
        if (i == kQuarantineShards)
          i = 0;
      }

      DCHECK_NE(reinterpret_cast<BlockHeader*>(NULL), heads_[i]);
      DCHECK_NE(reinterpret_cast<BlockHeader*>(NULL), tails_[i]);

      free_block = heads_[i];
      trailer = BlockHeaderToBlockTrailer(free_block);
      DCHECK_NE(reinterpret_cast<BlockTrailer*>(NULL), trailer);

      heads_[i] = trailer->next_free_block;
      if (heads_[i] == NULL)
        tails_[i] = NULL;
    }

    // Check if the block has been stomped while it's in the quarantine. If it
    // has we take great pains to delete it carefully, and also report an error.
    // Otherwise, we trust the data in the header and take the fast path.
    size_t alloc_size = 0;
    if (!VerifyChecksum(free_block)) {
      ReportHeapError(free_block, CORRUPTED_BLOCK);
      if (!FreeCorruptedBlock(free_block, &alloc_size))
        success = false;
    } else {
      alloc_size = GetAllocSize(free_block->block_size,
                                kDefaultAllocGranularity);
      if (!CleanUpAndFreeAsanBlock(free_block, alloc_size))
        success = false;
    }

    size_of_block_just_freed = alloc_size;
  }

  return success;
}

void HeapProxy::DestroyAsanBlock(void* asan_pointer) {
  DCHECK_NE(reinterpret_cast<void*>(NULL), asan_pointer);

  BlockHeader* block_header = AsanPointerToBlockHeader(asan_pointer);
  DCHECK_NE(reinterpret_cast<void*>(NULL), block_header);
  BlockTrailer* block_trailer = BlockHeaderToBlockTrailer(block_header);
  DCHECK_NE(reinterpret_cast<void*>(NULL), block_trailer);

  ReleaseAsanBlock(block_header);
}

void HeapProxy::ReleaseAsanBlock(BlockHeader* block_header) {
  DCHECK_NE(reinterpret_cast<void*>(NULL), block_header);

  // Return pointers to the stacks for reference counting purposes.
  if (block_header->alloc_stack != NULL) {
    stack_cache_->ReleaseStackTrace(block_header->alloc_stack);
    block_header->alloc_stack = NULL;
  }
  if (block_header->free_stack != NULL) {
    stack_cache_->ReleaseStackTrace(block_header->free_stack);
    block_header->free_stack = NULL;
  }

  block_header->state = FREED;
}

bool HeapProxy::FreeCorruptedBlock(BlockHeader* header, size_t* alloc_size) {
  DCHECK_NE(reinterpret_cast<BlockHeader*>(NULL), header);

  // TODO(chrisha): Is there a better way to do this? We should be able to do an
  //     exhaustive check of the stack cache to check for validity.
  // Set the alloc and free pointers to NULL as they might be invalid.
  header->alloc_stack = NULL;
  header->free_stack = NULL;

  // Calculate the allocation size via the shadow as the header might be
  // corrupted.
  size_t size = Shadow::GetAllocSize(reinterpret_cast<uint8*>(header));
  if (alloc_size != NULL)
    *alloc_size = size;
  if (!CleanUpAndFreeAsanBlock(header, size))
    return false;
  return true;
}

bool HeapProxy::FreeCorruptedBlock(void* user_pointer, size_t* alloc_size) {
  DCHECK_NE(reinterpret_cast<void*>(NULL), user_pointer);

  // We can't use UserPointerToBlockHeader because the magic number of the
  // header might be invalid.
  BlockHeader* header = reinterpret_cast<BlockHeader*>(user_pointer) - 1;
  if (!FreeCorruptedBlock(header, alloc_size))
    return false;
  return true;
}

bool HeapProxy::CleanUpAndFreeAsanBlock(BlockHeader* block_header,
                                        size_t alloc_size) {
  ReleaseAsanBlock(block_header);
  Shadow::Unpoison(block_header, alloc_size);

  // TODO(chrisha): Fill the block with garbage?

  if (::HeapFree(heap_, 0, block_header) != TRUE) {
    ReportHeapError(block_header, CORRUPTED_HEAP);
    return false;
  }

  return true;
}

void HeapProxy::ReportHeapError(void* address, BadAccessKind kind) {
  DCHECK_NE(reinterpret_cast<void*>(NULL), address);

  // Collect information about the error.
  AsanErrorInfo error_info = {};
  ::RtlCaptureContext(&error_info.context);
  error_info.access_mode = HeapProxy::ASAN_UNKNOWN_ACCESS;
  error_info.location = address;
  error_info.error_type = kind;
  GetBadAccessInformation(&error_info);
  agent::asan::StackCapture stack;
  stack.InitFromStack();
  error_info.crash_stack_id = stack.ComputeRelativeStackId();

  // We expect a callback to be set.
  DCHECK(!heap_error_callback_.is_null());
  heap_error_callback_.Run(&error_info);
}

void HeapProxy::CloneObject(const void* src_asan_pointer,
                            void* dst_asan_pointer) {
  DCHECK_NE(reinterpret_cast<void*>(NULL), src_asan_pointer);
  DCHECK_NE(reinterpret_cast<void*>(NULL), dst_asan_pointer);

  BlockHeader* block_header = AsanPointerToBlockHeader(
      const_cast<void*>(src_asan_pointer));
  DCHECK_NE(reinterpret_cast<void*>(NULL), block_header);

  DCHECK_NE(reinterpret_cast<StackCapture*>(NULL), block_header->alloc_stack);
  const_cast<StackCapture*>(block_header->alloc_stack)->AddRef();
  if (block_header->free_stack != NULL)
    const_cast<StackCapture*>(block_header->free_stack)->AddRef();

  size_t alloc_size = GetAllocSize(block_header->block_size,
                                   1 << block_header->alignment_log);

  memcpy(dst_asan_pointer, src_asan_pointer, alloc_size);

  Shadow::CloneShadowRange(src_asan_pointer, dst_asan_pointer, alloc_size);
}

void HeapProxy::QuarantineBlock(BlockHeader* block) {
  DCHECK(block != NULL);

  DCHECK(BlockHeaderToBlockTrailer(block)->next_free_block == NULL);
  size_t alloc_size = GetAllocSize(block->block_size,
                                   kDefaultAllocGranularity);

  // If the block is bigger than the quarantine then it will immediately be
  // trimmed and it will simply cause the quarantine to empty itself. So as not
  // to dominate the quarantine with overly large blocks we also limit blocks to
  // an (optional) maximum size.
  if (alloc_size > quarantine_max_block_size_ ||
      alloc_size > quarantine_max_size_) {
    // Don't worry if CleanUpAndFreeAsanBlock fails as it will report a heap
    // error in this case.
    CleanUpAndFreeAsanBlock(block, alloc_size);
    return;
  }

  // Randomly choose a quarantine shard to receive the block.
  size_t i = rand() % kQuarantineShards;

  {
    base::AutoLock lock(lock_);

    quarantine_size_ += alloc_size;
    if (tails_[i] != NULL) {
      BlockHeaderToBlockTrailer(tails_[i])->next_free_block = block;
    } else {
      DCHECK_EQ(reinterpret_cast<BlockHeader*>(NULL), heads_[i]);
      heads_[i] = block;
    }
    tails_[i] = block;
  }

  TrimQuarantine();
}

size_t HeapProxy::GetAllocSize(size_t bytes, size_t alignment) {
  bytes += std::max(sizeof(BlockHeader), alignment);
  bytes += sizeof(BlockTrailer);
  bytes += trailer_padding_size_;
  return common::AlignUp(bytes, Shadow::kShadowGranularity);
}

HeapProxy::BlockHeader* HeapProxy::UserPointerToBlockHeader(
    const void* user_pointer) {
  if (user_pointer == NULL)
    return NULL;

  const uint8* mem = static_cast<const uint8*>(user_pointer);
  const BlockHeader* header = reinterpret_cast<const BlockHeader*>(mem) - 1;
  if (header->magic_number != kBlockHeaderSignature)
    return NULL;

  return const_cast<BlockHeader*>(header);
}

HeapProxy::BlockHeader* HeapProxy::AsanPointerToBlockHeader(
    void* asan_pointer) {
  DCHECK_NE(reinterpret_cast<void*>(NULL), asan_pointer);

  void* user_pointer = AsanPointerToUserPointer(asan_pointer);
  DCHECK_NE(reinterpret_cast<void*>(NULL), user_pointer);

  return UserPointerToBlockHeader(user_pointer);
}

uint8* HeapProxy::AsanPointerToUserPointer(void* asan_pointer) {
  if (asan_pointer == NULL)
    return NULL;

  // Check if the ASan pointer is also pointing to the block header.
  BlockHeader* header = reinterpret_cast<BlockHeader*>(asan_pointer);
  if (header->magic_number == kBlockHeaderSignature)
    return BlockHeaderToUserPointer(const_cast<BlockHeader*>(header));

  // There's an offset between the ASan pointer and the block header, use it to
  // get the user pointer.
  size_t offset = *(reinterpret_cast<const size_t*>(asan_pointer));
  header = reinterpret_cast<BlockHeader*>(
      reinterpret_cast<uint8*>(asan_pointer) + offset);

  // No need to check the signature of the header here, this is already done in
  // BlockHeaderToUserPointer.
  return BlockHeaderToUserPointer(header);
}

uint8* HeapProxy::BlockHeaderToAsanPointer(const BlockHeader* header) {
  DCHECK(header != NULL);
  DCHECK_EQ(kBlockHeaderSignature, header->magic_number);

  return reinterpret_cast<uint8*>(
      common::AlignDown(reinterpret_cast<size_t>(header),
                        1 << header->alignment_log));
}

uint8* HeapProxy::UserPointerToAsanPointer(const void* user_pointer) {
  if (user_pointer == NULL)
    return NULL;

  const BlockHeader* header =
      reinterpret_cast<const BlockHeader*>(user_pointer) - 1;

  return BlockHeaderToAsanPointer(header);
}

HeapProxy::BlockTrailer* HeapProxy::BlockHeaderToBlockTrailer(
    const BlockHeader* header) {
  DCHECK(header != NULL);
  DCHECK_EQ(kBlockHeaderSignature, header->magic_number);
  // We want the block trailers to be 4 byte aligned after the end of a block.
  const size_t kBlockTrailerAlignment = 4;

  uint8* mem = reinterpret_cast<uint8*>(const_cast<BlockHeader*>(header));
  size_t aligned_size =
      common::AlignUp(sizeof(BlockHeader) + header->block_size,
                      kBlockTrailerAlignment);

  return reinterpret_cast<BlockTrailer*>(mem + aligned_size);
}

uint8* HeapProxy::BlockHeaderToUserPointer(BlockHeader* header) {
  DCHECK(header != NULL);
  DCHECK_EQ(kBlockHeaderSignature, header->magic_number);
  DCHECK(header->state == ALLOCATED || header->state == QUARANTINED);

  return reinterpret_cast<uint8*>(header + 1);
}

HeapProxy::BadAccessKind HeapProxy::GetBadAccessKind(const void* addr,
                                                     BlockHeader* header) {
  DCHECK(addr != NULL);
  DCHECK(header != NULL);

  BadAccessKind bad_access_kind = UNKNOWN_BAD_ACCESS;

  if (header->state == QUARANTINED) {
    bad_access_kind = USE_AFTER_FREE;
  } else {
    if (addr < (BlockHeaderToUserPointer(header)))
      bad_access_kind = HEAP_BUFFER_UNDERFLOW;
    else if (addr >= (BlockHeaderToUserPointer(header) + header->block_size))
      bad_access_kind = HEAP_BUFFER_OVERFLOW;
    else if (Shadow::GetShadowMarkerForAddress(addr) ==
        Shadow::kHeapFreedByte) {
      // This is a use after free on a block managed by a nested heap.
      bad_access_kind = USE_AFTER_FREE;
    }
  }
  return bad_access_kind;
}

HeapProxy::BlockHeader* HeapProxy::FindBlockContainingAddress(uint8* addr) {
  DCHECK(addr != NULL);

  uint8* original_addr = addr;
  addr = reinterpret_cast<uint8*>(
      common::AlignDown(reinterpret_cast<size_t>(addr),
      Shadow::kShadowGranularity));

  // Here's what the memory will look like for a block nested into another one:
  //          +-----------------------------+--------------+---------------+
  // Shadow:  |        Left redzone         |              | Right redzone |
  //          +------+---------------+------+--------------+-------+-------+
  // Memory:  |      | BH_2 Padding  | BH_2 | Data Block 2 | BT_2  |       |
  //          | BH_1 +---------------+------+--------------+-------+ BT_1  |
  //          |      |                 Data Block 1                |       |
  //          +------+---------------------------------------------+-------+
  // Legend:
  //   - BH_X: Block header of the block X.
  //   - BT_X: Block trailer of the block X.
  //
  // In this example block 2 has an alignment different from block 1, hence the
  // padding in front of its header.
  //
  // There can be several scenarios:
  //
  // 1) |addr| doesn't point to an address corresponding to a left redzone in
  //    the shadow. In this case we should walk the shadow until we find the
  //    header of a block containing |addr|.
  //
  // 2) |addr| points to the left redzone of the blocks, this can be due to
  //    several types of bad accesses: a underflow on block 1, a underflow on
  //    block 2 or a use after free on block 1. In this case we need to scan the
  //    shadow to the left and to the right until we find a block header, or
  //    until we get out of the shadow. We'll get 2 pointers to the bounds of
  //    the left redzone, at least one of them will point to a block header, if
  //    not then the heap is corrupted. If exactly one of them points to a
  //    header then it's our block header, if it doesn't encapsulate |addr| then
  //    the heap is corrupted. If both of them point to a block header then the
  //    address will fall in the header of exactly one of them. If both or
  //    neither, we have heap corruption.

  // This corresponds to the first case.
  if (!Shadow::IsLeftRedzone(addr)) {
    while (addr >= kAddressLowerLimit) {
      addr -= Shadow::kShadowGranularity;
      if (Shadow::GetShadowMarkerForAddress(reinterpret_cast<void*>(addr)) ==
          Shadow::kHeapBlockHeaderByte) {
        BlockHeader* header = reinterpret_cast<BlockHeader*>(addr -
            (sizeof(BlockHeader) - Shadow::kShadowGranularity));
        if (header->magic_number != kBlockHeaderSignature)
          continue;
        size_t block_size = GetAllocSize(header->block_size,
                                         1 << header->alignment_log);
        uint8* asan_ptr = BlockHeaderToAsanPointer(header);
        if (reinterpret_cast<uint8*>(original_addr) < asan_ptr + block_size)
          return header;
      }
    }

    // This address doesn't belong to any block.
    return NULL;
  }

  // The bad access occurred in a left redzone, this corresponds to the second
  // case.

  // Starts by looking for the left bound.
  uint8* left_bound = reinterpret_cast<uint8*>(addr);
  BlockHeader* left_header = NULL;
  size_t left_block_size = 0;
  while (Shadow::GetShadowMarkerForAddress(left_bound) ==
      Shadow::kHeapBlockHeaderByte) {
    BlockHeader* temp_header = reinterpret_cast<BlockHeader*>(left_bound);
    if (temp_header->magic_number == kBlockHeaderSignature) {
      left_header = temp_header;
      left_block_size = GetAllocSize(left_header->block_size,
                                     1 << left_header->alignment_log);
      break;
    }
    left_bound -= Shadow::kShadowGranularity;
  }

  // Look for the right bound.
  uint8* right_bound = reinterpret_cast<uint8*>(addr);
  BlockHeader* right_header = NULL;
  size_t right_block_size = 0;
  while (Shadow::IsLeftRedzone(right_bound + Shadow::kShadowGranularity)) {
    right_bound += Shadow::kShadowGranularity;
    BlockHeader* temp_header = reinterpret_cast<BlockHeader*>(right_bound);
    if (temp_header->magic_number == kBlockHeaderSignature) {
      right_header = temp_header;
      right_block_size = GetAllocSize(right_header->block_size,
                                      1 << right_header->alignment_log);
      break;
    }
  }

  CHECK(left_header != NULL || right_header != NULL);

  // If only one of the bounds corresponds to a block header then we return it.

  if (left_header != NULL && right_header == NULL) {
    if (original_addr >= reinterpret_cast<uint8*>(left_header) +
        left_block_size) {
      // TODO(sebmarchand): Report that the heap is corrupted.
      return NULL;
    }
    return left_header;
  }

  if (right_header != NULL && left_header == NULL) {
    if (original_addr < BlockHeaderToAsanPointer(right_header) ||
        original_addr >= BlockHeaderToAsanPointer(right_header) +
        right_block_size) {
      // TODO(sebmarchand): Report that the heap is corrupted.
      return NULL;
    }
    return right_header;
  }

  DCHECK(left_header != NULL && right_header != NULL);

  // Otherwise we start by looking if |addr| is contained in the rightmost
  // block.
  uint8* right_block_left_bound = reinterpret_cast<uint8*>(
      BlockHeaderToAsanPointer(right_header));
  if (original_addr >= right_block_left_bound &&
      original_addr < right_block_left_bound + right_block_size) {
    return right_header;
  }

  uint8* left_block_left_bound = reinterpret_cast<uint8*>(
      BlockHeaderToAsanPointer(left_header));
  if (original_addr < left_block_left_bound ||
      original_addr >= left_block_left_bound + left_block_size) {
    // TODO(sebmarchand): Report that the heap is corrupted.
    return NULL;
  }

  return left_header;
}

HeapProxy::BlockHeader* HeapProxy::FindContainingFreedBlock(
    BlockHeader* inner_block) {
  DCHECK_NE(reinterpret_cast<BlockHeader*>(NULL), inner_block);
  BlockHeader* containing_block = NULL;
  do {
    containing_block = FindContainingBlock(inner_block);
    inner_block = containing_block;
  } while (containing_block != NULL &&
           containing_block->state != QUARANTINED);
  return containing_block;
}

HeapProxy::BlockHeader* HeapProxy::FindContainingBlock(
    BlockHeader* inner_block) {
  DCHECK_NE(reinterpret_cast<BlockHeader*>(NULL), inner_block);
  DCHECK_EQ(kBlockHeaderSignature, inner_block->magic_number);

  size_t addr = reinterpret_cast<size_t>(inner_block);
  addr = common::AlignDown(addr - Shadow::kShadowGranularity,
                           Shadow::kShadowGranularity);

  // Try to find a block header containing this block.
  while (addr >= reinterpret_cast<size_t>(kAddressLowerLimit)) {
    // Only look at the addresses tagged as the redzone of a block.
    if (Shadow::GetShadowMarkerForAddress(reinterpret_cast<void*>(addr)) ==
        Shadow::kHeapBlockHeaderByte) {
      BlockHeader* temp_header = reinterpret_cast<BlockHeader*>(addr);
      if (temp_header->magic_number == kBlockHeaderSignature) {
        size_t block_size = GetAllocSize(temp_header->block_size,
                                    1 << temp_header->alignment_log);
        // Makes sure that the inner block is contained in this block.
        if (reinterpret_cast<size_t>(inner_block) <
            reinterpret_cast<size_t>(temp_header) + block_size) {
          return temp_header;
        }
      }
    }
    addr -= Shadow::kShadowGranularity;
  }

  return NULL;
}

bool HeapProxy::GetBadAccessInformation(AsanErrorInfo* bad_access_info) {
  DCHECK(bad_access_info != NULL);
  BlockHeader* header = FindBlockContainingAddress(
      reinterpret_cast<uint8*>(bad_access_info->location));

  if (header == NULL)
    return false;

  BlockTrailer* trailer = BlockHeaderToBlockTrailer(header);
  DCHECK(trailer != NULL);

  if (bad_access_info->error_type != DOUBLE_FREE &&
      bad_access_info->error_type != CORRUPTED_BLOCK) {
    bad_access_info->error_type = GetBadAccessKind(bad_access_info->location,
                                                   header);
  }

  // Checks if there's a containing block in the case of a use after free on a
  // block owned by a nested heap.
  BlockHeader* containing_block = NULL;
  if (bad_access_info->error_type == USE_AFTER_FREE &&
      header->state != QUARANTINED) {
    containing_block = FindContainingFreedBlock(header);
  }

  // Get the bad access description if we've been able to determine its kind.
  if (bad_access_info->error_type != UNKNOWN_BAD_ACCESS) {
    bad_access_info->microseconds_since_free = GetTimeSinceFree(header);

    DCHECK(header->alloc_stack != NULL);
    memcpy(bad_access_info->alloc_stack,
           header->alloc_stack->frames(),
           header->alloc_stack->num_frames() * sizeof(void*));
    bad_access_info->alloc_stack_size = header->alloc_stack->num_frames();
    bad_access_info->alloc_tid = trailer->alloc_tid;

    if (header->state != ALLOCATED) {
      const StackCapture* free_stack = header->free_stack;
      BlockTrailer* free_stack_trailer = trailer;
      // Use the free metadata of the containing block if there's one.
      if (containing_block != NULL) {
        free_stack = containing_block->free_stack;
        free_stack_trailer = BlockHeaderToBlockTrailer(containing_block);
      }
      memcpy(bad_access_info->free_stack,
             free_stack->frames(),
             free_stack->num_frames() * sizeof(void*));
      bad_access_info->free_stack_size = free_stack->num_frames();
      bad_access_info->free_tid = free_stack_trailer->free_tid;
    }
    GetAddressInformation(header, bad_access_info);
    return true;
  }

  return false;
}

void HeapProxy::GetAddressInformation(BlockHeader* header,
                                      AsanErrorInfo* bad_access_info) {
  DCHECK(header != NULL);
  DCHECK(bad_access_info != NULL);

  DCHECK(header != NULL);
  DCHECK(bad_access_info != NULL);
  DCHECK(bad_access_info->location != NULL);

  uint8* block_alloc = BlockHeaderToUserPointer(header);
  int offset = 0;
  char* offset_relativity = "";
  switch (bad_access_info->error_type) {
    case HEAP_BUFFER_OVERFLOW:
      offset = static_cast<const uint8*>(bad_access_info->location)
          - block_alloc - header->block_size;
      offset_relativity = "beyond";
      break;
    case HEAP_BUFFER_UNDERFLOW:
      offset = block_alloc -
          static_cast<const uint8*>(bad_access_info->location);
      offset_relativity = "before";
      break;
    case USE_AFTER_FREE:
      offset = static_cast<const uint8*>(bad_access_info->location)
          - block_alloc;
      offset_relativity = "inside";
      break;
    case WILD_ACCESS:
    case DOUBLE_FREE:
    case UNKNOWN_BAD_ACCESS:
    case CORRUPTED_BLOCK:
      return;
    default:
      NOTREACHED() << "Error trying to dump address information.";
  }

  size_t shadow_info_bytes = base::snprintf(
      bad_access_info->shadow_info,
      arraysize(bad_access_info->shadow_info) - 1,
      "%08X is %d bytes %s %d-byte block [%08X,%08X)\n",
      bad_access_info->location,
      offset,
      offset_relativity,
      header->block_size,
      block_alloc,
      block_alloc + header->block_size);

  std::string shadow_memory;
  Shadow::AppendShadowArrayText(bad_access_info->location, &shadow_memory);
  size_t shadow_mem_bytes = base::snprintf(
      bad_access_info->shadow_memory,
      arraysize(bad_access_info->shadow_memory) - 1,
      "%s",
      shadow_memory.c_str());

  // Ensure that we had enough space to store the full shadow information.
  DCHECK_LE(shadow_info_bytes, arraysize(bad_access_info->shadow_info) - 1);
  DCHECK_LE(shadow_mem_bytes, arraysize(bad_access_info->shadow_memory) - 1);
}

const char* HeapProxy::AccessTypeToStr(BadAccessKind bad_access_kind) {
  switch (bad_access_kind) {
    case USE_AFTER_FREE:
      return kHeapUseAfterFree;
    case HEAP_BUFFER_UNDERFLOW:
      return kHeapBufferUnderFlow;
    case HEAP_BUFFER_OVERFLOW:
      return kHeapBufferOverFlow;
    case WILD_ACCESS:
      return kWildAccess;
    case INVALID_ADDRESS:
      return kInvalidAddress;
    case DOUBLE_FREE:
      return kAttemptingDoubleFree;
    case UNKNOWN_BAD_ACCESS:
      return kHeapUnknownError;
    case CORRUPTED_BLOCK:
      return kHeapCorruptedBlock;
    case CORRUPTED_HEAP:
      return kCorruptedHeap;
    default:
      NOTREACHED() << "Unexpected bad access kind.";
      return NULL;
  }
}

LIST_ENTRY* HeapProxy::ToListEntry(HeapProxy* proxy) {
  DCHECK(proxy != NULL);
  return &proxy->list_entry_;
}

HeapProxy* HeapProxy::FromListEntry(LIST_ENTRY* list_entry) {
  DCHECK(list_entry != NULL);
  return CONTAINING_RECORD(list_entry, HeapProxy, list_entry_);
}

void HeapProxy::set_default_quarantine_max_size(
      size_t default_quarantine_max_size) {
  default_quarantine_max_size_ = default_quarantine_max_size;

  // If we change the quarantine size be sure to trim the corresponding maximum
  // block size.
  default_quarantine_max_block_size_ = std::min(
      default_quarantine_max_block_size_,
      default_quarantine_max_size_);
}

void HeapProxy::set_default_quarantine_max_block_size(
    size_t default_quarantine_max_block_size) {
  // Cap this with the default maximum quarantine size itself.
  default_quarantine_max_block_size_ = std::min(
      default_quarantine_max_block_size,
      default_quarantine_max_size_);
}

double HeapProxy::cpu_cycles_per_us() {
  if (!base::IsFinite(cpu_cycles_per_us_))
    cpu_cycles_per_us_ = GetCpuCyclesPerUs();
  return cpu_cycles_per_us_;
}

uint64 HeapProxy::GetTimeSinceFree(const BlockHeader* header) {
  DCHECK(header != NULL);

  if (header->state == ALLOCATED)
    return 0;

  BlockTrailer* trailer = BlockHeaderToBlockTrailer(header);
  DCHECK(trailer != NULL);

  uint64 cycles_since_free = trace::common::GetTsc() - trailer->free_timestamp;

  // On x86/64, as long as cpu_cycles_per_us_ is 64-bit aligned, the write is
  // atomic, which means we don't care about multiple writers since it's not an
  // update based on the previous value.
  DCHECK_NE(0.0, cpu_cycles_per_us());

  return cycles_since_free / cpu_cycles_per_us();
}

void HeapProxy::GetAsanExtent(const void* user_pointer,
                              void** asan_pointer,
                              size_t* size) {
  DCHECK_NE(reinterpret_cast<void*>(NULL), user_pointer);
  DCHECK_NE(reinterpret_cast<void*>(NULL), asan_pointer);
  DCHECK_NE(reinterpret_cast<void*>(NULL), size);

  *asan_pointer = UserPointerToAsanPointer(user_pointer);
  BlockHeader* block_header = UserPointerToBlockHeader(user_pointer);

  DCHECK_NE(reinterpret_cast<void*>(NULL), block_header);
  *size = GetAllocSize(block_header->block_size,
                       1 << block_header->alignment_log);
}

void HeapProxy::GetUserExtent(const void* asan_pointer,
                              void** user_pointer,
                              size_t* size) {
  DCHECK_NE(reinterpret_cast<void*>(NULL), asan_pointer);
  DCHECK_NE(reinterpret_cast<void*>(NULL), user_pointer);
  DCHECK_NE(reinterpret_cast<void*>(NULL), size);

  *user_pointer = AsanPointerToUserPointer(const_cast<void*>(asan_pointer));
  BlockHeader* block_header = UserPointerToBlockHeader(*user_pointer);

  DCHECK_NE(reinterpret_cast<void*>(NULL), block_header);
  *size = block_header->block_size;
}

bool HeapProxy::VerifyChecksum(BlockHeader* header) {
  size_t old_checksum = header->checksum;
  SetBlockChecksum(header);
  if (old_checksum != header->checksum)
    return false;
  return true;
}

}  // namespace asan
}  // namespace agent
