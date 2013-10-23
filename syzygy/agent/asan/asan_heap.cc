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
#include "syzygy/trace/common/clock.h"

namespace agent {
namespace asan {
namespace {

typedef StackCapture::StackId StackId;

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

}  // namespace

StackCaptureCache* HeapProxy::stack_cache_ = NULL;
double HeapProxy::cpu_cycles_per_us_ = 0.0;
// The default quarantine size for a new Heap.
size_t HeapProxy::default_quarantine_max_size_ = kDefaultQuarantineMaxSize;
size_t HeapProxy::trailer_padding_size_ = kDefaultTrailerPaddingSize;
const char* HeapProxy::kHeapUseAfterFree = "heap-use-after-free";
const char* HeapProxy::kHeapBufferUnderFlow = "heap-buffer-underflow";
const char* HeapProxy::kHeapBufferOverFlow = "heap-buffer-overflow";
const char* HeapProxy::kAttemptingDoubleFree = "attempting double-free";
const char* HeapProxy::kInvalidAddress = "invalid address";
const char* HeapProxy::kWildAccess = "wild access";
const char* HeapProxy::kHeapUnknownError = "heap-unknown-error";

HeapProxy::HeapProxy()
    : heap_(NULL),
      head_(NULL),
      tail_(NULL),
      quarantine_size_(0),
      quarantine_max_size_(0) {
}

HeapProxy::~HeapProxy() {
  if (heap_ != NULL)
    Destroy();

  DCHECK(heap_ == NULL);
}

void HeapProxy::Init(StackCaptureCache* cache) {
  DCHECK(cache != NULL);
  default_quarantine_max_size_ = kDefaultQuarantineMaxSize;
  trailer_padding_size_ = kDefaultTrailerPaddingSize;
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

  HANDLE heap_new = ::HeapCreate(options, initial_size, maximum_size);
  if (heap_new == NULL)
    return false;

  heap_ = heap_new;

  return true;
}

bool HeapProxy::Destroy() {
  DCHECK(heap_ != NULL);

  // Flush the quarantine.
  SetQuarantineMaxSize(0);

  if (!::HeapDestroy(heap_))
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
  size_t trailer_size = asan_size - user_size - header_size;
  Shadow::Poison(asan_pointer, header_size, Shadow::kHeapLeftRedzone);

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
  Shadow::Poison(block_alloc + user_size,
                 trailer_size,
                 Shadow::kHeapRightRedzone);

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
  DCHECK(heap_ != NULL);
  BlockHeader* block = UserPointerToBlockHeader(mem);
  // The standard allows to call free on a null pointer. ToBlock returns null if
  // the given pointer is null so we return true here.
  if (block == NULL)
    return true;

  DCHECK(BlockHeaderToUserPointer(block) == mem);

  // Capture the current stack.
  StackCapture stack;
  stack.InitFromStack();

  // Mark the block as quarantined.
  if (!MarkBlockAsQuarantined(block, stack))
    return false;

  QuarantineBlock(block);

  return true;
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

  // If the size of the allocation is zero then we shouldn't check the shadow
  // memory as it'll only contain the red-zone for the head and tail of this
  // block.
  if (block_header->block_size != 0 &&
      !Shadow::IsAccessible(BlockHeaderToUserPointer(block_header))) {
    return false;
  }

  block_header->state = QUARANTINED;

  // Poison the released alloc (marked as freed) and quarantine the block.
  // Note that the original data is left intact. This may make it easier
  // to debug a crash report/dump on access to a quarantined block.
  uint8* mem = BlockHeaderToUserPointer(block_header);
  Shadow::MarkAsFreed(mem, block_header->block_size);

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
  }

  TrimQuarantine();
}

void HeapProxy::TrimQuarantine() {
  while (true) {
    BlockHeader* free_block = NULL;
    BlockTrailer* trailer = NULL;
    size_t alloc_size = 0;

    // This code runs under a critical lock. Try to keep as much work out of
    // this scope as possible!
    {
      base::AutoLock lock(lock_);
      if (quarantine_size_ <= quarantine_max_size_)
        return;

      DCHECK(head_ != NULL);
      DCHECK(tail_ != NULL);

      free_block = head_;
      trailer = BlockHeaderToBlockTrailer(free_block);
      DCHECK(trailer != NULL);

      head_ = trailer->next_free_block;
      if (head_ == NULL)
        tail_ = NULL;

      alloc_size = GetAllocSize(free_block->block_size,
                                kDefaultAllocGranularity);

      DCHECK_GE(quarantine_size_, alloc_size);
      quarantine_size_ -= alloc_size;
    }

    // Clean up the block's metadata. We do this outside of the heap lock to
    // reduce contention.
    ReleaseASanBlock(free_block, trailer);

    Shadow::Unpoison(free_block, alloc_size);
    ::HeapFree(heap_, 0, free_block);
  }
}

void HeapProxy::ReleaseASanBlock(BlockHeader* block_header,
                                 BlockTrailer* block_trailer) {
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

void HeapProxy::QuarantineBlock(BlockHeader* block) {
  DCHECK(block != NULL);

  DCHECK(BlockHeaderToBlockTrailer(block)->next_free_block == NULL);
  size_t alloc_size = GetAllocSize(block->block_size,
                                   kDefaultAllocGranularity);

  {
    base::AutoLock lock(lock_);

    quarantine_size_ += alloc_size;
    if (tail_ != NULL) {
      BlockHeaderToBlockTrailer(tail_)->next_free_block = block;
    } else {
      DCHECK(head_ == NULL);
      head_ = block;
    }
    tail_ = block;
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
    // At this point we can't know if this address belongs to this
    // quarantined block... If the block containing this address has been
    // moved from the quarantine list its memory space could have been re-used
    // and freed again (so having this block in the quarantine list don't
    // guarantee that this is the original block).
    // TODO(sebmarchand): Find a way to fix this bug.
    bad_access_kind = USE_AFTER_FREE;
  } else {
    if (addr < (BlockHeaderToUserPointer(header)))
      bad_access_kind = HEAP_BUFFER_UNDERFLOW;
    else if (addr >= (BlockHeaderToUserPointer(header) + header->block_size))
      bad_access_kind = HEAP_BUFFER_OVERFLOW;
  }
  return bad_access_kind;
}

HeapProxy::BlockHeader* HeapProxy::FindAddressBlock(const void* addr) {
  DCHECK(addr != NULL);
  PROCESS_HEAP_ENTRY heap_entry = {};
  memset(&heap_entry, 0, sizeof(heap_entry));
  BlockHeader* header = NULL;

  // Walk through the heap to find the block containing @p addr.
  HeapLocker heap_locker(this);
  while (Walk(&heap_entry)) {
    uint8* entry_upper_bound =
        static_cast<uint8*>(heap_entry.lpData) + heap_entry.cbData;

    if (heap_entry.lpData <= addr && entry_upper_bound > addr) {
      header = reinterpret_cast<BlockHeader*>(heap_entry.lpData);
      // Ensures that the block have been allocated by this proxy.
      if (header->magic_number == kBlockHeaderSignature) {
        DCHECK(header->state != FREED);
        break;
      } else {
        header = NULL;
      }
    }
  }

  return header;
}

bool HeapProxy::GetBadAccessInformation(AsanErrorInfo* bad_access_info) {
  DCHECK(bad_access_info != NULL);
  base::AutoLock lock(lock_);
  BlockHeader* header = FindAddressBlock(bad_access_info->location);

  if (header == NULL)
    return false;

  BlockTrailer* trailer = BlockHeaderToBlockTrailer(header);
  DCHECK(trailer != NULL);

  if (bad_access_info->error_type != DOUBLE_FREE) {
    bad_access_info->error_type = GetBadAccessKind(bad_access_info->location,
                                                   header);
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
      memcpy(bad_access_info->free_stack,
             header->free_stack->frames(),
             header->free_stack->num_frames() * sizeof(void*));
      bad_access_info->free_stack_size = header->free_stack->num_frames();
      bad_access_info->free_tid = trailer->free_tid;
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
  if (cpu_cycles_per_us_ == 0.0)
    cpu_cycles_per_us_ = GetCpuCyclesPerUs();
  DCHECK_NE(0.0, cpu_cycles_per_us_);

  return cycles_since_free / cpu_cycles_per_us_;
}

}  // namespace asan
}  // namespace agent
