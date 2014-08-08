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
#include "base/rand_util.h"
#include "base/debug/alias.h"
#include "base/debug/stack_trace.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/strings/sys_string_conversions.h"
#include "base/time/time.h"
#include "syzygy/agent/asan/asan_heap_checker.h"
#include "syzygy/agent/asan/asan_runtime.h"
#include "syzygy/agent/asan/shadow.h"
#include "syzygy/common/align.h"
#include "syzygy/common/asan_parameters.h"
#include "syzygy/trace/common/clock.h"

namespace agent {
namespace asan {
namespace {

typedef StackCapture::StackId StackId;

// The first 64kB of the memory are not addressable.
const uint8* kAddressLowerLimit = reinterpret_cast<uint8*>(0x10000);

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
// The default quarantine and block size for a new Heap.
size_t HeapProxy::default_quarantine_max_size_ =
    common::kDefaultQuarantineSize;
size_t HeapProxy::default_quarantine_max_block_size_ =
    common::kDefaultQuarantineBlockSize;
size_t HeapProxy::trailer_padding_size_ = common::kDefaultTrailerPaddingSize;
float HeapProxy::allocation_guard_rate_ = common::kDefaultAllocationGuardRate;

HeapProxy::HeapProxy()
    : heap_(NULL),
      owns_heap_(false) {
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

  // Some allocations can pass through without instrumentation.
  if (allocation_guard_rate() < 1.0 &&
      base::RandDouble() >= allocation_guard_rate()) {
    void* alloc = ::HeapAlloc(heap_, flags, bytes);
    return alloc;
  }

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
                             kDefaultAllocGranularityLog,
                             false,
                             stack);
}

void* HeapProxy::InitializeAsanBlock(uint8* asan_pointer,
                                     size_t user_size,
                                     size_t alloc_granularity_log,
                                     bool is_nested,
                                     const StackCapture& stack) {
  if (asan_pointer == NULL)
    return NULL;

  BlockLayout layout = {};
  BlockPlanLayout(1 << alloc_granularity_log,
                  1 << alloc_granularity_log,
                  user_size,
                  1 << alloc_granularity_log,
                  trailer_padding_size_ + sizeof(BlockTrailer),
                  &layout);

  BlockInfo block_info = {};
  BlockInitialize(layout, asan_pointer, is_nested, &block_info);

  Shadow::PoisonAllocatedBlock(block_info);

  block_info.header->alloc_stack = stack_cache_->SaveStackTrace(stack);
  block_info.header->free_stack = NULL;

  BlockSetChecksum(block_info);

  return block_info.body;
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

  BlockHeader* header = BlockGetHeaderFromBody(mem);
  BlockInfo block_info = {};
  if (header == NULL || !Shadow::BlockInfoFromShadow(header, &block_info)) {
    // TODO(chrisha): Handle invalid allocation addresses. Currently we can't
    //     tell these apart from unguarded allocations.

    // Assume that this block was allocated without guards. The cast is
    // necessary for this to work on Windows XP systems.
    if (static_cast<BOOLEAN>(::HeapFree(heap_, 0, mem)) != TRUE)
      return false;
    return true;
  }

  if (!BlockChecksumIsValid(block_info)) {
    // The free stack hasn't yet been set, but may have been filled with junk.
    // Reset it.
    block_info.header->free_stack = NULL;

    // Report the error.
    ReportHeapError(mem, CORRUPT_BLOCK);

    // Try to clean up the block anyways.
    if (!FreeCorruptBlock(mem, NULL))
      return false;
    return true;
  }

  // Capture the current stack.
  StackCapture stack;
  stack.InitFromStack();

  // Mark the block as quarantined.
  if (!MarkBlockAsQuarantined(block_info.header, stack)) {
    ReportHeapError(mem, DOUBLE_FREE);
    return false;
  }

  QuarantineBlock(block_info);

  return true;
}

void HeapProxy::MarkBlockAsQuarantined(void* asan_pointer,
                                       const StackCapture& stack) {
  DCHECK_NE(reinterpret_cast<void*>(NULL), asan_pointer);
  BlockInfo block_info = {};
  Shadow::BlockInfoFromShadow(asan_pointer, &block_info);
  BlockHeader* block_header = block_info.header;

  MarkBlockAsQuarantined(block_header, stack);
}

bool HeapProxy::MarkBlockAsQuarantined(BlockHeader* block_header,
                                       const StackCapture& stack) {
  if (block_header->state != ALLOCATED_BLOCK) {
    // We're not supposed to see another kind of block here, the FREED_BLOCK
    // state is only applied to block after invalidating their magic number and
    // freed them.
    DCHECK(block_header->state == QUARANTINED_BLOCK);
    return false;
  }

  BlockInfo block_info = {};
  Shadow::BlockInfoFromShadow(block_header, &block_info);

  block_header->free_stack = stack_cache_->SaveStackTrace(stack);
  block_info.trailer->free_ticks = ::GetTickCount();
  block_info.trailer->free_tid = ::GetCurrentThreadId();

  block_header->state = QUARANTINED_BLOCK;

  // Poison the released alloc (marked as freed) and quarantine the block.
  // Note that the original data is left intact. This may make it easier
  // to debug a crash report/dump on access to a quarantined block.
  Shadow::MarkAsFreed(block_info.body, block_info.body_size);

  // TODO(chrisha): Poison the memory by XORing it?

  BlockSetChecksum(block_info);

  return true;
}

size_t HeapProxy::Size(DWORD flags, const void* mem) {
  DCHECK(heap_ != NULL);
  BlockHeader* block = BlockGetHeaderFromBody(mem);
  if (block == NULL)
    return ::HeapSize(heap_, flags, mem);
  // TODO(chrisha): Handle invalid allocation addresses.
  return block->body_size;
}

bool HeapProxy::Validate(DWORD flags, const void* mem) {
  DCHECK(heap_ != NULL);
  const void* address = BlockGetHeaderFromBody(mem);
  if (address == NULL)
    address = mem;
  // TODO(chrisha): Handle invalid allocation addresses.
  return ::HeapValidate(heap_, flags, address) == TRUE;
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
  if (info_class == ::HeapEnableTerminationOnCorruption)
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
    quarantine_.set_max_quarantine_size(quarantine_max_size);
  }

  // Trim the quarantine to the new maximum size if it's not zero, empty it
  // otherwise.
  if (quarantine_max_size != 0) {
    TrimQuarantine();
  } else {
    AsanShardedQuarantine::ObjectVector objects_vec;
    quarantine_.Empty(&objects_vec);
    AsanShardedQuarantine::ObjectVector::iterator iter = objects_vec.begin();
    for (; iter != objects_vec.end(); ++iter)
      CHECK(FreeQuarantinedBlock(*iter));
  }
}

void HeapProxy::SetQuarantineMaxBlockSize(size_t quarantine_max_block_size) {
  base::AutoLock lock(lock_);
  quarantine_.set_max_object_size(quarantine_max_block_size);

  // TODO(chrisha): Clean up existing blocks that exceed that size? This will
  //     require an entirely new TrimQuarantine function. Since this is never
  //     changed at runtime except in our unittests, this is not clearly
  //     useful.
}

bool HeapProxy::TrimQuarantine() {
  size_t size_of_block_just_freed = 0;
  bool success = true;
  BlockHeader* free_block = NULL;

  while (quarantine_.Pop(&free_block))
    success = success && FreeQuarantinedBlock(free_block);

  return success;
}

bool HeapProxy::FreeQuarantinedBlock(BlockHeader* block) {
  DCHECK_NE(reinterpret_cast<BlockHeader*>(NULL), block);
  bool success = true;

  // Check if the block has been stomped while it's in the quarantine. If it
  // has we take great pains to delete it carefully, and also report an error.
  // Otherwise, we trust the data in the header and take the fast path.
  size_t alloc_size = 0;
  BlockInfo block_info = {};
  Shadow::BlockInfoFromShadow(block, &block_info);
  if (!BlockChecksumIsValid(block_info)) {
    ReportHeapError(block, CORRUPT_BLOCK);
    if (!FreeCorruptBlock(block, &alloc_size))
      success = false;
  } else {
    alloc_size = block_info.block_size;
    if (!CleanUpAndFreeAsanBlock(block, alloc_size))
      success = false;
  }
  return success;
}

void HeapProxy::DestroyAsanBlock(void* asan_pointer) {
  DCHECK_NE(reinterpret_cast<void*>(NULL), asan_pointer);
  ReleaseAsanBlock(reinterpret_cast<BlockHeader*>(asan_pointer));
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

  block_header->state = FREED_BLOCK;
}

bool HeapProxy::FreeCorruptBlock(BlockHeader* header, size_t* alloc_size) {
  DCHECK_NE(reinterpret_cast<BlockHeader*>(NULL), header);

  // Set the invalid stack captures to NULL.
  if (!stack_cache_->StackCapturePointerIsValid(header->alloc_stack))
    header->alloc_stack = NULL;
  if (!stack_cache_->StackCapturePointerIsValid(header->free_stack))
    header->free_stack = NULL;

  // Calculate the allocation size via the shadow as the header might be
  // corrupt.
  size_t size = Shadow::GetAllocSize(reinterpret_cast<uint8*>(header));
  if (alloc_size != NULL)
    *alloc_size = size;
  if (!CleanUpAndFreeAsanBlock(header, size))
    return false;
  return true;
}

bool HeapProxy::FreeCorruptBlock(void* user_pointer, size_t* alloc_size) {
  DCHECK_NE(reinterpret_cast<void*>(NULL), user_pointer);

  // We can't use BlockGetHeaderFromBody because the magic number of the
  // header might be invalid.
  BlockHeader* header = reinterpret_cast<BlockHeader*>(user_pointer) - 1;
  if (!FreeCorruptBlock(header, alloc_size))
    return false;
  return true;
}

bool HeapProxy::CleanUpAndFreeAsanBlock(BlockHeader* block_header,
                                        size_t alloc_size) {
  ReleaseAsanBlock(block_header);
  Shadow::Unpoison(block_header, alloc_size);

  // TODO(chrisha): Fill the block with garbage?

  // According to the MSDN documentation about HeapFree the return value needs
  // to be cast to BOOLEAN in order to support Windows XP:
  //     Prior to Windows Vista, HeapFree has a bug: only the low byte of the
  //     return value is correctly indicative of the result.  This is because
  //     the implementation returns type BOOLEAN (BYTE) despite the prototype
  //     declaring it as returning BOOL (int).
  //
  //     If you care about the return value of HeapFree, and you need to support
  //     XP and 2003, cast the return value to BOOLEAN before checking it.
  if (static_cast<BOOLEAN>(::HeapFree(heap_, 0, block_header)) != TRUE) {
    ReportHeapError(block_header, CORRUPT_HEAP);
    return false;
  }

  return true;
}

void HeapProxy::ReportHeapError(void* address, BadAccessKind kind) {
  DCHECK_NE(reinterpret_cast<void*>(NULL), address);

  // Collect information about the error.
  AsanErrorInfo error_info = {};
  ::RtlCaptureContext(&error_info.context);
  error_info.access_mode = agent::asan::ASAN_UNKNOWN_ACCESS;
  error_info.location = address;
  error_info.error_type = kind;
  ErrorInfoGetBadAccessInformation(stack_cache_, &error_info);
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

  const BlockHeader* block_header =
      reinterpret_cast<const BlockHeader*>(src_asan_pointer);
  DCHECK_NE(reinterpret_cast<void*>(NULL), block_header);

  DCHECK_NE(reinterpret_cast<StackCapture*>(NULL), block_header->alloc_stack);
  const_cast<StackCapture*>(block_header->alloc_stack)->AddRef();
  if (block_header->free_stack != NULL)
    const_cast<StackCapture*>(block_header->free_stack)->AddRef();

  BlockInfo block_info = {};
  Shadow::BlockInfoFromShadow(block_header, &block_info);

  memcpy(dst_asan_pointer, src_asan_pointer, block_info.block_size);

  Shadow::CloneShadowRange(src_asan_pointer, dst_asan_pointer,
      block_info.block_size);
}

void HeapProxy::QuarantineBlock(const BlockInfo& block) {
  if (!quarantine_.Push(block.header)) {
    // Don't worry if CleanUpAndFreeAsanBlock fails as it will report a heap
    // error in this case.
    CleanUpAndFreeAsanBlock(block.header, block.block_size);
    return;
  }
  TrimQuarantine();
}

size_t HeapProxy::GetAllocSize(size_t bytes, size_t alignment) {
  BlockLayout layout = {};
  BlockPlanLayout(alignment,
                  alignment,
                  bytes,
                  alignment,
                  trailer_padding_size_ + sizeof(BlockTrailer),
                  &layout);
  return layout.block_size;
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

HeapLocker::HeapLocker(HeapProxy* const heap) : heap_(heap) {
  DCHECK(heap != NULL);
  if (!heap->Lock()) {
    LOG(ERROR) << "Unable to lock the heap.";
  }
}

HeapLocker::~HeapLocker() {
  DCHECK(heap_ != NULL);
  if (!heap_->Unlock()) {
    LOG(ERROR) << "Unable to unlock the heap.";
  }
}

}  // namespace asan
}  // namespace agent
