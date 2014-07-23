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
#include "base/string_util.h"
#include "base/stringprintf.h"
#include "base/time.h"
#include "base/debug/alias.h"
#include "base/debug/stack_trace.h"
#include "base/strings/sys_string_conversions.h"
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

// Copy a stack capture object into an array.
// @param stack_capture The stack capture that we want to copy.
// @param dst Will receive the stack frames.
// @param dst_size Will receive the number of frames that has been copied.
void CopyStackCaptureToArray(const StackCapture* stack_capture,
                             void* dst, uint8* dst_size) {
  DCHECK_NE(reinterpret_cast<const StackCapture*>(NULL), stack_capture);
  DCHECK_NE(reinterpret_cast<void*>(NULL), dst);
  DCHECK_NE(reinterpret_cast<uint8*>(NULL), dst_size);
  memcpy(dst,
         stack_capture->frames(),
         stack_capture->num_frames() * sizeof(void*));
  *dst_size = stack_capture->num_frames();
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
const char* HeapProxy::kHeapUseAfterFree = "heap-use-after-free";
const char* HeapProxy::kHeapBufferUnderFlow = "heap-buffer-underflow";
const char* HeapProxy::kHeapBufferOverFlow = "heap-buffer-overflow";
const char* HeapProxy::kAttemptingDoubleFree = "attempting double-free";
const char* HeapProxy::kInvalidAddress = "invalid-address";
const char* HeapProxy::kWildAccess = "wild-access";
const char* HeapProxy::kHeapUnknownError = "heap-unknown-error";
const char* HeapProxy::kHeapCorruptBlock = "corrupt-block";
const char* HeapProxy::kCorruptHeap = "corrupt-heap";

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

HeapProxy::BadAccessKind HeapProxy::GetBadAccessKind(
    const void* addr, const BlockHeader* header) {
  DCHECK(addr != NULL);
  DCHECK(header != NULL);

  BadAccessKind bad_access_kind = UNKNOWN_BAD_ACCESS;

  if (header->state == QUARANTINED_BLOCK) {
    bad_access_kind = USE_AFTER_FREE;
  } else {
    BlockInfo block_info = {};
    Shadow::BlockInfoFromShadow(header, &block_info);
    if (addr < block_info.body) {
      bad_access_kind = HEAP_BUFFER_UNDERFLOW;
    } else if (addr >= (block_info.body + block_info.body_size)) {
      bad_access_kind = HEAP_BUFFER_OVERFLOW;
    } else if (Shadow::GetShadowMarkerForAddress(addr) ==
        Shadow::kHeapFreedByte) {
      // This is a use after free on a block managed by a nested heap.
      bad_access_kind = USE_AFTER_FREE;
    }
  }
  return bad_access_kind;
}

bool HeapProxy::GetBadAccessInformation(AsanErrorInfo* bad_access_info) {
  DCHECK(bad_access_info != NULL);
  BlockInfo block_info = {};
  if (!Shadow::BlockInfoFromShadow(bad_access_info->location, &block_info))
    return false;

  if (bad_access_info->error_type != DOUBLE_FREE &&
      bad_access_info->error_type != CORRUPT_BLOCK) {
    bad_access_info->error_type = GetBadAccessKind(bad_access_info->location,
                                                   block_info.header);
  }

  // Makes sure that we don't try to use an invalid stack capture pointer.
  if (bad_access_info->error_type == CORRUPT_BLOCK) {
    // Set the invalid stack captures to NULL.
    if (!stack_cache_->StackCapturePointerIsValid(
        block_info.header->alloc_stack)) {
      block_info.header->alloc_stack = NULL;
    }
    if (!stack_cache_->StackCapturePointerIsValid(
        block_info.header->free_stack)) {
      block_info.header->free_stack = NULL;
    }
  }

  // Checks if there's a containing block in the case of a use after free on a
  // block owned by a nested heap.
  BlockInfo containing_block = {};
  if (bad_access_info->error_type == USE_AFTER_FREE &&
      block_info.header->state != QUARANTINED_BLOCK) {
     Shadow::ParentBlockInfoFromShadow(block_info, &containing_block);
  }

  // Get the bad access description if we've been able to determine its kind.
  if (bad_access_info->error_type != UNKNOWN_BAD_ACCESS) {
    bad_access_info->microseconds_since_free =
        GetTimeSinceFree(block_info.header);

    DCHECK(block_info.header->alloc_stack != NULL);
    CopyStackCaptureToArray(block_info.header->alloc_stack,
                            bad_access_info->alloc_stack,
                            &bad_access_info->alloc_stack_size);
    bad_access_info->alloc_tid = block_info.trailer->alloc_tid;

    if (block_info.header->state != ALLOCATED_BLOCK) {
      const StackCapture* free_stack = block_info.header->free_stack;
      BlockTrailer* free_stack_trailer = block_info.trailer;
      // Use the free metadata of the containing block if there's one.
      // TODO(chrisha): This should report all of the nested stack information
      //     from innermost to outermost. For now, innermost is best.
      if (containing_block.block != NULL) {
        free_stack = containing_block.header->free_stack;
        free_stack_trailer = containing_block.trailer;
      }
      CopyStackCaptureToArray(block_info.header->free_stack,
                              bad_access_info->free_stack,
                              &bad_access_info->free_stack_size);
      bad_access_info->free_tid = free_stack_trailer->free_tid;
    }
    GetAddressInformation(block_info.header, bad_access_info);
    return true;
  }

  return false;
}

void HeapProxy::GetAddressInformation(const BlockHeader* header,
                                      AsanErrorInfo* bad_access_info) {
  DCHECK(header != NULL);
  DCHECK(bad_access_info != NULL);

  DCHECK(header != NULL);
  DCHECK(bad_access_info != NULL);
  DCHECK(bad_access_info->location != NULL);

  BlockInfo block_info = {};
  Shadow::BlockInfoFromShadow(header, &block_info);

  int offset = 0;
  char* offset_relativity = "";
  switch (bad_access_info->error_type) {
    case HEAP_BUFFER_OVERFLOW:
      offset = static_cast<const uint8*>(bad_access_info->location)
          - block_info.body - block_info.body_size;
      offset_relativity = "beyond";
      break;
    case HEAP_BUFFER_UNDERFLOW:
      offset = block_info.body -
          static_cast<const uint8*>(bad_access_info->location);
      offset_relativity = "before";
      break;
    case USE_AFTER_FREE:
      offset = static_cast<const uint8*>(bad_access_info->location)
          - block_info.body;
      offset_relativity = "inside";
      break;
    case WILD_ACCESS:
    case DOUBLE_FREE:
    case UNKNOWN_BAD_ACCESS:
    case CORRUPT_BLOCK:
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
      block_info.body_size,
      block_info.body,
      block_info.body + block_info.body_size);

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
    case CORRUPT_BLOCK:
      return kHeapCorruptBlock;
    case CORRUPT_HEAP:
      return kCorruptHeap;
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

uint32 HeapProxy::GetTimeSinceFree(const BlockHeader* header) {
  DCHECK(header != NULL);

  if (header->state == ALLOCATED_BLOCK)
    return 0;

  BlockInfo block_info = {};
  Shadow::BlockInfoFromShadow(header, &block_info);
  DCHECK(block_info.trailer != NULL);

  uint32 time_since_free = ::GetTickCount() - block_info.trailer->free_ticks;

  return time_since_free;
}

bool HeapProxy::IsBlockCorrupt(const uint8* block_header) {
  BlockInfo block_info = {};
  if (!Shadow::BlockInfoFromShadow(block_header, &block_info) ||
      block_info.header->magic != kBlockHeaderMagic ||
      !BlockChecksumIsValid(block_info)) {
    return true;
  }
  return false;
}

void HeapProxy::GetBlockInfo(AsanBlockInfo* asan_block_info) {
  DCHECK_NE(reinterpret_cast<AsanBlockInfo*>(NULL), asan_block_info);
  const BlockHeader* header =
      reinterpret_cast<const BlockHeader*>(asan_block_info->header);

  asan_block_info->alloc_stack_size = 0;
  asan_block_info->free_stack_size = 0;
  asan_block_info->corrupt = IsBlockCorrupt(
      reinterpret_cast<const uint8*>(asan_block_info->header));

  // Copy the alloc and free stack traces if they're valid.
  if (stack_cache_->StackCapturePointerIsValid(header->alloc_stack)) {
    CopyStackCaptureToArray(header->alloc_stack,
                            asan_block_info->alloc_stack,
                            &asan_block_info->alloc_stack_size);
  }
  if (header->state != ALLOCATED_BLOCK &&
      stack_cache_->StackCapturePointerIsValid(header->free_stack)) {
    CopyStackCaptureToArray(header->free_stack,
                            asan_block_info->free_stack,
                            &asan_block_info->free_stack_size);
  }

  // Only check the trailer if the block isn't marked as corrupt.
  DCHECK_EQ(0U, asan_block_info->alloc_tid);
  DCHECK_EQ(0U, asan_block_info->free_tid);
  if (!asan_block_info->corrupt) {
    BlockInfo block_info = {};
    Shadow::BlockInfoFromShadow(asan_block_info->header, &block_info);
    asan_block_info->alloc_tid = block_info.trailer->alloc_tid;
    asan_block_info->free_tid = block_info.trailer->free_tid;
  }

  asan_block_info->state = header->state;
  asan_block_info->user_size = header->body_size;
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
