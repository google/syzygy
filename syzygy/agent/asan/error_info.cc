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

#include "syzygy/agent/asan/error_info.h"

#include "base/strings/string_util.h"
#include "syzygy/agent/asan/block_utils.h"
#include "syzygy/agent/asan/shadow.h"
#include "syzygy/agent/asan/stack_capture_cache.h"

namespace agent {
namespace asan {

namespace {

// Returns the time since the block @p header was freed (in milliseconds).
// @param header The block for which we want the time since free.
// @returns the time since the block was freed.
uint32 GetTimeSinceFree(const BlockHeader* header) {
  DCHECK(header != NULL);

  if (header->state == ALLOCATED_BLOCK)
    return 0;

  BlockInfo block_info = {};
  Shadow::BlockInfoFromShadow(header, &block_info);
  DCHECK(block_info.trailer != NULL);

  uint32 time_since_free = ::GetTickCount() - block_info.trailer->free_ticks;

  return time_since_free;
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
  ::memcpy(dst,
           stack_capture->frames(),
           stack_capture->num_frames() * sizeof(void*));
  *dst_size = stack_capture->num_frames();
}

// Get the information about an address relative to a block.
// @param header The header of the block containing this address.
// @param bad_access_info Will receive the information about this address.
void GetAddressInformation(BlockHeader* header,
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
    case HEAP_BUFFER_OVERFLOW: {
      offset = static_cast<const uint8*>(bad_access_info->location)
          - block_info.body - block_info.body_size;
      offset_relativity = "beyond";
      break;
    }
    case HEAP_BUFFER_UNDERFLOW: {
      offset = block_info.body -
          static_cast<const uint8*>(bad_access_info->location);
      offset_relativity = "before";
      break;
    }
    case USE_AFTER_FREE: {
      offset = static_cast<const uint8*>(bad_access_info->location)
          - block_info.body;
      offset_relativity = "inside";
      break;
    }
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
      block_info.trailer_padding);

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

}  // namespace

const char kHeapUseAfterFree[] = "heap-use-after-free";
const char kHeapBufferUnderFlow[] = "heap-buffer-underflow";
const char kHeapBufferOverFlow[] = "heap-buffer-overflow";
const char kAttemptingDoubleFree[] = "attempting double-free";
const char kInvalidAddress[] = "invalid-address";
const char kWildAccess[] = "wild-access";
const char kHeapUnknownError[] = "heap-unknown-error";
const char kHeapCorruptBlock[] = "corrupt-block";
const char kCorruptHeap[] = "corrupt-heap";

const char* ErrorInfoAccessTypeToStr(BadAccessKind bad_access_kind) {
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

bool ErrorInfoGetBadAccessInformation(StackCaptureCache* stack_cache,
                                      AsanErrorInfo* bad_access_info) {
  DCHECK_NE(reinterpret_cast<StackCaptureCache*>(NULL), stack_cache);
  DCHECK_NE(reinterpret_cast<AsanErrorInfo*>(NULL), bad_access_info);
  BlockInfo block_info = {};
  if (!Shadow::BlockInfoFromShadow(bad_access_info->location, &block_info))
    return false;

  if (bad_access_info->error_type != DOUBLE_FREE &&
      bad_access_info->error_type != CORRUPT_BLOCK) {
    bad_access_info->error_type =
        ErrorInfoGetBadAccessKind(bad_access_info->location, block_info.header);
  }

  // Makes sure that we don't try to use an invalid stack capture pointer.
  if (bad_access_info->error_type == CORRUPT_BLOCK) {
    // Set the invalid stack captures to NULL.
    if (!stack_cache->StackCapturePointerIsValid(
        block_info.header->alloc_stack)) {
      block_info.header->alloc_stack = NULL;
    }
    if (!stack_cache->StackCapturePointerIsValid(
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
    bad_access_info->milliseconds_since_free =
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

BadAccessKind ErrorInfoGetBadAccessKind(const void* addr,
                                        const BlockHeader* header) {
  DCHECK_NE(reinterpret_cast<const void*>(NULL), addr);
  DCHECK_NE(reinterpret_cast<const BlockHeader*>(NULL), header);

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
    } else if (Shadow::GetShadowMarkerForAddress(addr) == kHeapFreedMarker) {
      // This is a use after free on a block managed by a nested heap.
      bad_access_kind = USE_AFTER_FREE;
    }
  }
  return bad_access_kind;
}

void ErrorInfoGetAsanBlockInfo(StackCaptureCache* stack_cache,
                               AsanBlockInfo* asan_block_info) {
  DCHECK_NE(reinterpret_cast<StackCaptureCache*>(NULL), stack_cache);
  DCHECK_NE(reinterpret_cast<AsanBlockInfo*>(NULL), asan_block_info);
  const BlockHeader* header =
      reinterpret_cast<const BlockHeader*>(asan_block_info->header);

  asan_block_info->alloc_stack_size = 0;
  asan_block_info->free_stack_size = 0;
  asan_block_info->corrupt = IsBlockCorrupt(
      reinterpret_cast<const uint8*>(asan_block_info->header), NULL);

  // Copy the alloc and free stack traces if they're valid.
  if (stack_cache->StackCapturePointerIsValid(header->alloc_stack)) {
    CopyStackCaptureToArray(header->alloc_stack,
                            asan_block_info->alloc_stack,
                            &asan_block_info->alloc_stack_size);
  }
  if (header->state != ALLOCATED_BLOCK &&
      stack_cache->StackCapturePointerIsValid(header->free_stack)) {
    CopyStackCaptureToArray(header->free_stack,
                            asan_block_info->free_stack,
                            &asan_block_info->free_stack_size);
  }

  // Only check the trailer if the block isn't marked as corrupt.
  if (!asan_block_info->corrupt) {
    BlockInfo block_info = {};
    Shadow::BlockInfoFromShadow(asan_block_info->header, &block_info);
    asan_block_info->alloc_tid = block_info.trailer->alloc_tid;
    asan_block_info->free_tid = block_info.trailer->free_tid;
  } else {
    asan_block_info->alloc_tid = 0;
    asan_block_info->free_tid = 0;
  }

  asan_block_info->state = header->state;
  asan_block_info->user_size = header->body_size;
}

}  // namespace asan
}  // namespace agent
