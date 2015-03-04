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
#include "syzygy/agent/asan/asan_runtime.h"
#include "syzygy/agent/asan/block_utils.h"
#include "syzygy/agent/asan/shadow.h"
#include "syzygy/agent/asan/stack_capture_cache.h"
#include "syzygy/crashdata/crashdata.h"

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
void CopyStackCaptureToArray(const common::StackCapture* stack_capture,
                             void* dst, uint8* dst_size) {
  DCHECK_NE(reinterpret_cast<common::StackCapture*>(NULL), stack_capture);
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

  // TODO(chrisha): Use results of the analysis to determine which fields are
  //     written here.
  // TODO(chrisha, sebmarchand): Remove duplicated code in this function
  //     and GetAsanBlockInfo. Wait until we have integration tests with the
  //     symbolization scripts as this will most certainly derail them.
  bad_access_info->block_info.heap_type = kUnknownHeapType;
  HeapManagerInterface::HeapId heap_id = block_info.trailer->heap_id;
  if (heap_id != 0) {
    AsanRuntime* runtime = AsanRuntime::runtime();
    DCHECK_NE(static_cast<AsanRuntime*>(nullptr), runtime);
    bad_access_info->block_info.heap_type = runtime->GetHeapType(heap_id);
  }

  bad_access_info->block_info.milliseconds_since_free =
        GetTimeSinceFree(block_info.header);

  DCHECK(block_info.header->alloc_stack != NULL);
  CopyStackCaptureToArray(block_info.header->alloc_stack,
                          bad_access_info->block_info.alloc_stack,
                          &bad_access_info->block_info.alloc_stack_size);
  bad_access_info->block_info.alloc_tid = block_info.trailer->alloc_tid;

  if (block_info.header->state != ALLOCATED_BLOCK) {
    const common::StackCapture* free_stack = block_info.header->free_stack;
    BlockTrailer* free_stack_trailer = block_info.trailer;
    // Use the free metadata of the containing block if there's one.
    // TODO(chrisha): This should report all of the nested stack information
    //     from innermost to outermost. For now, innermost is best.
    if (containing_block.block != NULL) {
      free_stack = containing_block.header->free_stack;
      free_stack_trailer = containing_block.trailer;
    }
    CopyStackCaptureToArray(block_info.header->free_stack,
                            bad_access_info->block_info.free_stack,
                            &bad_access_info->block_info.free_stack_size);
    bad_access_info->block_info.free_tid = free_stack_trailer->free_tid;
  }

  // Get the bad access description if we've been able to determine its kind.
  if (bad_access_info->error_type != UNKNOWN_BAD_ACCESS) {
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

void ErrorInfoGetAsanBlockInfo(const BlockInfo& block_info,
                               StackCaptureCache* stack_cache,
                               AsanBlockInfo* asan_block_info) {
  DCHECK_NE(reinterpret_cast<StackCaptureCache*>(NULL), stack_cache);
  DCHECK_NE(reinterpret_cast<AsanBlockInfo*>(NULL), asan_block_info);

  ::memset(asan_block_info, 0, sizeof(*asan_block_info));
  BlockAnalyze(block_info, &asan_block_info->analysis);

  asan_block_info->header = block_info.header;
  asan_block_info->user_size = block_info.header->body_size;
  asan_block_info->state = block_info.header->state;
  asan_block_info->alloc_tid = block_info.trailer->alloc_tid;
  asan_block_info->free_tid = block_info.trailer->free_tid;

// TODO(chrisha): Use detailed analysis results to do this more efficiently.
  asan_block_info->heap_type = kUnknownHeapType;
  HeapManagerInterface::HeapId heap_id = block_info.trailer->heap_id;
  if (heap_id != 0) {
    AsanRuntime* runtime = AsanRuntime::runtime();
    DCHECK_NE(static_cast<AsanRuntime*>(nullptr), runtime);
    asan_block_info->heap_type = runtime->GetHeapType(heap_id);
  }

  // Copy the alloc and free stack traces if they're valid.
  // TODO(chrisha): Use detailed analysis results that have been gathered
  //                once, rather than recalculating this.
  if (stack_cache->StackCapturePointerIsValid(
          block_info.header->alloc_stack)) {
    CopyStackCaptureToArray(block_info.header->alloc_stack,
                            asan_block_info->alloc_stack,
                            &asan_block_info->alloc_stack_size);
  }
  if (block_info.header->state != ALLOCATED_BLOCK &&
      stack_cache->StackCapturePointerIsValid(
          block_info.header->free_stack)) {
    CopyStackCaptureToArray(block_info.header->free_stack,
                            asan_block_info->free_stack,
                            &asan_block_info->free_stack_size);
  }
}

namespace {

// Converts an access mode to a string.
void AccessModeToString(AccessMode access_mode, std::string* str) {
  DCHECK_NE(static_cast<std::string*>(nullptr), str);
  switch (access_mode) {
    case ASAN_READ_ACCESS: *str = "read"; break;
    case ASAN_WRITE_ACCESS: *str = "write"; break;
    default: *str = "(unknown)"; break;
  }
}

// Converts a block state to a string.
void BlockStateToString(BlockState block_state, std::string* str) {
  DCHECK_NE(static_cast<std::string*>(nullptr), str);
  switch (block_state) {
    case ALLOCATED_BLOCK: *str = "allocated"; break;
    case QUARANTINED_BLOCK: *str = "quarantined"; break;
    case FREED_BLOCK: *str = "freed"; break;
    default: *str = "(unknown)"; break;
  }
}

uint64 CastAddress(const void* address) {
  return static_cast<uint64>(reinterpret_cast<uint32>(address));
}

void PopulateStackTrace(const void* const* frames,
                        size_t frame_count,
                        crashdata::StackTrace* stack_trace) {
  DCHECK_NE(static_cast<void*>(nullptr), frames);
  DCHECK_LT(0u, frame_count);
  DCHECK_NE(static_cast<crashdata::StackTrace*>(nullptr), stack_trace);
  for (size_t i = 0; i < frame_count; ++i)
    stack_trace->add_frames(CastAddress(frames[i]));
}

void DataStateToString(DataState data_state, std::string* str) {
  DCHECK_NE(static_cast<std::string*>(nullptr), str);
  switch (data_state) {
    default:
    case kDataStateUnknown: *str = "(unknown)"; break;
    case kDataIsClean: *str = "clean"; break;
    case kDataIsCorrupt: *str = "corrupt"; break;
  }
}

void PopulateBlockAnalysisResult(const BlockAnalysisResult& analysis,
                                 crashdata::Dictionary* dict) {
  DCHECK_NE(static_cast<crashdata::Dictionary*>(nullptr), dict);
  DataStateToString(
      analysis.block_state,
      crashdata::LeafGetString(crashdata::DictAddLeaf("block", dict)));
  DataStateToString(
      analysis.header_state,
      crashdata::LeafGetString(crashdata::DictAddLeaf("header", dict)));
  DataStateToString(
      analysis.body_state,
      crashdata::LeafGetString(crashdata::DictAddLeaf("body", dict)));
  DataStateToString(
      analysis.trailer_state,
      crashdata::LeafGetString(crashdata::DictAddLeaf("trailer", dict)));
}

}  // namespace

void PopulateBlockInfo(const AsanBlockInfo& block_info,
                       crashdata::Value* value) {
  DCHECK_NE(static_cast<crashdata::Value*>(nullptr), value);

  crashdata::Dictionary* dict = ValueGetDict(value);
  DCHECK_NE(static_cast<crashdata::Dictionary*>(nullptr), dict);

  // Set block properties.
  crashdata::LeafGetAddress(crashdata::DictAddLeaf("header", dict))
      ->set_address(CastAddress(block_info.header));
  crashdata::LeafSetUInt(block_info.user_size,
                         crashdata::DictAddLeaf("user-size", dict));
  BlockStateToString(
      static_cast<BlockState>(block_info.state),
      crashdata::LeafGetString(crashdata::DictAddLeaf("state", dict)));
  crashdata::LeafGetString(crashdata::DictAddLeaf("heap-type", dict))
      ->assign(kHeapTypes[block_info.heap_type]);

  // Set the block analysis.
  PopulateBlockAnalysisResult(
      block_info.analysis,
      crashdata::ValueGetDict(crashdata::DictAddValue("analysis", dict)));

  // Set the allocation information.
  crashdata::LeafSetUInt(block_info.alloc_tid,
                         crashdata::DictAddLeaf("alloc-thread-id", dict));
  PopulateStackTrace(block_info.alloc_stack,
                     block_info.alloc_stack_size,
                     crashdata::LeafGetStackTrace(
                         crashdata::DictAddLeaf("alloc-stack", dict)));

  // Set the free information if available.
  if (block_info.free_stack_size != 0) {
    crashdata::LeafSetUInt(block_info.free_tid,
                           crashdata::DictAddLeaf("free-thread-id", dict));
    PopulateStackTrace(block_info.free_stack,
                       block_info.free_stack_size,
                       crashdata::LeafGetStackTrace(
                           crashdata::DictAddLeaf("free-stack", dict)));
    crashdata::LeafSetUInt(
        block_info.milliseconds_since_free,
        crashdata::DictAddLeaf("milliseconds-since-free", dict));
  }
}

void PopulateCorruptBlockRange(const AsanCorruptBlockRange& range,
                               crashdata::Value* value) {
  DCHECK_NE(static_cast<crashdata::Value*>(nullptr), value);

  crashdata::Dictionary* dict = ValueGetDict(value);
  DCHECK_NE(static_cast<crashdata::Dictionary*>(nullptr), dict);

  crashdata::LeafGetAddress(crashdata::DictAddLeaf("address", dict))
      ->set_address(CastAddress(range.address));
  crashdata::LeafSetUInt(range.length, crashdata::DictAddLeaf("length", dict));
  crashdata::LeafSetUInt(range.block_count,
                         crashdata::DictAddLeaf("block-count", dict));

  // Add the blocks.
  if (range.block_info_count > 0) {
    crashdata::List* list = crashdata::ValueGetList(
        crashdata::DictAddValue("blocks", dict));
    for (size_t i = 0; i < range.block_info_count; ++i)
      PopulateBlockInfo(range.block_info[i], list->add_values());
  }
}

void PopulateErrorInfo(const AsanErrorInfo& error_info,
                       crashdata::Value* value) {
  DCHECK_NE(static_cast<crashdata::Value*>(nullptr), value);

  // Create a single outermost dictionary.
  crashdata::Dictionary* dict = ValueGetDict(value);
  DCHECK_NE(static_cast<crashdata::Dictionary*>(nullptr), dict);

  crashdata::LeafGetAddress(crashdata::DictAddLeaf("location", dict))
      ->set_address(CastAddress(error_info.location));
  crashdata::LeafSetUInt(error_info.crash_stack_id,
                         crashdata::DictAddLeaf("crash-stack-id", dict));
  PopulateBlockInfo(error_info.block_info,
                    crashdata::DictAddValue("block-info", dict));
  crashdata::LeafGetString(crashdata::DictAddLeaf("error-type", dict))
      ->assign(ErrorInfoAccessTypeToStr(error_info.error_type));
  AccessModeToString(
      error_info.access_mode,
      crashdata::LeafGetString(crashdata::DictAddLeaf("access-mode", dict)));
  crashdata::LeafSetUInt(error_info.access_size,
                         crashdata::DictAddLeaf("access-size", dict));
  crashdata::LeafGetString(crashdata::DictAddLeaf("shadow-info", dict))
      ->assign(error_info.shadow_info);
  crashdata::LeafGetString(crashdata::DictAddLeaf("shadow-memory", dict))
      ->assign(error_info.shadow_memory);
  crashdata::LeafSetUInt(error_info.heap_is_corrupt,
                         crashdata::DictAddLeaf("heap-is-corrupt", dict));
  crashdata::LeafSetUInt(error_info.corrupt_range_count,
                         crashdata::DictAddLeaf("corrupt-range-count", dict));
  crashdata::LeafSetUInt(error_info.corrupt_block_count,
                         crashdata::DictAddLeaf("corrupt-block-count", dict));
  if (error_info.corrupt_ranges_reported > 0) {
    crashdata::List* list = crashdata::ValueGetList(
        crashdata::DictAddValue("corrupt-ranges", dict));
    for (size_t i = 0; i < error_info.corrupt_ranges_reported; ++i) {
      PopulateCorruptBlockRange(error_info.corrupt_ranges[i],
                                list->add_values());
    }
  }
}

}  // namespace asan
}  // namespace agent
