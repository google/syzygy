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

#include <limits>
#include <string>

#include "base/strings/string_util.h"
#include "syzygy/agent/asan/block_utils.h"
#include "syzygy/agent/asan/runtime.h"
#include "syzygy/agent/asan/shadow.h"
#include "syzygy/agent/asan/stack_capture_cache.h"
#include "syzygy/crashdata/crashdata.h"

namespace agent {
namespace asan {

namespace {

// Copy a stack capture object into an array.
// @param stack_capture The stack capture that we want to copy.
// @param dst Will receive the stack frames.
// @param dst_size Will receive the number of frames that has been copied.
void CopyStackCaptureToArray(const common::StackCapture* stack_capture,
                             void* dst,
                             uint8_t* dst_size) {
  DCHECK_NE(static_cast<common::StackCapture*>(nullptr), stack_capture);
  DCHECK_NE(static_cast<void*>(nullptr), dst);
  DCHECK_NE(static_cast<uint8_t*>(nullptr), dst_size);
  ::memcpy(dst,
           stack_capture->frames(),
           stack_capture->num_frames() * sizeof(void*));
  *dst_size = static_cast<uint8_t>(stack_capture->num_frames());
}

// Get the information about an address relative to a block.
// @param shadow The shadow memory to query.
// @param header The header of the block containing this address.
// @param bad_access_info Will receive the information about this address.
void GetAddressInformation(const Shadow* shadow,
                           BlockHeader* header,
                           AsanErrorInfo* bad_access_info) {
  DCHECK_NE(static_cast<Shadow*>(nullptr), shadow);
  DCHECK_NE(static_cast<BlockHeader*>(nullptr), header);
  DCHECK_NE(static_cast<AsanErrorInfo*>(nullptr), bad_access_info);
  DCHECK_NE(static_cast<void*>(nullptr), bad_access_info->location);

  BlockInfo block_info = {};
  shadow->BlockInfoFromShadow(header, &block_info);
  SSIZE_T offset = 0;
  char* offset_relativity = "";
  switch (bad_access_info->error_type) {
    case HEAP_BUFFER_OVERFLOW: {
      offset = static_cast<const uint8_t*>(bad_access_info->location) -
               block_info.RawBody() - block_info.body_size;
      offset_relativity = "beyond";
      break;
    }
    case HEAP_BUFFER_UNDERFLOW: {
      offset = block_info.RawBody() -
               static_cast<const uint8_t*>(bad_access_info->location);
      offset_relativity = "before";
      break;
    }
    case USE_AFTER_FREE: {
      offset = static_cast<const uint8_t*>(bad_access_info->location) -
               block_info.RawBody();
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
  shadow->AppendShadowArrayText(
      bad_access_info->location, &shadow_memory);
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
      return nullptr;
  }
}

namespace {

// Converts an access kind string to its corresponding enum value.
BadAccessKind ErrorInfoAccessTypeStrToEnum(const std::string& access_kind) {
  if (::strcmp(kHeapUseAfterFree, access_kind.c_str())) {
    return USE_AFTER_FREE;
  } else if (::strcmp(kHeapBufferUnderFlow, access_kind.c_str()) == 0) {
    return HEAP_BUFFER_UNDERFLOW;
  } else if (::strcmp(kHeapBufferOverFlow, access_kind.c_str()) == 0) {
    return HEAP_BUFFER_OVERFLOW;
  } else if (::strcmp(kWildAccess, access_kind.c_str()) == 0) {
    return WILD_ACCESS;
  } else if (::strcmp(kInvalidAddress, access_kind.c_str()) == 0) {
    return INVALID_ADDRESS;
  } else if (::strcmp(kAttemptingDoubleFree, access_kind.c_str()) == 0) {
    return DOUBLE_FREE;
  } else if (::strcmp(kHeapUnknownError, access_kind.c_str()) == 0) {
    return UNKNOWN_BAD_ACCESS;
  } else if (::strcmp(kHeapCorruptBlock, access_kind.c_str()) == 0) {
    return CORRUPT_BLOCK;
  } else if (::strcmp(kCorruptHeap, access_kind.c_str()) == 0) {
    return CORRUPT_HEAP;
  } else {
    NOTREACHED() << "Unexpected bad access kind.";
    return BAD_ACCESS_KIND_MAX;
  }
}

}  // namespace

bool ErrorInfoGetBadAccessInformation(const Shadow* shadow,
                                      StackCaptureCache* stack_cache,
                                      AsanErrorInfo* bad_access_info) {
  DCHECK_NE(static_cast<Shadow*>(nullptr), shadow);
  DCHECK_NE(static_cast<StackCaptureCache*>(nullptr), stack_cache);
  DCHECK_NE(static_cast<AsanErrorInfo*>(nullptr), bad_access_info);
  BlockInfo block_info = {};
  if (!shadow->BlockInfoFromShadow(
      bad_access_info->location, &block_info)) {
    return false;
  }

  // Fill out the information about the primary block.
  ErrorInfoGetAsanBlockInfo(shadow, block_info, stack_cache,
                            &bad_access_info->block_info);

  if (bad_access_info->error_type != DOUBLE_FREE &&
      bad_access_info->error_type != CORRUPT_BLOCK) {
    bad_access_info->error_type = ErrorInfoGetBadAccessKind(
        shadow, bad_access_info->location, block_info.header);
  }

  // Get the bad access description if we've been able to determine its kind.
  if (bad_access_info->error_type != UNKNOWN_BAD_ACCESS) {
    GetAddressInformation(shadow, block_info.header, bad_access_info);
    return true;
  }

  return false;
}

BadAccessKind ErrorInfoGetBadAccessKind(const Shadow* shadow,
                                        const void* addr,
                                        const BlockHeader* header) {
  DCHECK_NE(static_cast<Shadow*>(nullptr), shadow);
  DCHECK_NE(static_cast<const void*>(nullptr), addr);
  DCHECK_NE(static_cast<const BlockHeader*>(nullptr), header);

  switch (static_cast<BlockState>(header->state)) {
    case ALLOCATED_BLOCK: {
      BlockInfo block_info = {};
      shadow->BlockInfoFromShadow(header, &block_info);
      if (addr < block_info.body) {
        return HEAP_BUFFER_UNDERFLOW;
      } else if (addr >= (block_info.RawBody() + block_info.body_size)) {
        return HEAP_BUFFER_OVERFLOW;
      } else if (shadow->GetShadowMarkerForAddress(addr) ==
          kHeapFreedMarker) {
        // This is a use after free on a block managed by a nested heap.
        return USE_AFTER_FREE;
      }
      break;
    }

    case QUARANTINED_BLOCK:
    case QUARANTINED_FLOODED_BLOCK:
    case FREED_BLOCK: {
      return USE_AFTER_FREE;
      break;
    }
  }

  return UNKNOWN_BAD_ACCESS;
}

void ErrorInfoGetAsanBlockInfo(const Shadow* shadow,
                               const BlockInfo& block_info,
                               StackCaptureCache* stack_cache,
                               AsanBlockInfo* asan_block_info) {
  DCHECK_NE(static_cast<StackCaptureCache*>(nullptr), stack_cache);
  DCHECK_NE(static_cast<AsanBlockInfo*>(nullptr), asan_block_info);

  ::memset(asan_block_info, 0, sizeof(*asan_block_info));
  BlockState block_state = BlockDetermineMostLikelyState(shadow, block_info);
  BlockAnalyze(block_state, block_info, &asan_block_info->analysis);

  asan_block_info->header = block_info.header;
  asan_block_info->user_size = block_info.header->body_size;
  asan_block_info->state = block_info.header->state;
  asan_block_info->alloc_tid = block_info.trailer->alloc_tid;
  asan_block_info->free_tid = block_info.trailer->free_tid;

  if (block_info.header->state != ALLOCATED_BLOCK &&
      block_info.trailer->free_ticks != 0) {
    asan_block_info->milliseconds_since_free =
        ::GetTickCount() - block_info.trailer->free_ticks;
  }

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

void GetAsanErrorShadowMemory(const Shadow* shadow,
                              const void* error_location,
                              AsanErrorShadowMemory* shadow_memory) {
  DCHECK_NE(static_cast<AsanErrorShadowMemory*>(nullptr), shadow_memory);

  shadow_memory->index = reinterpret_cast<uintptr_t>(error_location);
  shadow_memory->index >>= kShadowRatioLog;
  shadow_memory->index = (shadow_memory->index / shadow->kShadowBytesPerLine) *
                         Shadow::kShadowBytesPerLine;

  uintptr_t index_min =
      shadow_memory->index -
      Shadow::kShadowContextLines * Shadow::kShadowBytesPerLine;
  if (index_min > shadow_memory->index)
    index_min = 0;
  uintptr_t index_max =
      shadow_memory->index +
      Shadow::kShadowContextLines * Shadow::kShadowBytesPerLine;
  if (index_max < shadow_memory->index)
    index_max = 0;

  shadow_memory->address =
      reinterpret_cast<uintptr_t>(shadow->shadow() + index_min);
  shadow_memory->length = index_max - index_min;
}

namespace {

const char kAllocatedBlock[] = "allocated";
const char kQuarantinedBlock[] = "quarantined";
const char kQuarantinedFloodedBlock[] = "quarantined (flooded)";
const char kFreedBlock[] = "freed";
const char kAccessModeRead[] = "read";
const char kAccessModeWrite[] = "write";
const char kAccessModeUnknown[] = "(unknown)";

// Converts an access mode to a string.
void AccessModeToString(AccessMode access_mode, std::string* str) {
  DCHECK_NE(static_cast<std::string*>(nullptr), str);
  switch (access_mode) {
    case ASAN_READ_ACCESS:
      *str = kAccessModeRead;
      break;
    case ASAN_WRITE_ACCESS:
      *str = kAccessModeWrite;
      break;
    default:
      *str = kAccessModeUnknown;
      break;
  }
}

// Converts an access mode string to its corresponding enum value.
AccessMode AccessModeStringToEnum(const std::string& access_mode) {
  if (::strcmp(kAccessModeRead, access_mode.c_str()) == 0) {
    return ASAN_READ_ACCESS;
  } else if (::strcmp(kAccessModeWrite, access_mode.c_str()) == 0) {
    return ASAN_WRITE_ACCESS;
  } else if (::strcmp(kAccessModeUnknown, access_mode.c_str()) == 0) {
    return ASAN_UNKNOWN_ACCESS;
  } else {
    NOTREACHED() << "Unexpected access mode.";
    return ASAN_ACCESS_MODE_MAX;
  }
}

// Converts a block state to a string.
void BlockStateToString(BlockState block_state, std::string* str) {
  DCHECK_NE(static_cast<std::string*>(nullptr), str);
  switch (block_state) {
    case ALLOCATED_BLOCK:
      *str = kAllocatedBlock;
      break;
    case QUARANTINED_BLOCK:
      *str = kQuarantinedBlock;
      break;
    case QUARANTINED_FLOODED_BLOCK:
      *str = kQuarantinedFloodedBlock;
      break;
    case FREED_BLOCK: *str = "freed"; break;
  }
}

// Converts a block state string to its corresponding enum value.
BlockState BlockStateStringToEnum(const std::string& block_state) {
  if (::strcmp(kAllocatedBlock, block_state.c_str()) == 0) {
    return ALLOCATED_BLOCK;
  } else if (::strcmp(kQuarantinedBlock, block_state.c_str()) == 0) {
    return QUARANTINED_BLOCK;
  } else if (::strcmp(kQuarantinedFloodedBlock, block_state.c_str()) == 0) {
    return QUARANTINED_FLOODED_BLOCK;
  } else if (::strcmp(kFreedBlock, block_state.c_str()) == 0) {
    return FREED_BLOCK;
  } else {
    NOTREACHED() << "Unexpected block state.";
    return BLOCK_STATE_MAX;
  }
}

// Converts a heap type string to its corresponding enum value.
HeapType HeapTypeStrToEnum(const std::string& heap_type) {
  for (size_t i = 0; i < kHeapTypeMax; ++i) {
    if (::strcmp(kHeapTypes[i], heap_type.c_str()) == 0) {
      return static_cast<HeapType>(i);
    }
  }
  NOTREACHED() << "Unexpected heap type.";
  return kHeapTypeMax;
}

uint64_t CastAddress(const void* address) {
  return static_cast<uint64_t>(reinterpret_cast<uintptr_t>(address));
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

void PopulateBlockInfo(const Shadow* shadow,
                       const AsanBlockInfo& block_info,
                       bool include_block_contents,
                       crashdata::Value* value,
                       MemoryRanges* memory_ranges) {
  DCHECK_NE(static_cast<Shadow*>(nullptr), shadow);
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
  if (block_info.alloc_stack_size != 0) {
    crashdata::LeafSetUInt(block_info.alloc_tid,
                           crashdata::DictAddLeaf("alloc-thread-id", dict));
    PopulateStackTrace(block_info.alloc_stack,
                       block_info.alloc_stack_size,
                       crashdata::LeafGetStackTrace(
                           crashdata::DictAddLeaf("alloc-stack", dict)));
  }

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

  if (include_block_contents) {
    // Get the full block information from the shadow memory.
    BlockInfo full_block_info = {};
    shadow->BlockInfoFromShadow(block_info.header, &full_block_info);

    // Copy the entire block contents.
    crashdata::Blob* blob = crashdata::LeafGetBlob(
        crashdata::DictAddLeaf("contents", dict));
    blob->mutable_address()->set_address(CastAddress(block_info.header));

    // Use memory range feature if available. Fallback on blob data.
    if (memory_ranges) {
      // protobuf accepts uint32 as size, so it must fit.
      DCHECK_LE(full_block_info.block_size,
                static_cast<size_t>(std::numeric_limits<uint32_t>::max()));
      blob->set_size(static_cast<uint32_t>(full_block_info.block_size));

      memory_ranges->push_back(std::pair<const char*, size_t>(
          static_cast<const char*>(block_info.header),
          full_block_info.block_size));
    } else {
      blob->mutable_data()->assign(
          reinterpret_cast<const char*>(block_info.header),
          full_block_info.block_size);
    }

    // Copy the associated shadow memory.
    size_t shadow_index =
        reinterpret_cast<size_t>(block_info.header) / kShadowRatio;
    size_t shadow_length = full_block_info.block_size / kShadowRatio;
    const char* shadow_data =
        reinterpret_cast<const char*>(shadow->shadow()) +
        shadow_index;
    blob = crashdata::LeafGetBlob(
        crashdata::DictAddLeaf("shadow", dict));
    blob->mutable_address()->set_address(CastAddress(shadow_data));

    // Use memory range feature if available. Fallback on blob data.
    if (memory_ranges) {
      // protobuf accepts uint32 as size, so it must fit.
      DCHECK_LE(shadow_length,
                static_cast<size_t>(std::numeric_limits<uint32_t>::max()));
      blob->set_size(static_cast<uint32_t>(shadow_length));

      memory_ranges->push_back(
          std::pair<const char*, size_t>(shadow_data, shadow_length));
    } else {
      blob->mutable_data()->assign(shadow_data, shadow_length);
    }
  }
}

void PopulateCorruptBlockRange(const Shadow* shadow,
                               const AsanCorruptBlockRange& range,
                               crashdata::Value* value,
                               MemoryRanges* memory_ranges) {
  DCHECK_NE(static_cast<Shadow*>(nullptr), shadow);
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
    crashdata::ValueList* list =
        crashdata::ValueGetValueList(crashdata::DictAddValue("blocks", dict));
    for (size_t i = 0; i < range.block_info_count; ++i) {
      if (range.block_info[i].header != nullptr)
        // Emit the block info but don't explicitly include the contents.
        PopulateBlockInfo(shadow, range.block_info[i], false,
                          list->add_values(), memory_ranges);
    }
  }
}

namespace {

void PopulateShadowMemoryBlob(const Shadow* shadow,
                              const AsanErrorInfo& error_info,
                              crashdata::Dictionary* dict,
                              MemoryRanges* memory_ranges) {
  DCHECK_NE(static_cast<Shadow*>(nullptr), shadow);
  DCHECK_NE(static_cast<crashdata::Dictionary*>(nullptr), dict);

  // The shadow-info string can be reconstructed from information already in
  // the crash (location, block-info, access-mode, access-size), so there's no
  // need to send it. This is emitted as a blob.
  AsanErrorShadowMemory shadow_memory = {};
  GetAsanErrorShadowMemory(shadow, error_info.location, &shadow_memory);

  crashdata::LeafSetUInt(shadow_memory.index,
                         crashdata::DictAddLeaf("shadow-memory-index", dict));
  crashdata::Blob* blob = crashdata::LeafGetBlob(
      crashdata::DictAddLeaf("shadow-memory", dict));
  blob->mutable_address()->set_address(shadow_memory.address);

  // Use memory range feature if available. Fallback on blob data.
  if (memory_ranges) {
    blob->set_size(shadow_memory.length);

    const char* data = reinterpret_cast<const char*>(shadow_memory.address);
    memory_ranges->push_back(
        std::pair<const char*, size_t>(data, shadow_memory.length));
  } else {
    blob->mutable_data()->assign(
        reinterpret_cast<const char*>(shadow_memory.address),
        shadow_memory.length);
  }
}

void PopulatePageBitsBlob(const Shadow* shadow,
                          const AsanErrorInfo& error_info,
                          crashdata::Dictionary* dict,
                          MemoryRanges* memory_ranges) {
  DCHECK_NE(static_cast<crashdata::Dictionary*>(nullptr), dict);

  // Emit information about page protections surround the address in question.
  static const size_t kPageBitsContext = 2;
  uintptr_t index = reinterpret_cast<uintptr_t>(error_info.location);
  index /= GetPageSize();  // 1 bit per page.
  index /= 8;  // 8 bits per byte.
  uintptr_t index_min = index - kPageBitsContext;
  if (index_min > index)
    index_min = 0;
  uintptr_t index_max = index + 1 + kPageBitsContext;
  if (index_max < index)
    index_max = 0;
  uintptr_t length = index_max - index_min;

  crashdata::LeafSetUInt(
      index, crashdata::DictAddLeaf("page-bits-index", dict));
  crashdata::Blob* blob =
      crashdata::LeafGetBlob(crashdata::DictAddLeaf("page-bits", dict));
  blob->mutable_address()->set_address(
      CastAddress(shadow->page_bits() + index_min));

  // Use memory range feature if available. Fallback on blob data.
  if (memory_ranges) {
    blob->set_size(length);

    const char* data =
        reinterpret_cast<const char*>(shadow->page_bits() + index_min);
    memory_ranges->push_back(std::pair<const char*, size_t>(data, length));
  } else {
    blob->mutable_data()->assign(
        reinterpret_cast<const char*>(shadow->page_bits() + index_min), length);
  }
}

void PopulateAsanParameters(const AsanErrorInfo& error_info,
                            crashdata::Dictionary* dict) {
  DCHECK_NE(static_cast<crashdata::Dictionary*>(nullptr), dict);

  // Any new parameter added to the parameters structure should also be added
  // here.
  static_assert(15 == ::common::kAsanParametersVersion,
                "Pointers in the params must be linked up here.");
  crashdata::Dictionary* param_dict = crashdata::DictAddDict("asan-parameters",
                                                             dict);
  DCHECK_NE(static_cast<crashdata::Dictionary*>(nullptr), param_dict);
  crashdata::LeafSetUInt(error_info.asan_parameters.quarantine_size,
                         crashdata::DictAddLeaf("quarantine-size", param_dict));
  crashdata::LeafSetUInt(error_info.asan_parameters.trailer_padding_size,
                         crashdata::DictAddLeaf("trailer-padding-size",
                                                param_dict));
  crashdata::LeafSetUInt(error_info.asan_parameters.quarantine_block_size,
                         crashdata::DictAddLeaf("quarantine-block-size",
                                                param_dict));
  crashdata::LeafSetUInt(error_info.asan_parameters.check_heap_on_failure,
                         crashdata::DictAddLeaf("check-heap-on-failure",
                                                param_dict));
  crashdata::LeafSetUInt(error_info.asan_parameters.enable_zebra_block_heap,
                         crashdata::DictAddLeaf("enable-zebra-block-heap",
                                                param_dict));
  crashdata::LeafSetUInt(error_info.asan_parameters.enable_large_block_heap,
                         crashdata::DictAddLeaf("enable-large-block-heap",
                                                param_dict));
  crashdata::LeafSetUInt(error_info.asan_parameters.enable_allocation_filter,
                         crashdata::DictAddLeaf("enable-allocation-filter",
                                                param_dict));
  crashdata::LeafSetReal(error_info.asan_parameters.allocation_guard_rate,
                         crashdata::DictAddLeaf("allocation-guard-rate",
                                                param_dict));
  crashdata::LeafSetUInt(error_info.asan_parameters.zebra_block_heap_size,
                         crashdata::DictAddLeaf("zebra-block-heap-size",
                                                param_dict));
  crashdata::LeafSetReal(
      error_info.asan_parameters.zebra_block_heap_quarantine_ratio,
      crashdata::DictAddLeaf("zebra-block-heap-quarantine-ratio", param_dict));
  crashdata::LeafSetUInt(error_info.asan_parameters.large_allocation_threshold,
                         crashdata::DictAddLeaf("large-allocation-threshold",
                                                param_dict));
  crashdata::LeafSetReal(
      error_info.asan_parameters.quarantine_flood_fill_rate,
      crashdata::DictAddLeaf("quarantine-flood-fill-rate", param_dict));
}

}  // namespace

// TODO(chrisha): Only emit information that makes sense for the given error
//                type. For example, wild-access errors have no associated
//                block information.
void PopulateErrorInfo(const Shadow* shadow,
                       const AsanErrorInfo& error_info,
                       crashdata::Value* value,
                       MemoryRanges* memory_ranges) {
  DCHECK_NE(static_cast<Shadow*>(nullptr), shadow);
  DCHECK_NE(static_cast<crashdata::Value*>(nullptr), value);

  // Create a single outermost dictionary.
  crashdata::Dictionary* dict = ValueGetDict(value);
  DCHECK_NE(static_cast<crashdata::Dictionary*>(nullptr), dict);

  crashdata::LeafGetAddress(crashdata::DictAddLeaf("location", dict))
      ->set_address(CastAddress(error_info.location));
  crashdata::LeafSetUInt(error_info.crash_stack_id,
                         crashdata::DictAddLeaf("crash-stack-id", dict));
  if (error_info.block_info.header != nullptr) {
    // Include the block contents only if the block isn't too large. This tries
    // to reflect the cap on crash server minidump sizes.
    // TODO(chrisha): This decision should be made higher up the stack, and not
    // here.
    bool include_block_info = error_info.block_info.user_size < 100 * 1024;
    PopulateBlockInfo(shadow, error_info.block_info, include_block_info,
                      crashdata::DictAddValue("block-info", dict),
                      memory_ranges);
  }
  crashdata::LeafGetString(crashdata::DictAddLeaf("error-type", dict))
      ->assign(ErrorInfoAccessTypeToStr(error_info.error_type));
  AccessModeToString(
      error_info.access_mode,
      crashdata::LeafGetString(crashdata::DictAddLeaf("access-mode", dict)));
  crashdata::LeafSetUInt(error_info.access_size,
                         crashdata::DictAddLeaf("access-size", dict));

  PopulateShadowMemoryBlob(shadow, error_info, dict, memory_ranges);
  PopulatePageBitsBlob(shadow, error_info, dict, memory_ranges);

  // Send information about corruption.
  crashdata::LeafSetUInt(error_info.heap_is_corrupt,
                         crashdata::DictAddLeaf("heap-is-corrupt", dict));
  crashdata::LeafSetUInt(error_info.corrupt_range_count,
                         crashdata::DictAddLeaf("corrupt-range-count", dict));
  crashdata::LeafSetUInt(error_info.corrupt_block_count,
                         crashdata::DictAddLeaf("corrupt-block-count", dict));
  if (error_info.corrupt_ranges_reported > 0) {
    crashdata::ValueList* list = crashdata::ValueGetValueList(
        crashdata::DictAddValue("corrupt-ranges", dict));
    for (size_t i = 0; i < error_info.corrupt_ranges_reported; ++i) {
      PopulateCorruptBlockRange(shadow, error_info.corrupt_ranges[i],
                                list->add_values(), memory_ranges);
    }
  }
  PopulateAsanParameters(error_info, dict);
}

void CrashdataProtobufToErrorInfo(const crashdata::Value& protobuf,
                                  AsanErrorInfo* error_info) {
  DCHECK_NE(static_cast<AsanErrorInfo*>(nullptr), error_info);

  DCHECK_EQ(crashdata::Value_Type_DICTIONARY, protobuf.type());

  const crashdata::Dictionary outer_dict = protobuf.dictionary();
  DCHECK(outer_dict.IsInitialized());
  for (const auto& iter : outer_dict.values()) {
    if (iter.value().has_leaf()) {
      const crashdata::Leaf& leaf = iter.value().leaf();
      if (base::LowerCaseEqualsASCII(iter.key(), "header")) {
        DCHECK(leaf.has_address());
        error_info->block_info.header =
            reinterpret_cast<const void*>(leaf.address().address());
      } else if (base::LowerCaseEqualsASCII(iter.key(), "user-size")) {
        DCHECK(leaf.has_unsigned_integer());
        error_info->block_info.user_size = leaf.unsigned_integer();
      } else if (base::LowerCaseEqualsASCII(iter.key(), "state")) {
        DCHECK(leaf.has_string());
        error_info->block_info.state = BlockStateStringToEnum(leaf.string());
      } else if (base::LowerCaseEqualsASCII(iter.key(), "heap-type")) {
        DCHECK(leaf.has_string());
        error_info->block_info.heap_type = HeapTypeStrToEnum(leaf.string());
      } else if (base::LowerCaseEqualsASCII(iter.key(), "alloc-thread-id")) {
        DCHECK(leaf.has_unsigned_integer());
        error_info->block_info.alloc_tid =
            static_cast<DWORD>(leaf.unsigned_integer());
      } else if (base::LowerCaseEqualsASCII(iter.key(), "alloc-stack")) {
        DCHECK(leaf.has_stack_trace());
        // TODO(sebmarchand): Parse this field.
      } else if (base::LowerCaseEqualsASCII(iter.key(), "free-thread-id")) {
        DCHECK(leaf.has_unsigned_integer());
        error_info->block_info.free_tid =
            static_cast<DWORD>(leaf.unsigned_integer());
      } else if (base::LowerCaseEqualsASCII(iter.key(), "free-stack")) {
        DCHECK(leaf.has_stack_trace());
        // TODO(sebmarchand): Parse this field.
      } else if (base::LowerCaseEqualsASCII(iter.key(),
                                            "milliseconds-since-free")) {
        DCHECK(leaf.has_unsigned_integer());
        error_info->block_info.milliseconds_since_free =
            leaf.unsigned_integer();
      } else if (base::LowerCaseEqualsASCII(iter.key(), "contents")) {
        DCHECK(leaf.has_blob());
        // TODO(sebmarchand): Parse this field.
      } else if (base::LowerCaseEqualsASCII(iter.key(), "shadow")) {
        DCHECK(leaf.has_blob());
        // TODO(sebmarchand): Parse this field.
      } else {
        NOTREACHED() << "Unexpected leaf entry.";
      }
    } else if (iter.value().has_dictionary()) {
      if (base::LowerCaseEqualsASCII(iter.key(), "analysis")) {
        // TODO(sebmarchand): Parse this field.
      } else {
        NOTREACHED() << "Unexpected dictionary entry.";
      }
    } else {
      NOTREACHED() << "Unexpected entry.";
    }
  }
}

}  // namespace asan
}  // namespace agent
