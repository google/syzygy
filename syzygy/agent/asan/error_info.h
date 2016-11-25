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
//
// Declares structures and utility functions used to get information about an
// Asan error.

#ifndef SYZYGY_AGENT_ASAN_ERROR_INFO_H_
#define SYZYGY_AGENT_ASAN_ERROR_INFO_H_

#include <utility>
#include <vector>

#include "base/callback.h"
#include "syzygy/agent/asan/block.h"
#include "syzygy/agent/asan/heap.h"
#include "syzygy/agent/common/stack_capture.h"
#include "syzygy/common/asan_parameters.h"

// Forward declaration.
namespace crashdata {
class Value;
}  // namespace crashdata

namespace agent {
namespace asan {

// Forward declarations.
class Shadow;
class StackCaptureCache;
struct BlockHeader;

// The different memory access modes that we can encounter.
enum AccessMode {
  ASAN_READ_ACCESS,
  ASAN_WRITE_ACCESS,
  ASAN_UNKNOWN_ACCESS,

  ASAN_ACCESS_MODE_MAX,
};

// Enumeration of the different kinds of bad heap accesses that we can
// encounter.
enum BadAccessKind {
  // This enum should start with bad access type that are not relative to a
  // heap block.
  // @note The ordering is important because those labels are used in
  //     numeric inequalities.
  UNKNOWN_BAD_ACCESS,
  WILD_ACCESS,
  INVALID_ADDRESS,
  CORRUPT_BLOCK,
  CORRUPT_HEAP,

  // This enum should end with bad access types that are relative to heap
  // blocks.
  USE_AFTER_FREE,
  HEAP_BUFFER_OVERFLOW,
  HEAP_BUFFER_UNDERFLOW,
  DOUBLE_FREE,

  BAD_ACCESS_KIND_MAX,
};

// The different types of errors we can encounter.
extern const char kHeapUseAfterFree[];
extern const char kHeapBufferUnderFlow[];
extern const char kHeapBufferOverFlow[];
extern const char kAttemptingDoubleFree[];
extern const char kInvalidAddress[];
extern const char kWildAccess[];
extern const char kHeapUnknownError[];
extern const char kHeapCorruptBlock[];
extern const char kCorruptHeap[];

enum AsanFeature : uint32_t {
  ASAN_FEATURE_ENABLE_PAGE_PROTECTIONS = (1 << 0),
  // This feature flag is currently deprecated and ignored.
  DEPRECATED_ASAN_FEATURE_ENABLE_CTMALLOC = (1 << 1),
  ASAN_FEATURE_ENABLE_LARGE_BLOCK_HEAP = (1 << 2),
  // This feature flag is currently deprecated and ignored.
  DEPRECATED_ASAN_FEATURE_ENABLE_KASKO = (1 << 3),
  // This feature flag is currently deprecated and ignored.
  DEPRECATED_ASAN_FEATURE_ENABLE_CRASHPAD = (1 << 4),
  ASAN_FEATURE_MAX = (1 << 5),
};
using AsanFeatureSet = uint32_t;

// Feature set for all valid features.
const AsanFeatureSet kAsanValidFeatures =
    ASAN_FEATURE_ENABLE_PAGE_PROTECTIONS |
    ASAN_FEATURE_ENABLE_LARGE_BLOCK_HEAP;

// Feature set for all deprecated features.
const AsanFeatureSet kAsanDeprecatedFeatures =
    DEPRECATED_ASAN_FEATURE_ENABLE_CTMALLOC |
    DEPRECATED_ASAN_FEATURE_ENABLE_KASKO |
    DEPRECATED_ASAN_FEATURE_ENABLE_CRASHPAD;

// Store the information that we want to report about a block.
// TODO(sebmarchand): Rename this to avoid the confusion with the BlockInfo
//     structure?
struct AsanBlockInfo {
  // The address of the header for this block.
  const void* header;
  // The user size of the block.
  size_t user_size;
  // This is implicitly a BlockState value.
  uint8_t state;
  // The ID of the allocation thread.
  DWORD alloc_tid;
  // The ID of the free thread.
  DWORD free_tid;
  // The result of a block analysis on this block.
  BlockAnalysisResult analysis;
  // The allocation stack trace.
  void* alloc_stack[agent::common::StackCapture::kMaxNumFrames];
  // The free stack trace.
  void* free_stack[agent::common::StackCapture::kMaxNumFrames];
  // The size of the allocation stack trace.
  uint8_t alloc_stack_size;
  // The size of the free stack trace.
  uint8_t free_stack_size;
  // The type of heap that made the allocation.
  HeapType heap_type;
  // The time since this block has been freed. This would be equal to zero if
  // the block is still allocated.
  // TODO(chrisha): We actually keep track of this in ticks. Rename this?
  uint32_t milliseconds_since_free;
};

struct AsanCorruptBlockRange {
  // The beginning address of the range.
  const void* address;
  // The length of the range.
  size_t length;
  // The number of blocks in this range.
  size_t block_count;
  // The number of blocks in the |block_info| array.
  size_t block_info_count;
  // The information about the blocks in this range. This may include one or
  // more of the corrupt blocks and/or the valid blocks surrounding them; at the
  // very least it will contain the first corrupt block in the range. The real
  // length of this array will be stored in |block_info_count|. The array itself
  // is allocated on the stack so that it gets shipped with minidumps.
  AsanBlockInfo* block_info;
};

// Store the information about a bad memory access.
struct AsanErrorInfo {
  // The address where the bad access happened.
  const void* location;
  // The context prior to the crash.
  CONTEXT context;
  // The ID of the crash stack, this is needed to be able to blacklist some
  // known bugs.
  common::StackCapture::StackId crash_stack_id;
  // The information about the block that contains the invalid location.
  AsanBlockInfo block_info;
  // The error type.
  BadAccessKind error_type;
  // The access mode.
  AccessMode access_mode;
  // The access size.
  size_t access_size;
  // The information about the shadow memory for this address, this would be
  // something like: "0x12345678 is located 8 bytes inside of a 10-byte region
  // [0x12345670,0x1234567A)."
  char shadow_info[128];
  // A textual description of the shadow memory around |location|.
  char shadow_memory[512];
  // Indicates if the heap is corrupt.
  bool heap_is_corrupt;
  // The number of corrupt ranges encountered.
  size_t corrupt_range_count;
  // The number of corrupt blocks encountered.
  size_t corrupt_block_count;
  // The number of corrupt ranges reported in |corrupt_ranges|.
  size_t corrupt_ranges_reported;
  // The information about the corrupt ranges of memory. The real length of this
  // array will be stored in |corrupt_ranges_reported|. This will be NULL if
  // |corrupt_ranges_reported| is zero.
  AsanCorruptBlockRange* corrupt_ranges;
  // The current configuration of the runtime library.
  ::common::AsanParameters asan_parameters;
  // Temporarily report the list of features that have been randomly enabled for
  // this client. This is something that could be deduced by analyzing the
  // |asan_parameters| structure but having it directly available in the crash
  // report structure will make it easier to investigate on the heap corruption
  // bug that we're tracking.
  // TODO(sebmarchand): Remove this once we don't need it anymore.
  AsanFeatureSet feature_set;
};

// Helper struct that is used when calculating the range of the shadow memory
// surrounding a point of invalid access.
struct AsanErrorShadowMemory {
  uintptr_t index;
  uintptr_t address;
  uintptr_t length;
};

// This callback allows a heap manager to report heap consistency problems that
// it encounters during its operation. This is usually plumbed into the Asan
// runtime so that the errors may be appropriately reported.
//
// |asan_error_info| contains information about the primary heap error that
// was encountered. It is guaranteed to be on the stack.
typedef base::Callback<void(AsanErrorInfo* asan_error_info)>
    HeapErrorCallback;

// Contains pairs of address/size of data to be reported to the crash reporter
// during a crash.
typedef std::vector<std::pair<const char*, size_t>> MemoryRanges;

// Returns a string describing a bad access kind.
// @param bad_access_kind The bad access kind for which we want a textual
//     representation.
// @returns a string describing the bad access kind.
const char* ErrorInfoAccessTypeToStr(BadAccessKind bad_access_kind);

// Get information about a bad access.
// @param shadow The shadow memory to query.
// @param stack_cache The stack cache that owns the alloc and free stack traces
//     of the blocks.
// @param bad_access_info Will receive the information about this access.
// @returns true if the address belongs to a memory block, false otherwise.
bool ErrorInfoGetBadAccessInformation(const Shadow* shadow,
                                      StackCaptureCache* stack_cache,
                                      AsanErrorInfo* bad_access_info);

// Give the type of a bad heap access corresponding to an address.
// @param shadow The shadow memory to query.
// @param addr The address causing a bad heap access.
// @param header The header of the block containing this address.
// @returns The type of the bad heap access corresponding to this address.
// @note Exposed for unittesting.
BadAccessKind ErrorInfoGetBadAccessKind(const Shadow* shadow,
                                        const void* addr,
                                        const BlockHeader* header);

// Retrieves a block's metadata.
// @param shadow The shadow memory to query.
// @param block_info The block whose info is to be gathered.
// @param stack_cache The stack cache that owns the alloc and free stack traces
//     of this block.
// @param asan_block_info Will receive the block's metadata.
void ErrorInfoGetAsanBlockInfo(const Shadow* shadow,
                               const BlockInfo& block_info,
                               StackCaptureCache* stack_cache,
                               AsanBlockInfo* asan_block_info);

// Computes the range of the shadow memory surrounding the point of invalid
// access.
// @param shadow The shadow memory to query.
// @param error_location The memory location where the error occured.
// @param shadow_memory Will receive the shadow memory surrounding the error.
void GetAsanErrorShadowMemory(const Shadow* shadow,
                              const void* error_location,
                              AsanErrorShadowMemory* shadow_memory);

// Given a populated AsanBlockInfo struct, fills out a corresponding crashdata
// protobuf.
// @param shadow The shadow memory to query.
// @param block_info The block info information.
// @param include_block_contents If this is true the block contents will be
//     explicitly included in the protobuf.
// @param value The uninitialized protobuf value to be populated.
// @param memory_ranges If its value is not nullptr, the address/size of
//     relevant memory content will be appended to this variable.
void PopulateBlockInfo(const Shadow* shadow,
                       const AsanBlockInfo& block_info,
                       bool include_block_contents,
                       crashdata::Value* value,
                       MemoryRanges* memory_ranges);

// Given a populated AsanCorruptBlockRange struct, fills out a corresponding
// crashdata protobuf.
// @param shadow The shadow memory to query.
// @param range The corrupt block range information.
// @param value The uninitialized protobuf value to be populated.
// @param memory_ranges If its value is not nullptr, the address/size of
//     relevant memory content will be appended to this variable.
void PopulateCorruptBlockRange(const Shadow* shadow,
                               const AsanCorruptBlockRange& range,
                               crashdata::Value* value,
                               MemoryRanges* memory_ranges);

// Given a populated AsanErrorInfo struct, fills out a corresponding crashdata
// protobuf.
// @param shadow The shadow memory to query.
// @param error_info The filled in error information.
// @param value The uninitialized protobuf value to be populated.
// @param memory_ranges If its value is not nullptr, the address/size of
//     relevant memory content will be appended to this variable.
void PopulateErrorInfo(const Shadow* shadow,
                       const AsanErrorInfo& error_info,
                       crashdata::Value* value,
                       MemoryRanges* memory_ranges);

// Given a populated crashdata protobuf, fills out a corresponding AsanErrorInfo
// struct.
// @param protobuf The filled in error information protobuf.
// @param value The uninitialized AsanErrorInfo struct to be populated.
void CrashdataProtobufToErrorInfo(const crashdata::Value& protobuf,
                                  AsanErrorInfo* error_info);

// Helper function to get the instruction pointer from a CONTEXT
// on both ia32 and x64.
inline void* GetInstructionPointer(const CONTEXT& context) {
#ifdef _WIN64
  return reinterpret_cast<void*>(context.Rip);
#else
  return reinterpret_cast<void*>(context.Eip);
#endif
}

}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_ERROR_INFO_H_
