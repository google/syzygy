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
// Declares some structure and some utility functions used to get some
// information about an ASan error.

#ifndef SYZYGY_AGENT_ASAN_ERROR_INFO_H_
#define SYZYGY_AGENT_ASAN_ERROR_INFO_H_

#include "syzygy/agent/asan/stack_capture.h"

namespace agent {
namespace asan {

// Forward declarations.
class StackCaptureCache;
struct BlockHeader;

// The different memory access modes that we can encounter.
enum AccessMode {
  ASAN_READ_ACCESS,
  ASAN_WRITE_ACCESS,
  ASAN_UNKNOWN_ACCESS
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
  DOUBLE_FREE
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

// Store the information that we want to report about a block.
// TODO(sebmarchand): Rename this to avoid the confusion with the BlockInfo
//     structure ?
struct AsanBlockInfo {
  // The address of the header for this block.
  const void* header;
  // The user size of the block.
  size_t user_size : 30;
  // This is implicitly a HeapProxy::BlockState value.
  size_t state : 2;
  // The ID of the allocation thread.
  DWORD alloc_tid;
  // The ID of the free thread.
  DWORD free_tid;
  // True iff the block is corrupt.
  bool corrupt;
  // The allocation stack trace.
  void* alloc_stack[agent::asan::StackCapture::kMaxNumFrames];
  // The free stack trace.
  void* free_stack[agent::asan::StackCapture::kMaxNumFrames];
  // The size of the allocation stack trace.
  uint8 alloc_stack_size;
  // The size of the free stack trace.
  uint8 free_stack_size;
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
  void* location;
  // The context prior to the crash.
  CONTEXT context;
  // The allocation stack trace.
  void* alloc_stack[agent::asan::StackCapture::kMaxNumFrames];
  // The size of the allocation stack trace.
  uint8 alloc_stack_size;
  // The ID of the allocation thread.
  DWORD alloc_tid;
  // The free stack trace.
  void* free_stack[agent::asan::StackCapture::kMaxNumFrames];
  // The size of the free stack trace.
  uint8 free_stack_size;
  // The ID of the free thread.
  DWORD free_tid;
  // The ID of the crash stack, this is needed to be able to blacklist some
  // known bugs.
  StackCapture::StackId crash_stack_id;
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
  // The time since the memory block containing this address has been freed.
  // This would be equal to zero if the block is still allocated.
  uint32 milliseconds_since_free;
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
};

// Returns a string describing a bad access kind.
// @param bad_access_kind The bad access kind for which we want a textual
//     representation.
// @returns a string describing the bad access kind.
const char* ErrorInfoAccessTypeToStr(BadAccessKind bad_access_kind);

// Get information about a bad access.
// @param stack_cache The stack cache that owns the alloc and free stack traces
//     of the blocks.
// @param bad_access_info Will receive the information about this access.
// @returns true if the address belongs to a memory block, false otherwise.
bool ErrorInfoGetBadAccessInformation(StackCaptureCache* stack_cache,
                                      AsanErrorInfo* bad_access_info);

// Give the type of a bad heap access corresponding to an address.
// @param addr The address causing a bad heap access.
// @param header The header of the block containing this address.
// @returns The type of the bad heap access corresponding to this address.
// @note Exposed for unittesting.
BadAccessKind ErrorInfoGetBadAccessKind(const void* addr,
                                        const BlockHeader* header);

// Retrieves a block's metadata.
// @param stack_cache The stack cache that owns the alloc and free stack traces
//     of this block.
// @param asan_block_info Will receive the block's metadata.
void ErrorInfoGetAsanBlockInfo(StackCaptureCache* stack_cache,
                               AsanBlockInfo* asan_block_info);

}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_ERROR_INFO_H_
