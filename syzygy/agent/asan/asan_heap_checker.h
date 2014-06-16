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
// Declares HeapChecker, a class that checks a heap for corruption.

#ifndef SYZYGY_AGENT_ASAN_ASAN_HEAP_CHECKER_H_
#define SYZYGY_AGENT_ASAN_ASAN_HEAP_CHECKER_H_

#include <vector>

#include "base/logging.h"
#include "base/memory/scoped_vector.h"
#include "syzygy/agent/asan/stack_capture.h"

namespace agent {
namespace asan {

// Forward declaration.
class AsanRuntime;

// Store the information about a corrupt block.
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

// A class to analyze the heap and to check if it's corrupt.
class HeapChecker {
 public:
  typedef ScopedVector<AsanCorruptBlockRange> CorruptRangesVector;

  // Constructor.
  // @param The runtime managing the heaps.
  explicit HeapChecker(AsanRuntime* runtime);

  // Checks if the heap is corrupt and returns the information about the
  // corrupt ranges.
  // @param corrupt_ranges Will receive the information about the corrupt
  //     ranges.
  // @returns true if the heap is corrupt, false otherwise.
  bool IsHeapCorrupt(CorruptRangesVector* corrupt_ranges);

  // TODO(sebmarchand): Add a testing seam that controls the range of memory
  //     that is walked by HeapChecker to keep unittest times to something
  //     reasonable.

 private:
  // Get the information about the corrupt ranges in a heap slab.
  // @param lower_bound The lower bound for this slab.
  // @param length The length of this slab.
  // @param corrupt_ranges Will receive the information about the corrupt ranges
  //     in this slab.
  void GetCorruptRangesInSlab(const uint8* lower_bound,
                              size_t length,
                              CorruptRangesVector* corrupt_ranges);

  // The runtime managing the heaps.
  AsanRuntime* runtime_;
};

}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_ASAN_HEAP_CHECKER_H_
