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
#include "syzygy/agent/asan/error_info.h"
#include "syzygy/agent/asan/stack_capture.h"

namespace agent {
namespace asan {

// Forward declaration.
class AsanRuntime;

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
