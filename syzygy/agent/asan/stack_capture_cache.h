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

#ifndef SYZYGY_AGENT_ASAN_STACK_CAPTURE_CACHE_H_
#define SYZYGY_AGENT_ASAN_STACK_CAPTURE_CACHE_H_

#include <stddef.h>

#include "base/hash_tables.h"
#include "base/synchronization/lock.h"

namespace agent {
namespace asan {

// A simple wrapper class to hold a stack trace capture.
class StackCapture {
 public:
  // From http://msdn.microsoft.com/en-us/library/bb204633.aspx,
  // The maximum number of frames which CaptureStackBackTrace can be asked
  // to traverse must be less than 63, so set it to 62.
  static const size_t kMaxNumFrames = 62;

  StackCapture() : num_frames_(0) {
  }

  // @returns true if this stack trace capture contains valid frame pointers.
  bool IsValid() const { return num_frames_ != 0; }

  // @returns the number of valid frame pointers in this stack trace capture.
  uint8 num_frames() const { return num_frames_; }

  // @returns a pointer to the captured stack frames, or NULL if no stack
  //     frames have been captured.
  const void* const* frames() const { return IsValid() ? frames_ : NULL; }

  // Initializes a stack trace from an array of frame pointers and a count
  // (such as returned by CaptureStackBackTrace).
  // @param frames an array of frame pointers.
  // @param num_frames the number of valid frame pointers in @frames. Note
  //     that at most kMaxNumFrames frame pointers will be copied to this
  //     stack trace capture.
  void InitFromBuffer(const void* const* frames, size_t num_frames);

 protected:
  // The number of valid frames in this stack trace capture.
  size_t num_frames_;

  // The array or frame pointers comprising this stack trace capture.
  void* frames_[kMaxNumFrames];

 private:
  DISALLOW_COPY_AND_ASSIGN(StackCapture);
};

// A class which manages a thread-safe cache of unique stack traces, by ID.
class StackCaptureCache {
 public:
  // The number of unused stack trace objects to preallocate per page.
  static const size_t kNumCapturesPerPage = 1024;

  // The type used to uniquely identify a stack.
  typedef unsigned long StackId;

  // A page of preallocated stack trace capture objects to be populated
  // and stored in the known stacks cache map.
  struct CachePage {
    explicit CachePage(CachePage* link)
        : next_page(link), num_captures_used(0) {
    }

    // The cache pages from a linked list, which allows for easy cleanup
    // when the cache is destroyed.
    struct CachePage* next_page;

    // The number of captures consumed by the cache. This is also the index
    // of the next capture to use when inserting into the cache. When this
    // becomes equal to kNumCapturesPerPage, it is time to allocate a new
    // page.
    size_t num_captures_used;

    // A page's worth of preallocated collection of capture objects.
    StackCapture captures[kNumCapturesPerPage];

   private:
    DISALLOW_COPY_AND_ASSIGN(CachePage);
  };

  // Initializes a new stack capture cache.
  StackCaptureCache();

  // Destroys a stack capture cache.
  ~StackCaptureCache();

  // Save (or retrieve) the stack capture (the first @p num_frames elements
  // from  @p frames) into the cache using @p stack_id as the key.
  const StackCapture* SaveStackTrace(StackId stack_id,
                                     const void* const* frames,
                                     size_t num_frames);

 protected:
  // The container type in which we store the cached stacks, by id.
  typedef base::hash_map<StackId, const StackCapture*> StackMap;

  // A lock to protect the known stacks map from concurrent access.
  base::Lock lock_;

  // The map of known stacks, by id. Accessed under lock_.
  StackMap known_stacks_;

  // The current page from which new stack captures are allocated.
  // Accessed under lock_.
  CachePage* current_page_;

 private:
  DISALLOW_COPY_AND_ASSIGN(StackCaptureCache);
};

}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_STACK_CAPTURE_CACHE_H_
