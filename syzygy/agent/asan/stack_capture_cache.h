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

// Forward declaration.
class AsanLogger;

// A simple wrapper class to hold a stack trace capture.
class StackCapture {
 public:
  // From http://msdn.microsoft.com/en-us/library/bb204633.aspx,
  // The maximum number of frames which CaptureStackBackTrace can be asked
  // to traverse must be less than 63, so set it to 62.
  static const size_t kMaxNumFrames = 62;

  // TODO(chrisha): Add the ability to runtime limit the number of stack frames
  //     that can be stored in a StackCapture.

  // This corresponds to the the type used by ::CaptureStackBackTrace's hash
  // for a stack-trace.
  typedef ULONG StackId;

  StackCapture() : stack_id_(0), num_frames_(0) {
  }

  // @returns true if this stack trace capture contains valid frame pointers.
  bool IsValid() const { return num_frames_ != 0; }

  // @returns the ID associated with this stack trace.
  StackId stack_id() const { return stack_id_; }

  // @returns the number of valid frame pointers in this stack trace capture.
  uint8 num_frames() const { return num_frames_; }

  // @returns a pointer to the captured stack frames, or NULL if no stack
  //     frames have been captured.
  const void* const* frames() const { return IsValid() ? frames_ : NULL; }

  // Sets the stack ID for a given trace.
  // @param The stack ID to set.
  void set_stack_id(StackId stack_id) { stack_id_ = stack_id; }

  // Initializes a stack trace from an array of frame pointers, a count and
  // a StackId (such as returned by ::CaptureStackBackTrace).
  // @param stack_id The ID of the stack back trace.
  // @param frames an array of frame pointers.
  // @param num_frames the number of valid frame pointers in @frames. Note
  //     that at most kMaxNumFrames frame pointers will be copied to this
  //     stack trace capture.
  void InitFromBuffer(StackId stack_id,
                      const void* const* frames,
                      size_t num_frames);

  // Initializes a stack trace using ::CaptureStackBackTrace. This is inlined so
  // that it doesn't further pollute the stack trace, but rather makes it
  // reflect the actual point of the call.
  __forceinline void InitFromStack() {
    num_frames_ = ::CaptureStackBackTrace(
        0, kMaxNumFrames, frames_, &stack_id_);
  }

  // The hash comparison functor for use with MSDN's stdext::hash_set.
  struct HashCompare {
    static const size_t bucket_size = 4;
    static const size_t min_buckets = 8;
    // Calculates a hash value for the given stack_capture.
    size_t operator()(const StackCapture* stack_capture) const;
    // Value comparison operator.
    bool operator()(const StackCapture* stack_capture1,
                    const StackCapture* stack_capture2) const;
  };

 protected:
  // The unique ID of this hash. This is used for storing the hash in the map.
  StackId stack_id_;

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
  typedef StackCapture::StackId StackId;

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
  explicit StackCaptureCache(AsanLogger* logger);

  // Destroys a stack capture cache.
  ~StackCaptureCache();

  // @returns the default compression reporting period value.
  static size_t GetDefaultCompressionReportingPeriod() {
    return kDefaultCompressionReportingPeriod;
  }

  // Sets a new (global) compression reporting period value. Note that this
  // method is not thread safe. It is expected to be called once at startup,
  // or not at all.
  static void SetCompressionReportingPeriod(size_t period) {
    compression_reporting_period_ = period;
  }

  // @returns the current (global) compression reporting period value. It is
  //     expected that this value is a constant after initialization.
  static size_t GetCompressionReportingPeriod() {
    return compression_reporting_period_;
  }

  // Save (or retrieve) the stack capture (the first @p num_frames elements
  // from  @p frames) into the cache using @p stack_id as the key.
  // @param stack_id a unique identifier for this stack trace. It is expected
  //     that identical stack traces will have the same @p stack_id.
  // @param frames an array of stack frame pointers.
  // @param num_frames the number of valid elements in @p frames. Note that
  //     at most StackCapture::kMaxNumFrames will be saved.
  // @param stack_capture The initialized stack capture to save.
  // @returns a pointer to the saved stack capture.
  const StackCapture* SaveStackTrace(StackId stack_id,
                                     const void* const* frames,
                                     size_t num_frames);
  const StackCapture* SaveStackTrace(const StackCapture& stack_capture);

  // Logs the current stack capture cache compression ratio. This method is
  // thread safe.
  void LogCompressionRatio() const;

 protected:
  // The container type in which we store the cached stacks. This enforces
  // uniqueness based on their hash value, nothing more.
  typedef base::hash_set<const StackCapture*,
                         StackCapture::HashCompare> StackSet;

  // @returns The compression ratio achieved by the stack capture cache. This
  //     is the percentage of total allocation stack traces actually stored in
  //     the cache. This method must be called while holding lock_.
  double GetCompressionRatioUnlocked() const;

  // Implementation function for logging the compression ratio.
  void LogCompressionRatioImpl(double ratio) const;

  // The default number of iterations between each compression ratio report.
  // Zero (0) means do not report.
  static const size_t kDefaultCompressionReportingPeriod = 0;

  // The number of allocations between reports of the stack trace cache
  // compression ratio. Zero (0) means do not report. Values like 1 million
  // seem to be pretty good with Chrome.
  static size_t compression_reporting_period_;

  // Logger instance to which to report the compression ratio.
  AsanLogger* const logger_;

  // A lock to protect the known stacks map from concurrent access.
  mutable base::Lock lock_;

  // The set of known stacks. Accessed under lock_.
  StackSet known_stacks_;

  // The current page from which new stack captures are allocated.
  // Accessed under lock_.
  CachePage* current_page_;

  // The total number of stack allocations requested. Accessed under lock_.
  uint64 total_allocations_;

  // The total number of stack allocations requested. Accessed under lock_.
  uint64 cached_allocations_;

 private:
  DISALLOW_COPY_AND_ASSIGN(StackCaptureCache);
};

}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_STACK_CAPTURE_CACHE_H_
