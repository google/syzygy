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

#include "syzygy/agent/asan/stack_capture_cache.h"

#include <windows.h>  // NOLINT
#include <string.h>
#include <algorithm>

#include "base/logging.h"
#include "base/stringprintf.h"
#include "syzygy/agent/asan/asan_logger.h"

namespace agent {
namespace asan {

size_t StackCaptureCache::compression_reporting_period_ =
    StackCaptureCache::kDefaultCompressionReportingPeriod;

void StackCapture::InitFromBuffer(const void* const* frames,
                                  size_t num_frames) {
  DCHECK(frames != NULL);
  DCHECK_LT(0U, num_frames);
  num_frames_ = std::min(num_frames, kMaxNumFrames);
  ::memcpy(frames_, frames, num_frames_ * sizeof(void*));
}

StackCaptureCache::StackCaptureCache(AsanLogger* logger)
    : logger_(logger),
      current_page_(new CachePage(NULL)),
      total_allocations_(0),
      cached_allocations_(0) {
  CHECK(current_page_ != NULL);
  DCHECK(logger_ != NULL);
}

StackCaptureCache::~StackCaptureCache() {
  // Iterate through the list of linked pages, deleting the head of the list
  // as we go.
  while (current_page_ != NULL) {
    CachePage* page_to_delete = current_page_;
    current_page_ = current_page_->next_page;
    delete page_to_delete;
  }
}

const StackCapture* StackCaptureCache::SaveStackTrace(
    StackId stack_id, const void* const* frames, size_t num_frames) {
  DCHECK(frames != NULL);
  DCHECK(num_frames != 0);
  DCHECK(current_page_ != NULL);

  bool must_log_ratio = false;
  double compression_ratio = 1.0;
  const StackCapture* stack_trace = NULL;

  {
    // Get or insert the current stack trace while under the lock.
    base::AutoLock auto_lock(lock_);

    // If the current page has been entirely consumed, allocate a new page
    // that links to the current page.
    if (current_page_->num_captures_used == kNumCapturesPerPage) {
      current_page_ = new CachePage(current_page_);
      CHECK(current_page_ != NULL);
    }

    // Find the next unused trace capture object.
    StackCapture* unused_trace =
        &current_page_->captures[current_page_->num_captures_used];

    // Attempt to insert it into the known stacks map.
    std::pair<StackMap::const_iterator, bool> result = known_stacks_.insert(
        std::make_pair(stack_id, unused_trace));

    // If the insertion was successful, then this capture has not already been
    // cached and we have to initialize the data.
    if (result.second) {
      unused_trace->InitFromBuffer(frames, num_frames);
      ++(current_page_->num_captures_used);
      ++cached_allocations_;
    }

    ++total_allocations_;
    stack_trace = result.first->second;

    if (compression_reporting_period_ != 0 &&
        total_allocations_ % compression_reporting_period_ == 0) {
      must_log_ratio = true;
      compression_ratio = GetCompressionRatioUnlocked();
    }
  }

  DCHECK(stack_trace != NULL);

  if (must_log_ratio)
    LogCompressionRatioImpl(compression_ratio);

  // Return the stack trace pointer that is now in the cache.
  return stack_trace;
}

void StackCaptureCache::LogCompressionRatio() const {
  double compression_ratio = 0.0;

  {
    base::AutoLock auto_lock(lock_);
    compression_ratio = GetCompressionRatioUnlocked();
  }

  LogCompressionRatioImpl(compression_ratio);
}

double StackCaptureCache::GetCompressionRatioUnlocked() const {
  lock_.AssertAcquired();
  if (total_allocations_ == 0)
    return 1.0;
  return static_cast<double>(cached_allocations_) / total_allocations_;
}

void StackCaptureCache::LogCompressionRatioImpl(double ratio) const {
  DCHECK_LE(0.0, ratio);
  DCHECK_GE(1.0, ratio);
  logger_->Write(base::StringPrintf(
      "Allocation stack cache compression: %.2f%%.\n", (1.0 - ratio) * 100.0));
}

}  // namespace asan
}  // namespace agent
