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

#include "base/logging.h"
#include "base/stringprintf.h"
#include "syzygy/agent/asan/asan_logger.h"
#include "syzygy/agent/asan/stack_capture.h"

namespace agent {
namespace asan {

size_t StackCaptureCache::compression_reporting_period_ =
    StackCaptureCache::kDefaultCompressionReportingPeriod;

StackCaptureCache::CachePage::~CachePage() {
  if (next_page_ != NULL)
    delete next_page_;
}

StackCapture* StackCaptureCache::CachePage::GetNextStackCapture(
    size_t max_num_frames) {
  size_t size = StackCapture::GetSize(max_num_frames);
  if (bytes_used_ + size > kCachePageSize)
    return NULL;

  // Use placement new.
  StackCapture* stack = new(data_ + bytes_used_) StackCapture(max_num_frames);
  bytes_used_ += size;

  return stack;
}

void StackCaptureCache::CachePage::ReleaseStackCapture(
    StackCapture* stack_capture) {
  DCHECK(stack_capture != NULL);

  uint8* stack = reinterpret_cast<uint8*>(stack_capture);
  size_t size = stack_capture->Size();
  DCHECK_EQ(data_ + bytes_used_, stack + size);
  bytes_used_ -= size;
}

StackCaptureCache::StackCaptureCache(AsanLogger* logger)
    : logger_(logger),
      max_num_frames_(StackCapture::kMaxNumFrames),
      current_page_(new CachePage(NULL)),
      total_allocations_(0),
      cached_allocations_(0) {
  CHECK(current_page_ != NULL);
  DCHECK(logger_ != NULL);
}

StackCaptureCache::StackCaptureCache(AsanLogger* logger, size_t max_num_frames)
    : logger_(logger),
      max_num_frames_(0),
      current_page_(new CachePage(NULL)),
      total_allocations_(0),
      cached_allocations_(0) {
  CHECK(current_page_ != NULL);
  DCHECK(logger_ != NULL);
  DCHECK_LT(0u, max_num_frames);
  max_num_frames_ = static_cast<uint8>(
      std::min(max_num_frames, StackCapture::kMaxNumFrames));
}

StackCaptureCache::~StackCaptureCache() {
  if (current_page_ != NULL)
    delete current_page_;
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
    StackCapture* unused_trace = current_page_->GetNextStackCapture(
        max_num_frames_);
    if (unused_trace == NULL) {
      current_page_ = new CachePage(current_page_);
      CHECK(current_page_ != NULL);
      unused_trace = current_page_->GetNextStackCapture(max_num_frames_);
    }
    DCHECK(unused_trace != NULL);

    // Attempt to insert it into the known stacks map.
    unused_trace->set_stack_id(stack_id);
    std::pair<StackSet::const_iterator, bool> result = known_stacks_.insert(
        unused_trace);

    // If the insertion was successful, then this capture has not already been
    // cached and we have to initialize the data.
    if (result.second) {
      DCHECK_EQ(unused_trace, *result.first);
      unused_trace->InitFromBuffer(stack_id, frames, num_frames);
      ++cached_allocations_;
    } else {
      // If we didn't need the stack capture then return it.
      current_page_->ReleaseStackCapture(unused_trace);
      unused_trace = NULL;
    }

    ++total_allocations_;
    stack_trace = *result.first;

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

const StackCapture* StackCaptureCache::SaveStackTrace(
    const StackCapture& stack_capture) {
  return SaveStackTrace(stack_capture.stack_id(),
                        stack_capture.frames(),
                        stack_capture.num_frames());
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
      "PID=%d; Allocation stack cache compression: %.2f%%.\n",
      ::GetCurrentProcessId(),
      (1.0 - ratio) * 100.0));
}

}  // namespace asan
}  // namespace agent
