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
      current_page_(new CachePage(NULL)) {
  CHECK(current_page_ != NULL);
  DCHECK(logger_ != NULL);
  ::memset(&statistics_, 0, sizeof(statistics_));
  statistics_.size = sizeof(CachePage);
}

StackCaptureCache::StackCaptureCache(AsanLogger* logger, size_t max_num_frames)
    : logger_(logger),
      max_num_frames_(0),
      current_page_(new CachePage(NULL)) {
  CHECK(current_page_ != NULL);
  DCHECK(logger_ != NULL);
  DCHECK_LT(0u, max_num_frames);
  max_num_frames_ = static_cast<uint8>(
      std::min(max_num_frames, StackCapture::kMaxNumFrames));
  ::memset(&statistics_, 0, sizeof(statistics_));
  statistics_.size = sizeof(CachePage);
}

StackCaptureCache::~StackCaptureCache() {
  if (current_page_ != NULL)
    delete current_page_;
}

void StackCaptureCache::Init() {
   compression_reporting_period_ = kDefaultCompressionReportingPeriod;
}

const StackCapture* StackCaptureCache::SaveStackTrace(
    StackId stack_id, const void* const* frames, size_t num_frames) {
  DCHECK(frames != NULL);
  DCHECK(num_frames != 0);
  DCHECK(current_page_ != NULL);

  bool must_log = false;
  Statistics statistics = {};
  StackCapture* stack_trace = NULL;

  {
    // Get or insert the current stack trace while under the lock.
    base::AutoLock auto_lock(lock_);

    // If the current page has been entirely consumed, allocate a new page
    // that links to the current page.
    // TODO(chrisha): Use |num_frames| in GetNextStackCapture. No need to
    //     allocate bigger captures then are needed!
    StackCapture* unused_trace = current_page_->GetNextStackCapture(
        max_num_frames_);
    if (unused_trace == NULL) {
      current_page_ = new CachePage(current_page_);
      CHECK(current_page_ != NULL);
      statistics_.size += sizeof(CachePage);
      unused_trace = current_page_->GetNextStackCapture(max_num_frames_);
    }
    DCHECK(unused_trace != NULL);

    // Attempt to insert it into the known stacks map.
    unused_trace->set_stack_id(stack_id);
    std::pair<StackSet::iterator, bool> result = known_stacks_.insert(
        unused_trace);
    ++statistics_.requested;
    stack_trace = *result.first;

    // If the insertion was successful, then this capture has not already been
    // cached and we have to initialize the data.
    if (result.second) {
      DCHECK_EQ(unused_trace, stack_trace);
      unused_trace->InitFromBuffer(stack_id, frames, num_frames);
      ++statistics_.allocated;
      DCHECK(stack_trace->HasNoRefs());
    } else {
      // If we didn't need the stack capture then return it.
      current_page_->ReleaseStackCapture(unused_trace);
      unused_trace = NULL;

      // If this is previously unreferenced and becoming referenced again, then
      // decrement the unreferenced counter.
      if (stack_trace->HasNoRefs()) {
        DCHECK_LT(0u, statistics_.unreferenced);
        --statistics_.unreferenced;
      }
    }

    // Increment the reference count for this stack trace.
    if (!stack_trace->RefCountIsSaturated()) {
      stack_trace->AddRef();
      if (stack_trace->RefCountIsSaturated())
        ++statistics_.saturated;
    }
    ++statistics_.references;

    if (compression_reporting_period_ != 0 &&
        statistics_.requested % compression_reporting_period_ == 0) {
      must_log = true;
      GetStatisticsUnlocked(&statistics);
    }
  }

  DCHECK(stack_trace != NULL);

  if (must_log)
    LogStatisticsImpl(statistics);

  // Return the stack trace pointer that is now in the cache.
  return stack_trace;
}

const StackCapture* StackCaptureCache::SaveStackTrace(
    const StackCapture& stack_capture) {
  return SaveStackTrace(stack_capture.stack_id(),
                        stack_capture.frames(),
                        stack_capture.num_frames());
}

void StackCaptureCache::ReleaseStackTrace(const StackCapture* stack_capture) {
  DCHECK(stack_capture != NULL);

  base::AutoLock auto_lock(lock_);

  // We own the stack so its fine to remove the const. We double check this is
  // the case in debug builds with the DCHECK.
  StackCapture* stack = const_cast<StackCapture*>(stack_capture);
  DCHECK(known_stacks_.find(stack) != known_stacks_.end());

  stack->RemoveRef();
  DCHECK_LT(0u, statistics_.references);
  --statistics_.references;

  if (stack->HasNoRefs()) {
    ++statistics_.unreferenced;
    DCHECK_GE(known_stacks_.size(), statistics_.unreferenced);
  }
}

void StackCaptureCache::LogStatistics() const {
  Statistics statistics = {};

  {
    base::AutoLock auto_lock(lock_);
    GetStatisticsUnlocked(&statistics);
  }

  LogStatisticsImpl(statistics);
}

void StackCaptureCache::GetStatisticsUnlocked(Statistics* statistics) const {
  lock_.AssertAcquired();

  DCHECK(statistics != NULL);
  *statistics = statistics_;
  statistics->cached = known_stacks_.size();
}

void StackCaptureCache::LogStatisticsImpl(const Statistics& statistics) const {
  double cache_size = statistics.size / 1024.0 / 1024.0;  // In MB.
  double compression = 100.0 * (1.0 - (static_cast<double>(statistics.cached) /
      statistics.references));
  double unreferenced = 100.0 * statistics.unreferenced / statistics.cached;

  logger_->Write(base::StringPrintf(
      "PID=%d; Stack cache size=%.2f MB; Compression=%.2f%%; "
      "Unreferenced=%.2f%%; Saturated=%d; Entries=%d",
      ::GetCurrentProcessId(),
      cache_size,
      compression,
      unreferenced,
      statistics.saturated,
      statistics.cached));
}

}  // namespace asan
}  // namespace agent
