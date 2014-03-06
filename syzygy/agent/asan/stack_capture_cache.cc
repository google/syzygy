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

#include <algorithm>

#include "base/logging.h"
#include "base/stringprintf.h"
#include "syzygy/agent/asan/asan_logger.h"
#include "syzygy/agent/asan/stack_capture.h"

namespace agent {
namespace asan {

namespace {

// Gives us access to the first frame of a stack capture as link-list pointer.
StackCapture** GetFirstFrameAsLink(StackCapture* stack_capture) {
  DCHECK(stack_capture != NULL);
  StackCapture** link = reinterpret_cast<StackCapture**>(
      const_cast<void**>(stack_capture->frames()));
  DCHECK(link != NULL);
  return link;
}

}  // namespace

size_t StackCaptureCache::compression_reporting_period_ =
    common::kDefaultReportingPeriod;

StackCaptureCache::CachePage::~CachePage() {
  // It's our parent StackCaptureCache's responsibility to clean up the linked
  // list of cache pages. We balk if we're being deleted and haven't been
  // properly unlinked from the linked list.
  DCHECK(next_page_ == NULL);
  Shadow::Unpoison(this, sizeof(CachePage));
}

StackCapture* StackCaptureCache::CachePage::GetNextStackCapture(
    size_t max_num_frames) {
  size_t size = StackCapture::GetSize(max_num_frames);
  if (bytes_used_ + size > kDataSize)
    return NULL;

  // Use placement new.
  StackCapture* stack = new(data_ + bytes_used_) StackCapture(max_num_frames);
  bytes_used_ += size;

  return stack;
}

bool StackCaptureCache::CachePage::ReturnStackCapture(
    StackCapture* stack_capture) {
  DCHECK(stack_capture != NULL);

  uint8* stack = reinterpret_cast<uint8*>(stack_capture);
  size_t size = stack_capture->Size();

  // If this was the last stack capture provided by this page then the end of
  // it must align with our current data pointer.
  if (data_ + bytes_used_ != stack + size)
    return false;

  bytes_used_ -= size;
  return true;
}

StackCaptureCache::StackCaptureCache(AsanLogger* logger)
    : logger_(logger),
      max_num_frames_(StackCapture::kMaxNumFrames),
      current_page_(new CachePage(NULL)) {
  CHECK(current_page_ != NULL);
  DCHECK(logger_ != NULL);
  ::memset(&statistics_, 0, sizeof(statistics_));
  ::memset(reclaimed_, 0, sizeof(reclaimed_));
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
  ::memset(reclaimed_, 0, sizeof(reclaimed_));
  statistics_.size = sizeof(CachePage);
}

StackCaptureCache::~StackCaptureCache() {
  // Clean up the linked list of cache pages.
  while (current_page_ != NULL) {
    CachePage* page = current_page_;
    current_page_ = page->next_page_;
    page->next_page_ = NULL;
    delete page;
  }
}

void StackCaptureCache::Init() {
  compression_reporting_period_ = common::kDefaultReportingPeriod;
}

const StackCapture* StackCaptureCache::SaveStackTrace(
    StackId stack_id, const void* const* frames, size_t num_frames) {
  DCHECK(frames != NULL);
  DCHECK_NE(num_frames, 0U);
  DCHECK(current_page_ != NULL);

  bool already_cached = false;
  StackCapture* stack_trace = NULL;
  bool saturated = false;

  {
    size_t known_stack_shard = stack_id % kKnownStacksSharding;
    // Get or insert the current stack trace while under the lock for this
    // bucket.
    base::AutoLock auto_lock(known_stacks_locks_[known_stack_shard]);

    // Check if the stack capture is already in the cache map.
    StackCapture capture;
    capture.set_stack_id(stack_id);
    StackSet::iterator result = known_stacks_[known_stack_shard].find(&capture);

    // If this capture has not already been cached then we have to initialize
    // the data.
    if (result == known_stacks_[known_stack_shard].end()) {
      stack_trace = GetStackCapture(num_frames);
      DCHECK(stack_trace != NULL);
      stack_trace->InitFromBuffer(stack_id, frames, num_frames);
      std::pair<StackSet::iterator, bool> it =
          known_stacks_[known_stack_shard].insert(stack_trace);
      DCHECK(it.second);
      DCHECK(stack_trace->HasNoRefs());
    } else {
      already_cached = true;
      stack_trace = *result;
    }
    // Increment the reference count for this stack trace.
    if (!stack_trace->RefCountIsSaturated()) {
      stack_trace->AddRef();
    } else {
      saturated = true;
    }
  }
  DCHECK(stack_trace != NULL);

  bool must_log = false;
  Statistics statistics = {};
  // Update the statistics.
  if (compression_reporting_period_ != 0) {
    base::AutoLock stats_lock(stats_lock_);
    if (already_cached) {
      // If the existing stack capture is previously unreferenced and becoming
      // referenced again, then decrement the unreferenced counter.
      if (stack_trace->HasNoRefs()) {
        DCHECK_LT(0u, statistics_.unreferenced);
        --statistics_.unreferenced;
      }
    } else {
      ++statistics_.cached;
      statistics_.frames_alive += num_frames;
      ++statistics_.allocated;
    }
    if (!saturated && stack_trace->RefCountIsSaturated()) {
      saturated = true;
      ++statistics_.saturated;
    }
    ++statistics_.requested;
    ++statistics_.references;
    statistics_.frames_stored += num_frames;
    if (statistics_.requested % compression_reporting_period_ == 0) {
      must_log = true;
      GetStatisticsUnlocked(&statistics);
    }
  }

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

  size_t known_stack_shard = stack_capture->stack_id() % kKnownStacksSharding;
  bool add_to_reclaimed_list = false;
  StackCapture* stack = NULL;
  {
    base::AutoLock auto_lock(known_stacks_locks_[known_stack_shard]);

    // We own the stack so its fine to remove the const. We double check this
    // is the case in debug builds with the DCHECK.
    stack = const_cast<StackCapture*>(stack_capture);
    DCHECK(known_stacks_[known_stack_shard].find(stack) !=
        known_stacks_[known_stack_shard].end());

    stack->RemoveRef();

    if (stack->HasNoRefs()) {
      add_to_reclaimed_list = true;
      // Remove this from the known stacks as we're going to reclaim it and
      // overwrite part of its data as we insert into the reclaimed_ list.
      size_t num_erased = known_stacks_[known_stack_shard].erase(stack);
      DCHECK_EQ(num_erased, 1u);
    }
  }

  // Link this stack capture into the list of reclaimed stacks.
  if (add_to_reclaimed_list)
    AddStackCaptureToReclaimedList(stack);

  // Update the statistics.
  if (compression_reporting_period_ != 0) {
    base::AutoLock stats_lock(stats_lock_);
    DCHECK_LT(0u, statistics_.references);
    --statistics_.references;
    statistics_.frames_stored -= stack->num_frames();
    if (add_to_reclaimed_list) {
      --statistics_.cached;
      ++statistics_.unreferenced;
      // The frames in this stack capture are no longer alive.
      statistics_.frames_alive -= stack->num_frames();
    }
  }
}

void StackCaptureCache::LogStatistics()  {
  Statistics statistics = {};

  {
    base::AutoLock auto_lock(stats_lock_);
    GetStatisticsUnlocked(&statistics);
  }

  LogStatisticsImpl(statistics);
}

void StackCaptureCache::GetStatisticsUnlocked(Statistics* statistics) const {
#ifndef NDEBUG
  stats_lock_.AssertAcquired();
#endif

  DCHECK(statistics != NULL);
  *statistics = statistics_;
}

void StackCaptureCache::LogStatisticsImpl(const Statistics& statistics) const {
  // The cache has 3 categories of storage.
  // alive frames: these are actively participating in storing a stack trace.
  // dead frames: these are unreferenced stack traces that are eligible for
  //     reuse, but are currently dormant.
  // overhead: frames in a stack-capture that aren't used, padding at the end
  //     cache pages, cache page metadata, stack capture metadata, etc.

  // These are all in bytes.
  double cache_size = statistics.size;
  double alive_size = statistics.frames_alive * 4;
  double dead_size = statistics.frames_dead * 4;
  double stored_size = statistics.frames_stored * 4;

  // The |cache_size| is the actual size of storage taken, while |stored_size|
  // is the conceptual amount of frame data that is stored in the cache.
  double compression = 100.0 * (1.0 - (cache_size / stored_size));
  double alive = 100.0 * alive_size / cache_size;
  double dead = 100.0 * dead_size / cache_size;
  double overhead = 100.0 - alive - dead;

  logger_->Write(base::StringPrintf(
      "PID=%d; Stack cache size=%.2f MB; Compression=%.2f%%; "
      "Alive=%.2f%%; Dead=%.2f%%; Overhead=%.2f%%; Saturated=%d; Entries=%d",
      ::GetCurrentProcessId(),
      cache_size / 1024.0 / 1024.0,
      compression,
      alive,
      dead,
      overhead,
      statistics.saturated,
      statistics.cached));
}

StackCapture* StackCaptureCache::GetStackCapture(size_t num_frames) {
  StackCapture* stack_capture = NULL;

  // First look to the reclaimed stacks and try to use one of those. We'll use
  // the first one that's big enough.
  for (size_t n = num_frames; n <= max_num_frames_; ++n) {
    base::AutoLock lock(reclaimed_locks_[n]);
    if (reclaimed_[n] != NULL) {
      StackCapture* reclaimed_stack_capture = reclaimed_[n];
      StackCapture** link = GetFirstFrameAsLink(reclaimed_stack_capture);
      reclaimed_[n] = *link;
      stack_capture = reclaimed_stack_capture;
      break;
    }
  }

  if (stack_capture != NULL) {
    if (compression_reporting_period_ != 0) {
      base::AutoLock stats_lock(stats_lock_);
      // These frames are no longer dead, but in limbo. If the stack capture
      // is used they'll be added to frames_alive and frames_stored.
      statistics_.frames_dead -= stack_capture->max_num_frames();
    }
    return stack_capture;
  }

  StackCapture* unused_stack_capture = NULL;
  {
    base::AutoLock current_page_lock(current_page_lock_);

    // We didn't find a reusable stack capture. Go to the cache page.
    stack_capture = current_page_->GetNextStackCapture(num_frames);

    if (stack_capture != NULL)
      return stack_capture;

    // If the allocation failed we don't have enough room on the current page.

    // Use the remaining bytes to create one more maximally sized stack
    // capture. We will stuff this into the reclaimed_ structure for later
    // use.
    size_t bytes_left = current_page_->bytes_left();
    size_t max_num_frames = StackCapture::GetMaxNumFrames(bytes_left);
    if (max_num_frames > 0) {
      DCHECK_LT(max_num_frames, num_frames);
      DCHECK_LE(StackCapture::GetSize(max_num_frames), bytes_left);
      unused_stack_capture =
          current_page_->GetNextStackCapture(max_num_frames);
      DCHECK(unused_stack_capture != NULL);
    }

    // Allocate a new page (that links to the current page) and use it to
    // allocate a new stack capture.
    current_page_ = new CachePage(current_page_);
    CHECK(current_page_ != NULL);
    statistics_.size += sizeof(CachePage);
    stack_capture = current_page_->GetNextStackCapture(num_frames);
  }

  if (unused_stack_capture != NULL) {
    // We're creating an unreferenced stack capture.
    AddStackCaptureToReclaimedList(unused_stack_capture);
  }

  // Update the statistics.
  if (compression_reporting_period_ != 0) {
    base::AutoLock stats_lock(stats_lock_);
    ++statistics_.unreferenced;
  }

  DCHECK(stack_capture != NULL);
  return stack_capture;
}

void StackCaptureCache::AddStackCaptureToReclaimedList(
    StackCapture* stack_capture) {
  DCHECK(stack_capture != NULL);
  {
    base::AutoLock lock(reclaimed_locks_[stack_capture->max_num_frames()]);

    StackCapture** link = GetFirstFrameAsLink(stack_capture);
    size_t num_frames = stack_capture->max_num_frames();
    *link = reclaimed_[num_frames];
    reclaimed_[num_frames] = stack_capture;
  }

  // Update the statistics.
  if (compression_reporting_period_ != 0) {
    base::AutoLock stats_lock(stats_lock_);
    statistics_.frames_dead += stack_capture->max_num_frames();
  }
}

}  // namespace asan
}  // namespace agent
