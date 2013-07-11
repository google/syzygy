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
    StackCaptureCache::kDefaultCompressionReportingPeriod;

StackCaptureCache::CachePage::~CachePage() {
  if (next_page_ != NULL)
    delete next_page_;
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

    // Get a stack capture to use.
    StackCapture* unused_trace = GetStackCapture(num_frames);
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
      statistics_.frames_alive += num_frames;
      DCHECK(stack_trace->HasNoRefs());
    } else {
      // If we didn't need the stack capture then return it.
      ReturnStackCapture(unused_trace);
      unused_trace = NULL;

      // If the existing stack capture is previously unreferenced and becoming
      // referenced again, then decrement the unreferenced counter.
      if (stack_trace->HasNoRefs()) {
        DCHECK_LT(0u, statistics_.unreferenced);
        --statistics_.unreferenced;
      }
    }

    // Increment the reference count for this stack trace, and the active number
    // of stored frames.
    if (!stack_trace->RefCountIsSaturated()) {
      stack_trace->AddRef();
      if (stack_trace->RefCountIsSaturated())
        ++statistics_.saturated;
    }
    ++statistics_.references;
    statistics_.frames_stored += num_frames;

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
  statistics_.frames_stored -= stack->num_frames();

  if (stack->HasNoRefs()) {
    ++statistics_.unreferenced;

    // The frames in this stack capture are no longer alive.
    statistics_.frames_alive -= stack->num_frames();

    // Remove this from the known stacks as we're going to reclaim it and
    // overwrite part of its data as we insert into the reclaimed_ list.
    StackSet::iterator it = known_stacks_.find(stack);
    DCHECK(it != known_stacks_.end());
    known_stacks_.erase(it);

    // Link this stack capture into the list of reclaimed stacks.
    AddStackCaptureToReclaimedList(stack);
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
#ifndef NDEBUG
  lock_.AssertAcquired();
#endif

  DCHECK(statistics != NULL);
  *statistics = statistics_;
  statistics->cached = known_stacks_.size();
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
#ifndef NDEBUG
  lock_.AssertAcquired();
#endif
  // First look to the reclaimed stacks and try to use one of those. We'll use
  // the first one that's big enough.
  for (size_t n = num_frames; n <= max_num_frames_; ++n) {
    if (reclaimed_[n] != NULL) {
      StackCapture* stack_capture = reclaimed_[n];
      StackCapture** link = GetFirstFrameAsLink(stack_capture);
      reclaimed_[n] = *link;

      // These frames are no longer dead, but in limbo. If the stack capture
      // is used they'll be added to frames_alive and frames_stored.
      statistics_.frames_dead -= stack_capture->max_num_frames();

      return stack_capture;
    }
  }

  // We didn't find a reusable stack capture. Go to the cache page.
  StackCapture* stack_capture = current_page_->GetNextStackCapture(num_frames);

  // If the allocation failed we don't have enough room on the current page.
  if (stack_capture == NULL) {
    // Use the remaining bytes to create one more maximally sized stack capture.
    // We immediately stuff this in to the reclaimed_ structure for later use.
    size_t bytes_left = current_page_->bytes_left();
    size_t max_num_frames = StackCapture::GetMaxNumFrames(bytes_left);
    if (max_num_frames > 0) {
      DCHECK_LT(max_num_frames, num_frames);
      DCHECK_LE(StackCapture::GetSize(max_num_frames), bytes_left);
      stack_capture = current_page_->GetNextStackCapture(max_num_frames);
      DCHECK(stack_capture != NULL);

      // The stack capture needs to be valid for us to be able to dereference
      // its frames. This is needed for splicing it into our reclaimed list.
      // We populate it with a single garbage stack frame.
      stack_capture->InitFromBuffer(
          0, reinterpret_cast<void**>(&stack_capture), 1);

      // We're creating an unreferenced stack capture.
      ++statistics_.unreferenced;
      AddStackCaptureToReclaimedList(stack_capture);
    }

    // Allocate a new page (that links to the current page) and use it to
    // allocate a new stack capture.
    current_page_ = new CachePage(current_page_);
    CHECK(current_page_ != NULL);
    statistics_.size += sizeof(CachePage);
    stack_capture = current_page_->GetNextStackCapture(num_frames);
  }
  DCHECK(stack_capture != NULL);
  return stack_capture;
}

void StackCaptureCache::ReturnStackCapture(StackCapture* stack_capture) {
#ifndef NDEBUG
  lock_.AssertAcquired();
#endif
  DCHECK(stack_capture != NULL);

  // First try to return it to the active cache page.
  if (current_page_->ReturnStackCapture(stack_capture))
    return;

  // If this fails we want to reclaim it.
  AddStackCaptureToReclaimedList(stack_capture);
}

void StackCaptureCache::AddStackCaptureToReclaimedList(
    StackCapture* stack_capture) {
#ifndef NDEBUG
  lock_.AssertAcquired();
#endif
  DCHECK(stack_capture != NULL);

  StackCapture** link = GetFirstFrameAsLink(stack_capture);
  size_t num_frames = stack_capture->max_num_frames();
  *link = reclaimed_[num_frames];
  reclaimed_[num_frames] = stack_capture;
  statistics_.frames_dead += stack_capture->max_num_frames();
}

}  // namespace asan
}  // namespace agent
