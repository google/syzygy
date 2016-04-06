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

#include "base/lazy_instance.h"
#include "base/logging.h"
#include "base/strings/stringprintf.h"
#include "syzygy/agent/asan/logger.h"
#include "syzygy/agent/asan/memory_notifier.h"
#include "syzygy/agent/common/stack_capture.h"
#include "syzygy/common/align.h"

namespace agent {
namespace asan {

namespace {

static base::LazyInstance<common::StackCapture> g_empty_stack_capture =
    LAZY_INSTANCE_INITIALIZER;

// Gives us access to the first frame of a stack capture as link-list pointer.
common::StackCapture** GetFirstFrameAsLink(
    common::StackCapture* stack_capture) {
  DCHECK_NE(static_cast<common::StackCapture*>(nullptr), stack_capture);
  common::StackCapture** link = reinterpret_cast<common::StackCapture**>(
      const_cast<void**>(stack_capture->frames()));
  DCHECK_NE(static_cast<common::StackCapture**>(nullptr), link);
  return link;
}

}  // namespace

size_t StackCaptureCache::compression_reporting_period_ =
    ::common::kDefaultReportingPeriod;

StackCaptureCache::CachePage::~CachePage() {
}

// static
StackCaptureCache::CachePage* StackCaptureCache::CachePage::CreateInPlace(
    void* alloc, CachePage* link) {
  // Use a placement new.
  return new(alloc) CachePage(link);
}

common::StackCapture* StackCaptureCache::CachePage::GetNextStackCapture(
    size_t max_num_frames, size_t metadata_size) {
  metadata_size = ::common::AlignUp(metadata_size, sizeof(void*));

  size_t stack_size = common::StackCapture::GetSize(max_num_frames);
  size_t size = stack_size + metadata_size;
  if (bytes_used_ + size > kDataSize)
    return nullptr;

  // Use placement new for the StackCapture and zero initialize the metadata.
  common::StackCapture* stack =
      new(data_ + bytes_used_) common::StackCapture(max_num_frames);
  ::memset(data_ + bytes_used_ + stack_size, 0, metadata_size);

  // Update the allocation cursor.
  bytes_used_ += size;

  return stack;
}

common::StackCapture* StackCaptureCache::CachePage::GetNextStackCapture(
    size_t max_num_frames) {
  return GetNextStackCapture(max_num_frames, 0);
}

bool StackCaptureCache::CachePage::ReturnStackCapture(
    common::StackCapture* stack_capture, size_t metadata_size) {
  DCHECK_NE(static_cast<common::StackCapture*>(nullptr), stack_capture);

  metadata_size = ::common::AlignUp(metadata_size, sizeof(void*));

  uint8_t* stack = reinterpret_cast<uint8_t*>(stack_capture);
  size_t size = stack_capture->Size() + metadata_size;

  // If this was the last stack capture provided by this page then the end of
  // it must align with our current data pointer.
  if (data_ + bytes_used_ != stack + size)
    return false;

  bytes_used_ -= size;
  return true;
}

bool StackCaptureCache::CachePage::ReturnStackCapture(
    common::StackCapture* stack_capture) {
  return ReturnStackCapture(stack_capture, 0);
}

StackCaptureCache::StackCaptureCache(
    AsanLogger* logger, MemoryNotifierInterface* memory_notifier)
    : logger_(logger),
      memory_notifier_(memory_notifier),
      max_num_frames_(common::StackCapture::kMaxNumFrames),
      current_page_(nullptr) {
  DCHECK_NE(static_cast<AsanLogger*>(nullptr), logger);
  DCHECK_NE(static_cast<MemoryNotifierInterface*>(nullptr), memory_notifier);

  AllocateCachePage();

  ::memset(&statistics_, 0, sizeof(statistics_));
  ::memset(reclaimed_, 0, sizeof(reclaimed_));
  statistics_.size = sizeof(CachePage);
}

StackCaptureCache::StackCaptureCache(
    AsanLogger* logger, MemoryNotifierInterface* memory_notifier,
    size_t max_num_frames)
    : logger_(logger),
      memory_notifier_(memory_notifier),
      max_num_frames_(0),
      current_page_(nullptr) {
  DCHECK_NE(static_cast<AsanLogger*>(nullptr), logger);
  DCHECK_NE(static_cast<MemoryNotifierInterface*>(nullptr), memory_notifier);
  DCHECK_LT(0u, max_num_frames);
  max_num_frames_ = static_cast<uint8_t>(
      std::min(max_num_frames, common::StackCapture::kMaxNumFrames));

  AllocateCachePage();
  ::memset(&statistics_, 0, sizeof(statistics_));
  ::memset(reclaimed_, 0, sizeof(reclaimed_));
  statistics_.size = sizeof(CachePage);
}

StackCaptureCache::~StackCaptureCache() {
  // Clean up the linked list of cache pages.
  while (current_page_ != nullptr) {
    CachePage* page = current_page_;
    current_page_ = page->next_page_;
    page->next_page_ = nullptr;

    memory_notifier_->NotifyReturnedToOS(page, sizeof(*page));

    // This should have been allocated by VirtuaAlloc, so should be aligned.
    DCHECK(::common::IsAligned(page, GetPageSize()));
    CHECK_EQ(TRUE, ::VirtualFree(page, 0, MEM_RELEASE));
  }
}

void StackCaptureCache::Init() {
  compression_reporting_period_ = ::common::kDefaultReportingPeriod;
}

const common::StackCapture* StackCaptureCache::SaveStackTrace(
    const common::StackCapture& stack_capture) {
  auto frames = stack_capture.frames();
  auto num_frames = stack_capture.num_frames();
  auto absolute_stack_id = stack_capture.absolute_stack_id();
  DCHECK_NE(static_cast<void**>(nullptr), frames);
  DCHECK_NE(static_cast<CachePage*>(nullptr), current_page_);

  // If the number of frames is zero, the stack_capture was not captured
  // correctly. In that case, return an empty stack_capture. Otherwise, saving a
  // zero framed stack capture and then releasing it will lead to an explosion.
  if (!num_frames)
    return &g_empty_stack_capture.Get();

  bool already_cached = false;
  common::StackCapture* stack_trace = nullptr;
  bool saturated = false;

  {
    size_t known_stack_shard = absolute_stack_id % kKnownStacksSharding;
    // Get or insert the current stack trace while under the lock for this
    // bucket.
    base::AutoLock auto_lock(known_stacks_locks_[known_stack_shard]);

    // Check if the stack capture is already in the cache map.
    StackMap::iterator result =
        known_stacks_[known_stack_shard].find(absolute_stack_id);

    // If this capture has not already been cached then we have to initialize
    // the data.
    if (result == known_stacks_[known_stack_shard].end()) {
      stack_trace = GetStackCapture(num_frames);
      DCHECK_NE(static_cast<common::StackCapture*>(nullptr), stack_trace);
      stack_trace->InitFromExistingStack(stack_capture);
      auto result = known_stacks_[known_stack_shard].insert(
          std::make_pair(absolute_stack_id, stack_trace));
      DCHECK(result.second);
      DCHECK(stack_trace->HasNoRefs());
      FOR_EACH_OBSERVER(Observer, observer_list_, OnNewStack(stack_trace));
    } else {
      already_cached = true;
      stack_trace = result->second;
    }
    // Increment the reference count for this stack trace.
    if (!stack_trace->RefCountIsSaturated()) {
      stack_trace->AddRef();
    } else {
      saturated = true;
    }
  }
  DCHECK_NE(static_cast<common::StackCapture*>(nullptr), stack_trace);

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

void StackCaptureCache::ReleaseStackTrace(
    const common::StackCapture* stack_capture) {
  DCHECK_NE(static_cast<common::StackCapture*>(nullptr), stack_capture);

  if (!stack_capture->num_frames()) {
    DCHECK_EQ(&g_empty_stack_capture.Get(), stack_capture);
    return;
  }

  size_t known_stack_shard =
      stack_capture->absolute_stack_id() % kKnownStacksSharding;
  bool add_to_reclaimed_list = false;
  common::StackCapture* stack = nullptr;
  {
    base::AutoLock auto_lock(known_stacks_locks_[known_stack_shard]);

    // We own the stack so its fine to remove the const. We double check this
    // is the case in debug builds with the DCHECK.
    stack = const_cast<common::StackCapture*>(stack_capture);

    stack->RemoveRef();

    if (stack->HasNoRefs()) {
      add_to_reclaimed_list = true;
      // Remove this from the known stacks as we're going to reclaim it and
      // overwrite part of its data as we insert into the reclaimed_ list.
      size_t num_erased = known_stacks_[known_stack_shard].erase(
          stack_capture->absolute_stack_id());
      DCHECK_EQ(num_erased, 1u);
    }
  }

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

  // Link this stack capture into the list of reclaimed stacks. This
  // must come after the statistics updating, as we modify the |num_frames|
  // parameter in place.
  if (add_to_reclaimed_list)
    AddStackCaptureToReclaimedList(stack);
}

bool StackCaptureCache::StackCapturePointerIsValid(
    const common::StackCapture* stack_capture) {
  // All stack captures must have pointer alignment at least.
  if (!::common::IsAligned(stack_capture, sizeof(uintptr_t)))
    return false;

  const uint8_t* stack_capture_addr =
      reinterpret_cast<const uint8_t*>(stack_capture);

  // Walk over the allocated pages and see if it lands within any of them.
  base::AutoLock lock(current_page_lock_);
  CachePage* page = current_page_;
  while (page != nullptr) {
    const uint8_t* page_end = page->data() + page->bytes_used();

    // If the proposed stack capture lands within a page we then check to
    // ensure that it is also internally consistent. This can still fail
    // but is somewhat unlikely.
    static const size_t kMinSize = common::StackCapture::GetSize(1);
    if (stack_capture_addr >= page->data() &&
        stack_capture_addr + kMinSize <= page_end &&
        stack_capture_addr + stack_capture->Size() <= page_end &&
        stack_capture->num_frames() <= stack_capture->max_num_frames() &&
        stack_capture->max_num_frames() <=
            common::StackCapture::kMaxNumFrames) {
      return true;
    }
    page = page->next_page_;
  }
  return false;
}

void StackCaptureCache::AddObserver(Observer* obs) {
  observer_list_.AddObserver(obs);
}

void StackCaptureCache::RemoveObserver(Observer* obs) {
  observer_list_.RemoveObserver(obs);
}

void StackCaptureCache::LogStatistics()  {
  Statistics statistics = {};

  {
    base::AutoLock auto_lock(stats_lock_);
    GetStatisticsUnlocked(&statistics);
  }

  LogStatisticsImpl(statistics);
}

void StackCaptureCache::AllocateCachePage() {
  static_assert(sizeof(CachePage) % (64 * 1024) == 0,
                "kCachePageSize should be a multiple of the system allocation "
                "granularity.");

  void* new_page = ::VirtualAlloc(nullptr, sizeof(CachePage), MEM_COMMIT,
                                  PAGE_READWRITE);
  CHECK_NE(static_cast<void*>(nullptr), new_page);

  // Use a placement new and notify the shadow memory.
  current_page_ = CachePage::CreateInPlace(new_page, current_page_);
  memory_notifier_->NotifyInternalUse(new_page, sizeof(CachePage));
}

void StackCaptureCache::GetStatisticsUnlocked(Statistics* statistics) const {
#ifndef NDEBUG
  stats_lock_.AssertAcquired();
#endif

  DCHECK_NE(static_cast<Statistics*>(nullptr), statistics);
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

common::StackCapture* StackCaptureCache::GetStackCapture(size_t num_frames) {
  common::StackCapture* stack_capture = nullptr;

  // First look to the reclaimed stacks and try to use one of those. We'll use
  // the first one that's big enough.
  for (size_t n = num_frames; n <= max_num_frames_; ++n) {
    base::AutoLock lock(reclaimed_locks_[n]);
    if (reclaimed_[n] != nullptr) {
      common::StackCapture* reclaimed_stack_capture = reclaimed_[n];
      common::StackCapture** link =
          GetFirstFrameAsLink(reclaimed_stack_capture);
      reclaimed_[n] = *link;
      stack_capture = reclaimed_stack_capture;
      break;
    }
  }

  if (stack_capture != nullptr) {
    if (compression_reporting_period_ != 0) {
      base::AutoLock stats_lock(stats_lock_);
      // These frames are no longer dead, but in limbo. If the stack capture
      // is used they'll be added to frames_alive and frames_stored.
      statistics_.frames_dead -= stack_capture->max_num_frames();
    }
    return stack_capture;
  }

  common::StackCapture* unused_stack_capture = nullptr;
  {
    base::AutoLock current_page_lock(current_page_lock_);

    // We didn't find a reusable stack capture. Go to the cache page.
    stack_capture = current_page_->GetNextStackCapture(num_frames);

    if (stack_capture != nullptr)
      return stack_capture;

    // If the allocation failed we don't have enough room on the current page.

    // Use the remaining bytes to create one more maximally sized stack
    // capture. We will stuff this into the reclaimed_ structure for later
    // use.
    size_t bytes_left = current_page_->bytes_left();
    size_t max_num_frames = common::StackCapture::GetMaxNumFrames(bytes_left);
    if (max_num_frames > 0) {
      DCHECK_LT(max_num_frames, num_frames);
      DCHECK_LE(common::StackCapture::GetSize(max_num_frames), bytes_left);
      unused_stack_capture =
          current_page_->GetNextStackCapture(max_num_frames);
      DCHECK_NE(static_cast<common::StackCapture*>(nullptr),
                unused_stack_capture);
    }

    // Allocate a new page (that links to the current page) and use it to
    // allocate a new stack capture.
    AllocateCachePage();
    CHECK_NE(static_cast<CachePage*>(nullptr), current_page_);
    statistics_.size += sizeof(CachePage);
    stack_capture = current_page_->GetNextStackCapture(num_frames);
  }

  if (unused_stack_capture != nullptr) {
    // We're creating an unreferenced stack capture.
    AddStackCaptureToReclaimedList(unused_stack_capture);
  }

  // Update the statistics.
  if (compression_reporting_period_ != 0) {
    base::AutoLock stats_lock(stats_lock_);
    ++statistics_.unreferenced;
  }

  DCHECK_NE(static_cast<common::StackCapture*>(nullptr), stack_capture);
  return stack_capture;
}

namespace {

class PrivateStackCapture : public common::StackCapture {
 public:
  // Expose the actual number of frames. We use this to make reclaimed
  // stack captures look invalid when they're in a free list.
  using common::StackCapture::num_frames_;
};

}

void StackCaptureCache::AddStackCaptureToReclaimedList(
    common::StackCapture* stack_capture) {
  DCHECK_NE(static_cast<common::StackCapture*>(nullptr), stack_capture);

  // Make the stack capture internally inconsistent so that it can't be
  // interpreted as being valid. This is rewritten upon reuse so not
  // dangerous.
  reinterpret_cast<PrivateStackCapture*>(stack_capture)->num_frames_ =
      UINT8_MAX;

  {
    base::AutoLock lock(reclaimed_locks_[stack_capture->max_num_frames()]);

    common::StackCapture** link = GetFirstFrameAsLink(stack_capture);
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
