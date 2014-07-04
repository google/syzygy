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
// Implementation details for PageAllocator. This is not meant to be
// included directly.

#ifndef SYZYGY_AGENT_ASAN_PAGE_ALLOCATOR_IMPL_H_
#define SYZYGY_AGENT_ASAN_PAGE_ALLOCATOR_IMPL_H_

#include <windows.h>

#include <algorithm>

#include "base/logging.h"
#include "syzygy/agent/asan/constants.h"
#include "syzygy/common/align.h"

namespace agent {
namespace asan {

// Empty statistics helper.
template<> struct PageAllocatorStatisticsHelper<false> {
  void Lock() { }
  void Unlock() { }
  template<size_t PageAllocatorStatistics::*stat> void Increment(size_t) { }
  template<size_t PageAllocatorStatistics::*stat> void Decrement(size_t) { }
  void GetStatistics(PageAllocatorStatistics* stats) const {
    DCHECK_NE(static_cast<PageAllocatorStatistics*>(NULL), stats);
    ::memset(stats, 0, sizeof(*stats));
  }
};

// Actual statistics helper.
template<> struct PageAllocatorStatisticsHelper<true> {
  PageAllocatorStatisticsHelper() {
    ::memset(&stats, 0, sizeof(stats));
  }

  void Lock() { lock.Acquire(); }
  void Unlock() { lock.Release(); }

  template<size_t PageAllocatorStatistics::*member>
  void Increment(size_t amount) {
    lock.AssertAcquired();
    stats.*member += amount;
  }

  template<size_t PageAllocatorStatistics::*member>
  void Decrement(size_t amount) {
    lock.AssertAcquired();
    stats.*member -= amount;
  }

  void GetStatistics(PageAllocatorStatistics* stats) const {
    lock.AssertAcquired();
    DCHECK_NE(static_cast<PageAllocatorStatistics*>(NULL), stats);
    *stats = this->stats;
  }

  base::Lock lock;
  PageAllocatorStatistics stats;
};

template<size_t kObjectSize, size_t kMaxObjectCount, size_t kPageSize,
         bool kKeepStats>
PageAllocator<kObjectSize, kMaxObjectCount, kPageSize, kKeepStats>::
PageAllocator()
    : current_page_(NULL), current_object_(NULL), end_object_(NULL) {
  COMPILE_ASSERT(kObjectSize >= sizeof(uintptr_t), object_size_too_small);

  // There needs to be at least one object per page, and extra bytes for a
  // linked list pointer.
  page_size_ = std::max<size_t>(kPageSize,
                                kObjectSize + sizeof(void*));
  // Round this up to a multiple of the OS page size.
  page_size_ = common::AlignUp(page_size_, agent::asan::kPageSize);

  objects_per_page_ = (page_size_ - sizeof(void*)) / kObjectSize;

  // Clear the freelists.
  ::memset(free_, 0, sizeof(free_));
}

template<size_t kObjectSize, size_t kMaxObjectCount, size_t kPageSize,
         bool kKeepStats>
PageAllocator<kObjectSize, kMaxObjectCount, kPageSize, kKeepStats>::
~PageAllocator() {
  // Returns all pages to the OS.
  uint8* page = current_page_;
  while (page) {
    uint8* prev = page + page_size_ - sizeof(void*);
    uint8* next_page = *reinterpret_cast<uint8**>(prev);
    CHECK_EQ(TRUE, ::VirtualFree(page, 0, MEM_RELEASE));
    page = next_page;
  }
}

template<size_t kObjectSize, size_t kMaxObjectCount, size_t kPageSize,
         bool kKeepStats>
void* PageAllocator<kObjectSize, kMaxObjectCount, kPageSize, kKeepStats>::
Allocate(size_t count) {
  size_t received = 0;
  void* alloc = Allocate(count, &received);

  // If there were leftover objects in the allocation then shard it and
  // add them to the appropriate free list.
  if (count < received) {
    size_t n = received - count;
    uint8* remaining = reinterpret_cast<uint8*>(alloc) +
        kObjectSize * count;
    // These objects are part of an active allocation that are being returned.
    // Thus we don't decrement the number of allocated groups, but we do
    // decrement the number of allocated objects.
    FreePush(remaining, n, false, true);
  }

  return alloc;
}

template<size_t kObjectSize, size_t kMaxObjectCount, size_t kPageSize,
         bool kKeepStats>
void* PageAllocator<kObjectSize, kMaxObjectCount, kPageSize, kKeepStats>::
Allocate(size_t count, size_t* received) {
  DCHECK_LT(0u, count);
  DCHECK_GE(kMaxObjectCount, count);
  DCHECK_NE(static_cast<size_t*>(NULL), received);

  uint8* object = NULL;

  // Look to the lists of freed objects and try to use one of those. Use the
  // first one that's big enough, and stuff the leftover objects into another
  // freed list.
  for (size_t n = count; n <= kMaxObjectCount; ++n) {
    // This is racy and can end up lying to us. However, it's faster to first
    // check this outside of the lock. We do this properly afterwards.
    if (free_[n - 1] == NULL)
      continue;

    // Unlink the objects from the free list of size n.
    object = FreePop(n);
    if (object == NULL)
      continue;

    // Update statistics.
    stats_.Lock();
    stats_.Increment<&PageAllocatorStatistics::allocated_groups>(1);
    stats_.Increment<&PageAllocatorStatistics::allocated_objects>(n);
    stats_.Unlock();

    *received = n;
    return object;
  }

  // Get the object from a page. Try the active page first and allocate a new
  // one if need be.
  {
    base::AutoLock lock(lock_);

    // If the current page is not big enough for the requested allocation then
    // get a new page.
    DCHECK_LE(current_object_, end_object_);
    if (static_cast<size_t>(end_object_ - current_object_) <
            kObjectSize * count) {
      if (!AllocatePageLocked())
        return NULL;
    }

    DCHECK_NE(static_cast<uint8*>(NULL), current_page_);
    DCHECK_NE(static_cast<uint8*>(NULL), current_object_);
    DCHECK_LE(current_object_ + kObjectSize * count, end_object_);

    // Grab a copy of the cursor and advance it.
    object = current_object_;
    current_object_ += kObjectSize * count;
  }

  // Update statistics.
  stats_.Lock();
  stats_.Increment<&PageAllocatorStatistics::allocated_groups>(1);
  stats_.Increment<&PageAllocatorStatistics::allocated_objects>(count);
  stats_.Unlock();

  *received = count;
  return object;
}

template<size_t kObjectSize, size_t kMaxObjectCount, size_t kPageSize,
         bool kKeepStats>
void PageAllocator<kObjectSize, kMaxObjectCount, kPageSize, kKeepStats>::
Free(void* object, size_t count) {
  DCHECK_NE(static_cast<void*>(NULL), object);
  DCHECK_LT(0u, count);
  DCHECK_GE(kMaxObjectCount, count);

#ifndef NDEBUG
  // These checks are expensive so only run in debug builds.
  // Ensure that the object was actually allocated by this allocator.
  DCHECK(Allocated(object, count));
  // Ensure that it has not been freed.
  DCHECK(!Freed(object, count));
#endif

  // Add this object to the list of freed objects for this size class.
  // This is a simple allocation that is being returned so both allocated
  // groups and objects are decremented.
  FreePush(object, count, true, true);
}

template<size_t kObjectSize, size_t kMaxObjectCount, size_t kPageSize,
         bool kKeepStats>
bool PageAllocator<kObjectSize, kMaxObjectCount, kPageSize, kKeepStats>::
Allocated(const void* object, size_t count) {
  if (object == NULL || count == 0)
    return false;

  base::AutoLock lock(lock_);

  // Look for a page owning this object.
  const uint8* alloc = reinterpret_cast<const uint8*>(object);
  const uint8* alloc_end = alloc + count * kObjectSize;
  uint8* page = current_page_;
  while (page) {
    // Skip to the next page if it doesn't own this allocation.
    uint8* page_end = page + objects_per_page_ * kObjectSize;
    if (alloc < page || alloc_end > page_end) {
      page = *reinterpret_cast<uint8**>(page_end);
      continue;
    }

    // If the allocation hasn't yet been handed out then this page does not own
    // it.
    if (page == current_page_ && alloc_end > current_object_)
      return false;

    // Determine if it's aligned as expected.
    if (((alloc - page) % kObjectSize) != 0)
      return false;

    // This allocation must have been previously handed out at some point.
    // Note that this does not allow the detection of double frees. Nor does
    // it allow us to determine if the object was the return address of an
    // allocation, or simply lies somewhere within an allocated chunk.
    return true;
  }

  // The pages have been exhausted and no match was found.
  return false;
}

template<size_t kObjectSize, size_t kMaxObjectCount, size_t kPageSize,
         bool kKeepStats>
bool PageAllocator<kObjectSize, kMaxObjectCount, kPageSize, kKeepStats>::
Freed(const void* object, size_t count) {
  if (object == NULL)
    return false;

  DCHECK_NE(static_cast<void*>(NULL), object);

  // Determine the range of size classes to investigate.
  size_t n_min = 1;
  size_t n_max = kMaxObjectCount;
  if (count != 0) {
    n_min = count;
    n_max = count;
  }

  // Iterate over the applicable size classes.
  for (size_t n = n_min; n <= n_max; ++n) {
    base::AutoLock lock(free_lock_[n - 1]);

    // Walk the list for this size class.
    uint8* free = free_[n - 1];
    while (free) {
      if (object == free)
        return true;

      // Jump to the next freed object in this size class.
      free = *reinterpret_cast<uint8**>(free);
    }
  }

  // The freed objects have been exhausted and no match was found.
  return false;
}

template<size_t kObjectSize, size_t kMaxObjectCount, size_t kPageSize,
         bool kKeepStats>
void PageAllocator<kObjectSize, kMaxObjectCount, kPageSize, kKeepStats>::
GetStatistics(PageAllocatorStatistics* stats) {
  DCHECK_NE(static_cast<PageAllocatorStatistics*>(NULL), stats);

  stats_.Lock();
  stats_.GetStatistics(stats);
  stats_.Unlock();
}

template<size_t kObjectSize, size_t kMaxObjectCount, size_t kPageSize,
         bool kKeepStats>
uint8* PageAllocator<kObjectSize, kMaxObjectCount, kPageSize, kKeepStats>::
    FreePop(size_t count) {
  DCHECK_LT(0u, count);
  DCHECK_GE(kMaxObjectCount, count);

  uint8* object = NULL;
  {
    base::AutoLock lock(free_lock_[count - 1]);
    object = free_[count - 1];
    if (object)
      free_[count - 1] = *reinterpret_cast<uint8**>(object);
  }

  // Update statistics.
  stats_.Lock();
  stats_.Decrement<&PageAllocatorStatistics::freed_groups>(1);
  stats_.Decrement<&PageAllocatorStatistics::freed_objects>(count);
  stats_.Unlock();

  return object;
}

template<size_t kObjectSize, size_t kMaxObjectCount, size_t kPageSize,
         bool kKeepStats>
void PageAllocator<kObjectSize, kMaxObjectCount, kPageSize, kKeepStats>::
    FreePush(void* object, size_t count,
             bool decr_alloc_groups, bool decr_alloc_objects) {
  DCHECK_NE(static_cast<void*>(NULL), object);
  DCHECK_LT(0u, count);
  DCHECK_GE(kMaxObjectCount, count);

  {
    base::AutoLock lock(free_lock_[count - 1]);
    *reinterpret_cast<uint8**>(object) = free_[count - 1];
    free_[count - 1] = reinterpret_cast<uint8*>(object);
  }

  // Update statistics.
  stats_.Lock();
  if (decr_alloc_groups)
    stats_.Decrement<&PageAllocatorStatistics::allocated_groups>(1);
  if (decr_alloc_objects)
    stats_.Decrement<&PageAllocatorStatistics::allocated_objects>(count);
  stats_.Increment<&PageAllocatorStatistics::freed_groups>(1);
  stats_.Increment<&PageAllocatorStatistics::freed_objects>(count);
  stats_.Unlock();
}

template<size_t kObjectSize, size_t kMaxObjectCount, size_t kPageSize,
         bool kKeepStats>
bool PageAllocator<kObjectSize, kMaxObjectCount, kPageSize, kKeepStats>::
    AllocatePageLocked() {
  DCHECK_LT(0u, page_size_);
  lock_.AssertAcquired();

  // If there are remaining objects stuff them into the appropriately sized
  // free list.
  // NOTE: If this is a point of contention it could be moved to be outside
  //     the scoped of lock_.
  if (current_object_ < end_object_) {
    size_t n = reinterpret_cast<uint8*>(end_object_) -
        reinterpret_cast<uint8*>(current_object_);
    n /= kObjectSize;
    DCHECK_GE(kMaxObjectCount, n);
    // These are objects that have never been allocated, so don't affect the
    // number of allocated groups or objects.
    FreePush(current_object_, n, false, false);
  }

  uint8* page = reinterpret_cast<uint8*>(
      ::VirtualAlloc(NULL, page_size_, MEM_COMMIT, PAGE_READWRITE));
  if (page == NULL)
    return false;

  uint8* prev = page + page_size_ - sizeof(void*);
  end_object_ = common::AlignDown(prev, kObjectSize);

  // Keep a pointer to the previous page, and set up the next object pointer.
  *reinterpret_cast<uint8**>(prev) = current_page_;
  current_page_ = page;
  current_object_ = page;

  // Update statistics.
  // NOTE: This can also be moved out from under lock_.
  stats_.Lock();
  stats_.Increment<&PageAllocatorStatistics::page_count>(1);
  stats_.Unlock();

  return true;
}

template<typename ObjectType, size_t kMaxObjectCount, size_t kPageSize,
         bool kKeepStats>
ObjectType*
TypedPageAllocator<ObjectType, kMaxObjectCount, kPageSize, kKeepStats>::
    Allocate(size_t count) {
  DCHECK_LT(0u, count);
  DCHECK_GE(kMaxObjectCount, count);
  void* object = Super::Allocate(count);
  return reinterpret_cast<ObjectType*>(object);
}

template<typename ObjectType, size_t kMaxObjectCount, size_t kPageSize,
         bool kKeepStats>
ObjectType*
TypedPageAllocator<ObjectType, kMaxObjectCount, kPageSize, kKeepStats>::
    Allocate(size_t count, size_t* received) {
  DCHECK_LT(0u, count);
  DCHECK_GE(kMaxObjectCount, count);
  DCHECK_NE(static_cast<size_t*>(NULL), received);
  void* object = Super::Allocate(count, received);
  return reinterpret_cast<ObjectType*>(object);
}

template<typename ObjectType, size_t kMaxObjectCount, size_t kPageSize,
         bool kKeepStats>
void TypedPageAllocator<ObjectType, kMaxObjectCount, kPageSize, kKeepStats>::
    Free(ObjectType* object, size_t count) {
  DCHECK_NE(static_cast<ObjectType*>(NULL), object);
  DCHECK_LT(0u, count);
  DCHECK_GE(kMaxObjectCount, count);
  Super::Free(object, count);
}

}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_PAGE_ALLOCATOR_IMPL_H_
