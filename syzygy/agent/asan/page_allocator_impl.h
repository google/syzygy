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

namespace detail {

// Empty statistics helper.
template<> struct PageAllocatorStatisticsHelper<false> {
  void Lock() { }
  void Unlock() { }
  template<size_t PageAllocatorStatistics::*stat> void Increment(size_t) { }
  template<size_t PageAllocatorStatistics::*stat> void Decrement(size_t) { }
  void GetStatistics(PageAllocatorStatistics* stats) const {
    DCHECK_NE(static_cast<PageAllocatorStatistics*>(nullptr), stats);
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
    DCHECK_NE(static_cast<PageAllocatorStatistics*>(nullptr), stats);
    *stats = this->stats;
  }

  base::Lock lock;
  PageAllocatorStatistics stats;
};

// This is the internal object type used by the page allocator. This allows
// easy free list chaining.
template<size_t kObjectSize>
struct PageAllocatorObject {
  typedef PageAllocatorObject<kObjectSize> Self;

  union {
    uint8_t object_data[kObjectSize];
    Self* next_free;
  };
};


template<size_t kMinPageSize>
struct PageAllocatorPageSize {
  // The kPageSize calculation below presumes a 64KB allocation
  // granularity. If this changes for whatever reason the logic needs
  // to be updated.
  static_assert(64 * 1024 == kUsualAllocationGranularity,
                "Logic out of sync with allocation granularity.");

  // Round up to the nearest multiple of the allocation granularity.
  static const size_t kSlabSize =
      (kMinPageSize + kUsualAllocationGranularity - 1) &
      ~(kUsualAllocationGranularity - 1);

  // Calculate a number of pages that divides the allocation granularity,
  // or that is a multiple of it.
  static const size_t kPageSize =
      (kMinPageSize <= (1<<12) ? (1<<12) :              // 4KB.
          (kMinPageSize <= (1<<13) ? (1<<13) :          // 8KB.
              (kMinPageSize <= (1<<14) ? (1<<14) :      // 16KB.
                  (kMinPageSize <= (1<<15) ? (1<<15) :  // 32KB.
                      kSlabSize))));
};

// The internal page type used by the page allocator. Allows easy page list
// chaining.
template<size_t kObjectSize, size_t kMinPageSize>
struct PageAllocatorPage {
  typedef PageAllocatorPage<kObjectSize, kMinPageSize> Self;
  typedef PageAllocatorObject<kObjectSize> Object;
  typedef PageAllocatorPageSize<kMinPageSize> PageSize;

  // The OS reserves virtual memory in chunks of 64KB, and backs them with real
  // memory with pages of 4KB. We want to use a page size that is a multiple of
  // 4KB, and a divisor of 64KB, or a multiple of 64KB.
  static const size_t kPageSize = PageSize::kPageSize;
  static const size_t kSlabSize = PageSize::kSlabSize;
  static const size_t kPagesPerSlab = kSlabSize / kPageSize;

  static const size_t kObjectsPerPage =
      (kPageSize - sizeof(void*)) / sizeof(Object);

  const Object* end() const {
    return objects + kObjectsPerPage;
  }

  union {
    struct {
      Object objects[kObjectsPerPage];
      Self* prev_page;
    };
    uint8_t unused[kPageSize];
  };
};

}  // namespace detail

template<size_t kObjectSize, size_t kMaxObjectCount, size_t kPageSize,
         bool kKeepStats>
PageAllocator<kObjectSize, kMaxObjectCount, kPageSize, kKeepStats>::
PageAllocator()
    : page_count_(0), slab_(nullptr), slab_cursor_(nullptr), page_(nullptr),
      object_(nullptr) {
  static_assert(kPageSize > kObjectSize,
                "Page size should be bigger than the object size.");
  static_assert(kObjectSize >= sizeof(uintptr_t), "Object size is too small.");
  static_assert(kObjectSize <= sizeof(Object), "Object is too small.");
  static_assert(sizeof(Object) < kObjectSize + 4, "Object is too large.");
  static_assert(kPageSize <= sizeof(Page), "Page is too small.");
  static_assert(sizeof(Page) % kUsualPageSize == 0, "Invalid page size.");

  // Clear the freelists.
  ::memset(free_, 0, sizeof(free_));
}

template<size_t kObjectSize, size_t kMaxObjectCount, size_t kPageSize,
         bool kKeepStats>
PageAllocator<kObjectSize, kMaxObjectCount, kPageSize, kKeepStats>::
~PageAllocator() {
  // Iterate over the pages and make not of the slab addresses. These will
  // be pages whose root address a multiple of the allocation granulairty.
  Page* page = page_;
  size_t page_count = 0;
  size_t slab_count = 0;
  while (page) {
    // Pages are chained in reverse order, and allocated moving forward through
    // a slab. Thus it is safe for us to remove the entire slab when we
    // encounter the first page within it, as we'll already have iterated
    // through the other pages in the slab.
    ++page_count;
    Page* prev_page = page->prev_page;
    if (::common::IsAligned(page, kUsualAllocationGranularity)) {
      ++slab_count;
      CHECK_EQ(TRUE, ::VirtualFree(page, 0, MEM_RELEASE));
    }
    page = prev_page;
  }
  DCHECK_EQ(page_count_, page_count);

  // Determine how many slabs we expected to see and confirm that we saw that
  // many.
  size_t expected_slab_count = (page_count + Page::kPagesPerSlab - 1) /
      Page::kPagesPerSlab;
  DCHECK_EQ(expected_slab_count, slab_count);
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
    Object* remaining = reinterpret_cast<Object*>(alloc) + count;
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
  DCHECK_NE(static_cast<size_t*>(nullptr), received);

  void* object = nullptr;

  // Look to the lists of freed objects and try to use one of those. Use the
  // first one that's big enough, and stuff the leftover objects into another
  // freed list.
  for (size_t n = count; n <= kMaxObjectCount; ++n) {
    // This is racy and can end up lying to us. However, it's faster to first
    // check this outside of the lock. We do this properly afterwards.
    if (free_[n - 1] == nullptr)
      continue;

    // Unlink the objects from the free list of size n. This actually acquires
    // the appropriate free-list lock.
    object = FreePop(n);
    if (object == nullptr)
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
    if (page_ == nullptr || page_->end() - object_ < count) {
      if (!AllocatePageLocked())
        return nullptr;
    }

    DCHECK_NE(static_cast<Page*>(nullptr), page_);
    DCHECK_LT(object_, page_->end());

    // Grab a copy of the cursor and advance it.
    object = object_;
    object_ += count;
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
  DCHECK_NE(static_cast<void*>(nullptr), object);
  DCHECK_LT(0u, count);
  DCHECK_GE(kMaxObjectCount, count);

#ifndef NDEBUG
  // These checks are expensive so only run in debug builds.
  // Ensure the block is currently allocated by the allocator.
  DCHECK_EQ(1, AllocationStatus(object, count));
#endif

  // Add this object to the list of freed objects for this size class.
  // This is a simple allocation that is being returned so both allocated
  // groups and objects are decremented.
  FreePush(reinterpret_cast<Object*>(object), count, true, true);
}

template<size_t kObjectSize, size_t kMaxObjectCount, size_t kPageSize,
         bool kKeepStats>
void PageAllocator<kObjectSize, kMaxObjectCount, kPageSize, kKeepStats>::
GetStatistics(PageAllocatorStatistics* stats) {
  DCHECK_NE(static_cast<PageAllocatorStatistics*>(nullptr), stats);

  stats_.Lock();
  stats_.GetStatistics(stats);
  stats_.Unlock();
}

template<size_t kObjectSize, size_t kMaxObjectCount, size_t kPageSize,
         bool kKeepStats>
int PageAllocator<kObjectSize, kMaxObjectCount, kPageSize, kKeepStats>::
AllocationStatus(const void* object, size_t count) {
  // If the memory was never allocated then it's under management.
  if (!WasOnceAllocated(object, count))
    return -1;
  // The memory has been allocated, but it may since have been freed.
  if (IsInFreeList(object, count))
    return 0;
  // It's been allocated and it's not in the freed list. Must still be
  // a valid allocation!
  return 1;
}

template<size_t kObjectSize, size_t kMaxObjectCount, size_t kPageSize,
         bool kKeepStats>
bool PageAllocator<kObjectSize, kMaxObjectCount, kPageSize, kKeepStats>::
WasOnceAllocated(const void* object, size_t count) {
  if (object == nullptr || count == 0)
    return false;

  base::AutoLock lock(lock_);

  // Look for a page owning this object.
  const Object* object_begin = reinterpret_cast<const Object*>(object);
  const Object* object_end = object_begin + count;
  Page* page = page_;
  while (page) {
    // If this page does not contain the objects entirely, then skip to the next
    // page.
    if (object_begin < page->objects || object_end > page->end()) {
      page = page->prev_page;
      continue;
    }

    // If the allocation hasn't yet been handed out then this page does not own
    // it.
    if (page == page_ && object_end > object_)
      return false;

    // Determine if it's aligned as expected.
    size_t offset = reinterpret_cast<const uint8_t*>(object) -
                    reinterpret_cast<const uint8_t*>(page);
    if ((offset % sizeof(Object)) != 0)
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
IsInFreeList(const void* object, size_t count) {
  if (object == nullptr)
    return false;

  DCHECK_NE(static_cast<void*>(nullptr), object);

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
    Object* free = free_[n - 1];
    while (free) {
      if (free == object)
        return true;

      // Jump to the next freed object in this size class.
      free = free->next_free;
    }
  }

  // The freed objects have been exhausted and no match was found.
  return false;
}

template<size_t kObjectSize, size_t kMaxObjectCount, size_t kPageSize,
         bool kKeepStats>
typename
PageAllocator<kObjectSize, kMaxObjectCount, kPageSize, kKeepStats>::Object*
PageAllocator<kObjectSize, kMaxObjectCount, kPageSize, kKeepStats>::
    FreePop(size_t count) {
  DCHECK_LT(0u, count);
  DCHECK_GE(kMaxObjectCount, count);

  Object* object = nullptr;
  {
    base::AutoLock lock(free_lock_[count - 1]);
    object = free_[count - 1];
    if (object)
      free_[count - 1] = object->next_free;
  }
  object->next_free = nullptr;

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
    FreePush(Object* object, size_t count,
             bool decr_alloc_groups, bool decr_alloc_objects) {
  DCHECK_NE(static_cast<void*>(nullptr), object);
  DCHECK_LT(0u, count);
  DCHECK_GE(kMaxObjectCount, count);

  {
    base::AutoLock lock(free_lock_[count - 1]);
    object->next_free = free_[count - 1];
    free_[count - 1] = object;
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
  lock_.AssertAcquired();

  // If there are remaining objects stuff them into the appropriately sized
  // free list.
  // NOTE: If this is a point of contention it could be moved to be outside
  //     the scoped of lock_.
  if (page_ && object_ < page_->end()) {
    size_t n = page_->end() - object_;
    DCHECK_LT(0u, n);
    DCHECK_GE(kMaxObjectCount, n);

    // These are objects that have never been allocated, so don't affect the
    // number of allocated groups or objects.
    FreePush(object_, n, false, false);
  }

  Page* slab_end = slab_ + Page::kPagesPerSlab;

  // Grab a new slab if needed.
  if (slab_ == nullptr || slab_cursor_ >= slab_end) {
    void* slab = ::VirtualAlloc(
        nullptr, Page::kSlabSize, MEM_RESERVE, PAGE_NOACCESS);
    if (slab == nullptr)
      return false;

    // Update the slab and next page cursor.
    slab_ = reinterpret_cast<Page*>(slab);
    slab_cursor_ = slab_;
  }

  // Commit the next page. If this fails to commit we simply explode.
  Page* page = reinterpret_cast<Page*>(::VirtualAlloc(
      slab_cursor_, sizeof(Page), MEM_COMMIT, PAGE_READWRITE));
  if (page == nullptr)
    return false;
  DCHECK_EQ(page, slab_cursor_);

  // Update the slab cursor.
  ++slab_cursor_;

  // Keep a pointer to the previous page, and set up the next object pointer.
  page->prev_page = page_;
  page_ = page;
  object_ = page->objects;
  ++page_count_;

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
  DCHECK_NE(static_cast<size_t*>(nullptr), received);
  void* object = Super::Allocate(count, received);
  return reinterpret_cast<ObjectType*>(object);
}

template<typename ObjectType, size_t kMaxObjectCount, size_t kPageSize,
         bool kKeepStats>
void TypedPageAllocator<ObjectType, kMaxObjectCount, kPageSize, kKeepStats>::
    Free(ObjectType* object, size_t count) {
  DCHECK_NE(static_cast<ObjectType*>(nullptr), object);
  DCHECK_LT(0u, count);
  DCHECK_GE(kMaxObjectCount, count);
  Super::Free(object, count);
}

}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_PAGE_ALLOCATOR_IMPL_H_
