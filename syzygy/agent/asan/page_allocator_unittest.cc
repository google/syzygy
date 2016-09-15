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

#include "syzygy/agent/asan/page_allocator.h"

#include "gtest/gtest.h"

namespace agent {
namespace asan {

namespace {

template<size_t kObjectSize,
         size_t kMaxObjectCount,
         size_t kPageSize>
class TestPageAllocator
    : public PageAllocator<kObjectSize, kMaxObjectCount, kPageSize, true> {
 public:
  typedef PageAllocator<kObjectSize, kMaxObjectCount, kPageSize, true>
      Super;

  void AllocatePage() {
    base::AutoLock lock(lock_);
    AllocatePageLocked();
  }

  // Counts the number of free objects by iterating over the lists.
  // If |count| is 0 then counts all free objects, otherwise only counts
  // those in the given size class.
  size_t FreeObjects(size_t count) {
    size_t n_min = 1;
    size_t n_max = kMaxObjectCount;
    if (count != 0) {
      n_min = count;
      n_max = count;
    }

    size_t free_objects = 0;
    for (size_t n = n_min; n <= n_max; ++n) {
      Object* free = free_[n - 1];
      while (free) {
        free_objects += n;
        free = free->next_free;
      }
    }

    return free_objects;
  }

  const PageAllocatorStatistics& stats() {
    return stats_.stats;
  }

  using Super::AllocatePageLocked;
  using Super::page_;
  using Super::object_;
  using Super::free_;
};

template<typename ObjectType,
         size_t kMaxObjectCount,
         size_t kPageSize>
class TestTypedPageAllocator
    : public TypedPageAllocator<ObjectType, kMaxObjectCount, kPageSize, true> {
 public:
  typedef TypedPageAllocator<ObjectType, kMaxObjectCount, kPageSize, true>
      Super;

  const PageAllocatorStatistics& stats() {
    return stats_.stats;
  }
};

// There are 256 16-byte objects in a 4KB page, so we should get 255 objects.
typedef TestPageAllocator<16, 1, 4096> TestPageAllocator255;
typedef TestPageAllocator<16, 10, 4096> TestPageAllocatorMulti255;

}  // namespace

TEST(PageAllocatorTest, Constructor) {
  TestPageAllocator255 pa;
  EXPECT_EQ(255, TestPageAllocator255::Page::kObjectsPerPage);
  EXPECT_TRUE(pa.page_ == nullptr);
  EXPECT_TRUE(pa.object_ == nullptr);
  EXPECT_TRUE(pa.free_[0] == nullptr);

  TestPageAllocatorMulti255 mpa;
  EXPECT_EQ(255, TestPageAllocatorMulti255::Page::kObjectsPerPage);
  EXPECT_TRUE(mpa.page_ == nullptr);
  EXPECT_TRUE(mpa.object_ == nullptr);
  for (size_t i = 0; i < arraysize(mpa.free_); ++i)
    EXPECT_TRUE(mpa.free_[i] == nullptr);
}

TEST(PageAllocatorTest, AllocatePage) {
  TestPageAllocator255 pa;
  EXPECT_TRUE(pa.page_ == nullptr);
  EXPECT_TRUE(pa.object_ == nullptr);
  EXPECT_EQ(0u, pa.stats().page_count);

  pa.AllocatePage();
  EXPECT_FALSE(pa.page_ == nullptr);
  EXPECT_FALSE(pa.object_ == nullptr);
  EXPECT_EQ(pa.page_->objects, pa.object_);
  EXPECT_EQ(1u, pa.stats().page_count);
}

TEST(PageAllocatorTest, Allocated) {
  TestPageAllocator255 pa;
  EXPECT_TRUE(pa.page_ == nullptr);
  EXPECT_TRUE(pa.object_ == nullptr);
  EXPECT_EQ(0u, pa.stats().page_count);

  std::vector<void*> allocs;
  allocs.reserve(300);
  for (size_t i = 0; i < 300; ++i) {
    void* alloc = pa.Allocate(1);
    EXPECT_TRUE(pa.Allocated(alloc, 1));
    EXPECT_FALSE(pa.Freed(alloc, 1));
    allocs.push_back(alloc);
  }
  EXPECT_EQ(2u, pa.stats().page_count);

  for (size_t i = 0; i < 300; ++i) {
    size_t index = ::rand() % allocs.size();
    void* alloc = allocs[index];
    allocs[index] = allocs.back();
    allocs.pop_back();
    EXPECT_TRUE(pa.Allocated(alloc, 1));
    EXPECT_FALSE(pa.Freed(alloc, 1));
  }
}

TEST(PageAllocatorTest, SuccessiveSingleAllocations) {
  TestPageAllocator255 pa;
  EXPECT_TRUE(pa.page_ == nullptr);
  EXPECT_TRUE(pa.object_ == nullptr);
  EXPECT_EQ(0u, pa.stats().page_count);

  pa.AllocatePage();
  for (size_t i = 0; i < 255; ++i) {
    EXPECT_EQ(pa.page_->objects + i, pa.object_);
    void* current_object = pa.object_;
    EXPECT_EQ(current_object, pa.Allocate(1));
    EXPECT_EQ(i + 1, pa.stats().allocated_groups);
    EXPECT_EQ(i + 1, pa.stats().allocated_objects);
    EXPECT_EQ(0u, pa.stats().freed_groups);
    EXPECT_EQ(0u, pa.stats().freed_objects);
  }
  EXPECT_EQ(pa.object_, pa.page_->end());
  EXPECT_EQ(1u, pa.stats().page_count);

  TestPageAllocator255::Page* current_page = pa.page_;
  pa.Allocate(1);
  EXPECT_NE(current_page, pa.page_);
  EXPECT_EQ(pa.page_->objects + 1, pa.object_);
  EXPECT_EQ(2u, pa.stats().page_count);
  EXPECT_EQ(current_page, pa.page_->prev_page);
}

TEST(PageAllocatorTest, SingleStatsTest) {
  TestPageAllocator255 pa;

  EXPECT_EQ(0u, pa.stats().page_count);
  EXPECT_EQ(0u, pa.stats().allocated_groups);
  EXPECT_EQ(0u, pa.stats().allocated_objects);
  EXPECT_EQ(0u, pa.stats().freed_groups);
  EXPECT_EQ(0u, pa.stats().freed_objects);

  void* a1 = pa.Allocate(1);
  EXPECT_EQ(1u, pa.stats().page_count);
  EXPECT_EQ(1u, pa.stats().allocated_groups);
  EXPECT_EQ(1u, pa.stats().allocated_objects);
  EXPECT_EQ(0u, pa.stats().freed_groups);
  EXPECT_EQ(0u, pa.stats().freed_objects);

  void* a2 = pa.Allocate(1);
  EXPECT_EQ(1u, pa.stats().page_count);
  EXPECT_EQ(2u, pa.stats().allocated_groups);
  EXPECT_EQ(2u, pa.stats().allocated_objects);
  EXPECT_EQ(0u, pa.stats().freed_groups);
  EXPECT_EQ(0u, pa.stats().freed_objects);

  pa.Free(a1, 1);
  EXPECT_EQ(1u, pa.stats().page_count);
  EXPECT_EQ(1u, pa.stats().allocated_groups);
  EXPECT_EQ(1u, pa.stats().allocated_objects);
  EXPECT_EQ(1u, pa.stats().freed_groups);
  EXPECT_EQ(1u, pa.stats().freed_objects);

  pa.Free(a2, 1);
  EXPECT_EQ(1u, pa.stats().page_count);
  EXPECT_EQ(0u, pa.stats().allocated_groups);
  EXPECT_EQ(0u, pa.stats().allocated_objects);
  EXPECT_EQ(2u, pa.stats().freed_groups);
  EXPECT_EQ(2u, pa.stats().freed_objects);
}

TEST(PageAllocatorTest, SingleAllocsAndFrees) {
  std::set<void*> allocated, freed;

  // Runs of allocations/frees to perform.
  static const size_t kSizes[] = {
    12, 10,   // 12 high water, 2 allocated, 10 freed.
    33, 15,   // 35 high water, 20 allocated, 15 freed.
    100, 80,  // 120 high water, 40 allocated, 80 freed.
    1, 10,    // 120 high water, 31 allocated, 89 freed.
    5, 7,     // 120 high water, 29 allocated, 91 freed.
    100, 80,  // 129 high water, 49 allocated, 80 freed.
    10, 59,   // 129 high water, 0 allocated, 129 freed.
  };

  TestPageAllocator255 pa;
  for (size_t i = 0; i < arraysize(kSizes); ++i) {
    if ((i % 2) == 0) {
      // Allocating.
      for (size_t j = 0; j < kSizes[i]; ++j) {
        void* alloc = pa.Allocate(1);
        EXPECT_TRUE(pa.Allocated(alloc, 1));
        EXPECT_FALSE(pa.Freed(alloc, 1));
        EXPECT_EQ(0u, allocated.count(alloc));
        allocated.insert(alloc);

        if (!freed.empty()) {
          EXPECT_EQ(1u, freed.count(alloc));
          freed.erase(alloc);
        }
      }
    } else {
      EXPECT_LE(kSizes[i], allocated.size());
      // Freeing.
      for (size_t j = 0; j < kSizes[i]; ++j) {
        void* alloc = *allocated.begin();
        EXPECT_TRUE(pa.Allocated(alloc, 1));
        EXPECT_FALSE(pa.Freed(alloc, 1));
        allocated.erase(alloc);
        pa.Free(alloc, 1);
        EXPECT_FALSE(pa.Allocated(alloc, 1));
        EXPECT_TRUE(pa.Freed(alloc, 1));
        EXPECT_EQ(0u, freed.count(alloc));
        freed.insert(alloc);
      }
    }

    std::set<void*>::const_iterator it;
    for (it = allocated.begin(); it != allocated.end(); ++it) {
      EXPECT_TRUE(pa.Allocated(*it, 1));
      EXPECT_FALSE(pa.Freed(*it, 1));
    }
    for (it = freed.begin(); it != freed.end(); ++it) {
      EXPECT_FALSE(pa.Allocated(*it, 1));
      EXPECT_TRUE(pa.Freed(*it, 1));
    }
  }

  EXPECT_EQ(129u, pa.FreeObjects(1));
}

TEST(PageAllocatorTest, MultiAllocsAndFrees) {
  TestPageAllocatorMulti255 pa;
  EXPECT_EQ(0u, pa.stats().page_count);

  void* a = pa.Allocate(10);
  void* a_orig = a;
  EXPECT_EQ(1u, pa.stats().page_count);
  EXPECT_EQ(0u, pa.FreeObjects(0));

  pa.Free(a, 10);
  EXPECT_EQ(1u, pa.stats().page_count);
  EXPECT_EQ(10u, pa.FreeObjects(0));  // All size classes.
  EXPECT_EQ(10u, pa.FreeObjects(10));  // Length 10 allocations only.

  // Allocating again should reuse the freed allocation.
  size_t r = 0;
  a = pa.Allocate(8, &r);
  EXPECT_EQ(a_orig, a);
  EXPECT_EQ(10u, r);
  EXPECT_EQ(1u, pa.stats().page_count);
  EXPECT_EQ(0u, pa.FreeObjects(0));

  pa.Free(a, r);
  EXPECT_EQ(1u, pa.stats().page_count);
  EXPECT_EQ(10u, pa.FreeObjects(0));  // All size classes.
  EXPECT_EQ(10u, pa.FreeObjects(10));  // Length 10 allocations only.

  // Allocated should use the freed allocation, and add the remainder to a
  // shorter free list.
  a = pa.Allocate(8);
  EXPECT_EQ(a_orig, a);
  EXPECT_EQ(1u, pa.stats().page_count);
  EXPECT_EQ(2u, pa.FreeObjects(0));  // All size classes.
  EXPECT_EQ(2u, pa.FreeObjects(2));  // Length 2 allocations only.

  // The remainder should now be used.
  a = pa.Allocate(2);
  void* a_expected = reinterpret_cast<uint8_t*>(a_orig) + 16 * 8;
  EXPECT_EQ(a_expected, a);
  EXPECT_EQ(1u, pa.stats().page_count);
  EXPECT_EQ(0u, pa.FreeObjects(0));
}

TEST(PageAllocatorTest, MultiStatsTest) {
  TestPageAllocatorMulti255 pa;

  EXPECT_EQ(0u, pa.stats().page_count);
  EXPECT_EQ(0u, pa.stats().allocated_groups);
  EXPECT_EQ(0u, pa.stats().allocated_objects);
  EXPECT_EQ(0u, pa.stats().freed_groups);
  EXPECT_EQ(0u, pa.stats().freed_objects);

  void* a1 = pa.Allocate(10);
  EXPECT_EQ(1u, pa.stats().page_count);
  EXPECT_EQ(1u, pa.stats().allocated_groups);
  EXPECT_EQ(10u, pa.stats().allocated_objects);
  EXPECT_EQ(0u, pa.stats().freed_groups);
  EXPECT_EQ(0u, pa.stats().freed_objects);

  void* a2 = pa.Allocate(5);
  EXPECT_EQ(1u, pa.stats().page_count);
  EXPECT_EQ(2u, pa.stats().allocated_groups);
  EXPECT_EQ(15u, pa.stats().allocated_objects);
  EXPECT_EQ(0u, pa.stats().freed_groups);
  EXPECT_EQ(0u, pa.stats().freed_objects);

  pa.Free(a1, 10);
  EXPECT_EQ(1u, pa.stats().page_count);
  EXPECT_EQ(1u, pa.stats().allocated_groups);
  EXPECT_EQ(5u, pa.stats().allocated_objects);
  EXPECT_EQ(1u, pa.stats().freed_groups);
  EXPECT_EQ(10u, pa.stats().freed_objects);

  pa.Free(a2, 5);
  EXPECT_EQ(1u, pa.stats().page_count);
  EXPECT_EQ(0u, pa.stats().allocated_groups);
  EXPECT_EQ(0u, pa.stats().allocated_objects);
  EXPECT_EQ(2u, pa.stats().freed_groups);
  EXPECT_EQ(15u, pa.stats().freed_objects);

  // This will take from the allocation of size 10,
  // and create a free group of size 3.
  a1 = pa.Allocate(7);
  EXPECT_EQ(1u, pa.stats().page_count);
  EXPECT_EQ(1u, pa.stats().allocated_groups);
  EXPECT_EQ(7u, pa.stats().allocated_objects);
  EXPECT_EQ(2u, pa.stats().freed_groups);
  EXPECT_EQ(8u, pa.stats().freed_objects);

  // This will take from the free group of size 5,
  // returning one more element than requested.
  size_t received = 0;
  a2 = pa.Allocate(4, &received);
  EXPECT_EQ(5u, received);
  EXPECT_EQ(1u, pa.stats().page_count);
  EXPECT_EQ(2u, pa.stats().allocated_groups);
  EXPECT_EQ(12u, pa.stats().allocated_objects);
  EXPECT_EQ(1u, pa.stats().freed_groups);
  EXPECT_EQ(3u, pa.stats().freed_objects);
}

TEST(PageAllocatorTest, MultiSlabsPagesSmallerThanAllocGranularity) {
  typedef PageAllocator<16, 1, 32 * 1024, false> PA;
  PA pa;

  EXPECT_EQ(2u, PA::Page::kPagesPerSlab);
  EXPECT_EQ(64 * 1024, PA::Page::kSlabSize);
  EXPECT_EQ(32 * 1024, PA::Page::kPageSize);
  EXPECT_EQ(32 * 1024, sizeof(PA::Page));
  EXPECT_EQ(2 * 1024 - 1, PA::Page::kObjectsPerPage);

  // We can fit 2047 objects per page, and 2 pages per 64KB slab. So we need
  // to allocate nearly 10000 objects before we'll be certain that 2 slabs have
  // been allocated, each containing 2 pages.
  for (size_t i = 0; i < 10000; ++i)
    pa.Allocate(1);
}

TEST(PageAllocatorTest, MultiSlabsPagesBiggerThanAllGranularity) {
  typedef PageAllocator<16, 1, 70 * 1024, false> PA;
  PA pa;

  EXPECT_EQ(1u, PA::Page::kPagesPerSlab);
  EXPECT_EQ(128 * 1024, PA::Page::kSlabSize);
  EXPECT_EQ(128 * 1024, PA::Page::kPageSize);
  EXPECT_EQ(128 * 1024, sizeof(PA::Page));
  EXPECT_EQ(8 * 1024 - 1, PA::Page::kObjectsPerPage);

  // We can over 16K objects per page/slab so we need to allocate at least 35K
  // objects before we're certain that 2 slabs will have been allocated.
  for (size_t i = 0; i < 35000; ++i)
    pa.Allocate(1);
}

TEST(TypedPageAllocatorTest, SingleEndToEnd) {
  TypedPageAllocator<size_t, 1, 1000, true> pa;
  for (size_t i = 0; i < 1600; ++i) {
    size_t* alloc = pa.Allocate(1);
    if ((i % 3) == 0)
      pa.Free(alloc, 1);
  }
}

TEST(TypedPageAllocatorTest, MultiEndToEnd) {
  TypedPageAllocator<size_t, 10, 1000, true> pa;
  for (size_t i = 0; i < 100; ++i) {
    size_t requested = (i % 10) + 1;
    size_t received = 0;
    size_t* alloc = pa.Allocate(requested, &received);
    if ((i % 3) == 0)
      pa.Free(alloc, received);
  }

  for (size_t i = 0; i < 100; ++i) {
    size_t requested = (i % 10) + 1;
    size_t* alloc = pa.Allocate(requested);
    if ((i % 3) == 0)
      pa.Free(alloc, requested);
  }
}

}  // namespace asan
}  // namespace agent
