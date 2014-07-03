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

template<size_t kObjectSize, size_t kObjectsPerPage>
class TestPageAllocator : public PageAllocator<kObjectSize, kObjectsPerPage> {
 public:
  typedef PageAllocator<kObjectSize, kObjectsPerPage> Super;

  using Super::AllocatePage;
  using Super::Allocated;
  using Super::Freed;
  using Super::page_size_;
  using Super::current_page_;
  using Super::current_object_;
  using Super::end_object_;
  using Super::free_;
};

// There are 256 16-byte objects in a 4KB page, so requesting 250 objects
// should give us 255 of them.
typedef TestPageAllocator<16, 250> TestPageAllocator250;

// There are 512 16-byte objects in 2 4KB pages, so requesting 500 objects
// should give us 510 of them.
typedef TestPageAllocator<16, 500> TestPageAllocator500;

}  // namespace

TEST(PageAllocatorTest, PageSizeCalculationIsCorrect) {
  TestPageAllocator250 pa250;
  EXPECT_EQ(4096, pa250.page_size_);

  TestPageAllocator500 pa500;
  EXPECT_EQ(8192, pa500.page_size_);
}

TEST(PageAllocatorTest, Constructor) {
  TestPageAllocator250 pa;
  EXPECT_TRUE(pa.current_page_ == NULL);
  EXPECT_TRUE(pa.current_object_ == NULL);
  EXPECT_TRUE(pa.free_ == NULL);
}

TEST(PageAllocatorTest, AllocatePage) {
  TestPageAllocator250 pa;
  EXPECT_TRUE(pa.current_page_ == NULL);
  EXPECT_TRUE(pa.current_object_ == NULL);

  pa.AllocatePage();
  EXPECT_TRUE(pa.current_page_ != NULL);
  EXPECT_TRUE(pa.current_object_ != NULL);
  EXPECT_EQ(reinterpret_cast<uint8*>(pa.current_page_),
            reinterpret_cast<uint8*>(pa.current_object_));
}

TEST(PageAllocatorTest, SuccessiveAllocations) {
  TestPageAllocator250 pa;
  EXPECT_TRUE(pa.current_page_ == NULL);
  EXPECT_TRUE(pa.current_object_ == NULL);

  pa.AllocatePage();
  for (size_t i = 0; i < 255; ++i) {
    EXPECT_EQ(reinterpret_cast<uint8*>(pa.current_page_) + i * 16,
              reinterpret_cast<uint8*>(pa.current_object_));
    void* current_object = pa.current_object_;
    EXPECT_EQ(current_object, pa.Allocate());
  }
  EXPECT_GE(pa.current_object_, pa.end_object_);

  void* current_page = pa.current_page_;
  pa.Allocate();
  EXPECT_NE(current_page, pa.current_page_);
  EXPECT_EQ(reinterpret_cast<uint8*>(pa.current_page_) + 16,
            reinterpret_cast<uint8*>(pa.current_object_));

  void* prev = reinterpret_cast<uint8*>(pa.current_page_) + pa.page_size_ -
      sizeof(void*);
  EXPECT_EQ(current_page, *reinterpret_cast<void**>(prev));
}

TEST(PageAllocatorTest, AllocsAndFrees) {
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

  TestPageAllocator250 pa;
  for (size_t i = 0; i < arraysize(kSizes); ++i) {
    if ((i % 2) == 0) {
      // Allocating.
      for (size_t j = 0; j < kSizes[i]; ++j) {
        void* alloc = pa.Allocate();
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
        allocated.erase(alloc);
        pa.Free(alloc);
        EXPECT_EQ(0u, freed.count(alloc));
        freed.insert(alloc);
      }
    }

    std::set<void*>::const_iterator it;
    for (it = allocated.begin(); it != allocated.end(); ++it)
      EXPECT_TRUE(pa.Allocated(*it));
    for (it = freed.begin(); it != freed.end(); ++it)
      EXPECT_TRUE(pa.Freed(*it));
  }
}

TEST(TypedPageAllocatorTest, EndToEnd) {
  TypedPageAllocator<uint32, 1000> pa;
  for (size_t i = 0; i < 1600; ++i) {
    uint32* alloc = pa.Allocate();
    if ((i % 3) == 0)
      pa.Free(alloc);
  }
}

}  // namespace asan
}  // namespace agent
