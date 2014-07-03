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

template<size_t kObjectSize, size_t kObjectsPerPage>
PageAllocator<kObjectSize, kObjectsPerPage>::PageAllocator()
    : current_page_(NULL), current_object_(NULL), end_object_(NULL),
      free_(NULL) {
  COMPILE_ASSERT(kObjectSize >= sizeof(uintptr_t), object_size_too_small);

  // There needs to be at least one object per page, and extra bytes for a
  // linked list pointer.
  page_size_ = std::max<size_t>(kObjectsPerPage, 1);
  page_size_ *= kObjectSize;
  page_size_ += sizeof(void*);
  page_size_ = common::AlignUp(page_size_, agent::asan::kPageSize);
}

template<size_t kObjectSize, size_t kObjectsPerPage>
PageAllocator<kObjectSize, kObjectsPerPage>::~PageAllocator() {
  // Returns all pages to the OS.
  void* page = current_page_;
  while (page) {
    void* prev = reinterpret_cast<uint8*>(page) + page_size_ -
        sizeof(void*);
    void* next_page = *reinterpret_cast<void**>(prev);
    CHECK_EQ(TRUE, ::VirtualFree(page, 0, MEM_RELEASE));
    page = next_page;
  }
}

template<size_t kObjectSize, size_t kObjectsPerPage>
void* PageAllocator<kObjectSize, kObjectsPerPage>::Allocate() {
  // Reuse a free object if possible.
  if (free_ != NULL) {
    void* object = free_;
    free_ = *reinterpret_cast<void**>(free_);
    return object;
  }

  // If the current page is exhausted then allocate a new one.
  if (current_object_ >= end_object_) {
    if (!AllocatePage())
      return NULL;
  }
  DCHECK_NE(static_cast<void*>(NULL), current_page_);
  DCHECK_NE(static_cast<void*>(NULL), current_object_);

  void* object = current_object_;

  // Advance the cursor.
  current_object_ = reinterpret_cast<uint8*>(current_object_) + kObjectSize;

  return object;
}

template<size_t kObjectSize, size_t kObjectsPerPage>
void PageAllocator<kObjectSize, kObjectsPerPage>::Free(void* object) {
  DCHECK_NE(static_cast<void*>(NULL), object);

#ifndef NDEBUG
  // These checks are expensive so only run in debug builds.
  // Ensure that the object was actually allocated by this allocator.
  DCHECK(Allocated(object));
  // Ensure that it has not been freed.
  DCHECK(!Freed(object));
#endif

  // Add this object to the list of freed objects.
  *reinterpret_cast<void**>(object) = free_;
  free_ = object;
}

template<size_t kObjectSize, size_t kObjectsPerPage>
bool PageAllocator<kObjectSize, kObjectsPerPage>::AllocatePage() {
  DCHECK_LT(0u, page_size_);
  DCHECK_GE(current_object_, end_object_);

  void* page = ::VirtualAlloc(NULL, page_size_, MEM_COMMIT, PAGE_READWRITE);
  if (page == NULL)
    return false;

  void* prev = reinterpret_cast<uint8*>(page) + page_size_ - sizeof(void*);
  end_object_ = common::AlignDown(prev, kObjectSize);

  // Keep a pointer to the previous page, and set up the next object pointer.
  *reinterpret_cast<void**>(prev) = current_page_;
  current_page_ = page;
  current_object_ = page;

  return true;
}

template<size_t kObjectSize, size_t kObjectsPerPage>
bool PageAllocator<kObjectSize, kObjectsPerPage>::Allocated(
    void* object) const {
  DCHECK_NE(static_cast<void*>(NULL), object);

  // Look for a page owning this object.
  uint8* alloc = reinterpret_cast<uint8*>(object);
  void* page = current_page_;
  while (page) {
    // Skip to the next page if it doesn't own this allocation.
    uint8* page_begin = reinterpret_cast<uint8*>(page);
    uint8* page_end = reinterpret_cast<uint8*>(page) + page_size_ -
        sizeof(void*);
    if (alloc < page_begin || alloc >= page_end) {
      page = *reinterpret_cast<void**>(page_end);
      continue;
    }

    // Determine if the allocation has already been handed out.
    if (page == current_page_ && object >= current_object_)
      return false;

    // Determine if it's aligned as expted.
    if (((alloc - page_begin) % kObjectSize) != 0)
      return false;

    // This allocation must have been previously handed out at some point.
    // Note that this does not allow the detection of double frees.
    return true;
  }

  // The pages have been exhausted and no match was found.
  return false;
}

template<size_t kObjectSize, size_t kObjectsPerPage>
bool PageAllocator<kObjectSize, kObjectsPerPage>::Freed(void* object) const {
  DCHECK_NE(static_cast<void*>(NULL), object);

  void* free = free_;
  while (free) {
    if (free == object)
      return true;

    // Jump to the next freed object.
    free = *reinterpret_cast<void**>(free);
  }

  // The freed objects have been exhausted and no match was found.
  return false;
}

template<typename ObjectType, size_t ObjectsPerPage>
ObjectType* TypedPageAllocator<ObjectType, ObjectsPerPage>::Allocate() {
  return reinterpret_cast<ObjectType*>(allocator_.Allocate());
}

template<typename ObjectType, size_t ObjectsPerPage>
void TypedPageAllocator<ObjectType, ObjectsPerPage>::Free(ObjectType* object) {
  allocator_.Free(object);
}

}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_PAGE_ALLOCATOR_IMPL_H_
