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
// Defines PageAllocator. This is a simple allocator that grabs pages of
// memory of a fixed specified size and hands out fixed size regions from head
// to tail within that page. Regions of pages that have been freed are kept
// track of in a simple linked list, and returned regions are aggressively
// reused before a new page is allocated.
//
// Since memory is not actively recovered at runtime this allocator will always
// use as much memory as the 'high waterline'. Thus, it is not suitable for
// managing bursty objects. Rather, it should be used for pools that tend to
// grow monotonically to a stable maximum size.

#ifndef SYZYGY_AGENT_ASAN_PAGE_ALLOCATOR_H_
#define SYZYGY_AGENT_ASAN_PAGE_ALLOCATOR_H_

#include "base/basictypes.h"

namespace agent {
namespace asan {

// An untyped PageAllocator. This object is not thread safe.
// @tparam kObjectSize The size of objects returned by the allocator,
//     in bytes. Objects will be tightly packed so any alignment constraints
//     should be reflected in this size.
// @tparam kObjectsPerPage The minimum number of objects that should be
//     allocated at a time as the pool grows.
template<size_t kObjectSize, size_t kObjectsPerPage>
class PageAllocator {
 public:
  // Constructor.
  PageAllocator();

  // Destructor.
  ~PageAllocator();

  // Allocates a single object of the configured size.
  // @returns A pointer to the allocated object, or NULL on failure.
  void* Allocate();

  // Frees the given object.
  // @param object The object to be returned.
  void Free(void* object);

 protected:
  // Reserves a new page of objects, modifying current_page_ and
  // current_object_. This should only be called when
  // current_object_ >= end_object_.
  // @returns true if the allocation was successful, false otherwise.
  bool AllocatePage();

  // @returns true if the given object was handed out by this allocator.
  bool Allocated(void* object) const;

  // @returns true if the given object has been freed by this allocator.
  bool Freed(void* object) const;

  // The size of a page.
  size_t page_size_;

  // The currently active page of objects.
  void* current_page_;

  // A pointer into the currently active page of objects.
  void* current_object_;

  // A pointer into the currently active page of objects that represents beyond
  // the end of allocatable objects. This also points to the last pointer sized
  // run of bytes in the page, which is used for storing the linked list
  // pointer.
  void* end_object_;

  // A singly linked list of freed objects.
  void* free_;

 private:
  DISALLOW_COPY_AND_ASSIGN(PageAllocator);
};

// A templated PageAllocator with convenience functions for allocating and
// freeing typed objects.
// @tparam ObjectType The type of object that is returned by the allocator.
// @tparam ObjectsPerPage The minimum number of objects that should be
//     allocated at a time as the pool grows.
template<typename ObjectType, size_t ObjectsPerPage>
class TypedPageAllocator {
 public:
  // Constructor.
  TypedPageAllocator() { }

  // Destructor.
  ~TypedPageAllocator() { }

  // Allocates a single object.
  // @returns A pointer to the allocated object, or NULL on failure.
  ObjectType* Allocate();

  // Frees the given object.
  // @param object The object to be returned.
  void Free(ObjectType* object);

 protected:
  PageAllocator<sizeof(ObjectType), ObjectsPerPage> allocator_;

 private:
  DISALLOW_COPY_AND_ASSIGN(TypedPageAllocator);
};

}  // namespace asan
}  // namespace agent

#include "syzygy/agent/asan/page_allocator_impl.h"

#endif  // SYZYGY_AGENT_ASAN_PAGE_ALLOCATOR_H_
