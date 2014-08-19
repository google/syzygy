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
// Declares a handful of STL compatible allocators that interact with
// SyzyASan subsystems. This is all with the goal of enhanced redzone
// reporting.

#ifndef SYZYGY_AGENT_ASAN_ALLOCATORS_H_
#define SYZYGY_AGENT_ASAN_ALLOCATORS_H_

#include <memory>

#include "syzygy/agent/asan/heap.h"
#include "syzygy/agent/asan/memory_notifier.h"

namespace agent {
namespace asan {

// An STL-compatible allocator that notifies a MemoryNotifier object of
// memory use.
// @tparam T The type of object that is returned by the allocator.
template <typename T>
class MemoryNotifierAllocator : public std::allocator<T> {
 public:
  typedef size_t size_type;
  typedef T* pointer;
  typedef const T* const_pointer;

  // Functor that converts this allocator to an equivalent one for another
  // type.
  // @tparam T2 The type being casted to.
  template <typename T2>
  struct rebind {
    typedef MemoryNotifierAllocator<T2> other;
  };

  // Constructor with a notifier object.
  // @param memory_notifier A pointer to the memory notifier object
  //     that this allocate will notify.
  explicit MemoryNotifierAllocator(
      MemoryNotifierInterface* memory_notifier);

  // Copy constructor. Necessary for STL compatibility.
  MemoryNotifierAllocator(const MemoryNotifierAllocator& other);

  // Copy constructor from another type. Necessary for STL compatibility.
  // This simply copies the memory notifier API.
  // @tparam T2 The type of the other allocator.
  // @param other The allocator being copied.
  template <typename T2>
  MemoryNotifierAllocator(const MemoryNotifierAllocator<T2>& other);

  // Allocates @p count objects of type T.
  // @param count The number of objects to allocate.
  // @param hint A hint as to where the objects should be allocated.
  // @returns a pointer to the allocated objects, NULL if the allocation
  //     failed.
  pointer allocate(size_type count, const void* hint = NULL);

  // Deallocates a group of @p n objects.
  // @param objects A pointer to the allocated objects. This must have
  //     previously been returned a call to 'allocate'.
  // @param count The number of objects in the allocation.
  void deallocate(pointer objects, size_type count);

  // @returns the MemoryNotifier object used by this allocator.
  MemoryNotifierInterface* memory_notifier() const;

 protected:
  MemoryNotifierInterface* memory_notifier_;
};

// An STL-compatible allocator that uses a HeapInterface object under the
// hood.
// @tparam T The type of object that is returned by the allocator.
template <typename T>
class HeapAllocator : public std::allocator<T> {
 public:
  typedef size_t size_type;
  typedef T* pointer;
  typedef const T* const_pointer;

  // Functor that converts this allocator to an equivalent one for another
  // type.
  // @tparam T2 The type being casted to.
  template <typename T2>
  struct rebind {
    typedef HeapAllocator<T2> other;
  };

  // Constructor with a notifier object.
  // @param heap A pointer to the heap object that will be used to make the
  //     allocations.
  explicit HeapAllocator(HeapInterface* heap);

  // Copy constructor. Necessary for STL compatibility.
  HeapAllocator(const HeapAllocator& other);

  // Copy constructor from another type. Necessary for STL compatibility.
  // This simply copies the memory notifier API.
  // @tparam T2 The type of the other allocator.
  // @param other The allocator being copied.
  template <typename T2>
  HeapAllocator(const HeapAllocator<T2>& other);

  // Allocates @p count objects of type T.
  // @param count The number of objects to allocate.
  // @param hint A hint as to where the objects should be allocated.
  // @returns a pointer to the allocated objects, NULL if the allocation
  //     failed.
  pointer allocate(size_type count, const void* hint = NULL);

  // Deallocates a group of @p n objects.
  // @param objects A pointer to the allocated objects. This must have
  //     previously been returned a call to 'allocate'.
  // @param count The number of objects in the allocation.
  void deallocate(pointer objects, size_type count);

  // @returns the Heap object used by this allocator.
  HeapInterface* heap() const;

 protected:
  HeapInterface* heap_;
};

}  // namespace asan
}  // namespace agent

#include "syzygy/agent/asan/allocators_impl.h"

#endif  // SYZYGY_AGENT_ASAN_ALLOCATORS_H_
