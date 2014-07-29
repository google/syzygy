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
// Declares MemoryNotifierInterface, an API that is used by runtime
// components to notify the runtime of memory that they have allocated for
// internal use. This results in enhanced shadow redzone coverage.

#ifndef SYZYGY_AGENT_ASAN_MEMORY_NOTIFIER_H_
#define SYZYGY_AGENT_ASAN_MEMORY_NOTIFIER_H_

#include <memory>

namespace agent {
namespace asan {

// Declares a simple interface that is used by internal runtime components to
// notify the runtime of their own memory use.
class MemoryNotifierInterface {
 public:
  // Virtual destructor.
  virtual ~MemoryNotifierInterface() { }

  // Reports the given range of memory for internal use by the runtime.
  // @param address The address of the memory range.
  // @param size The size of the memory range, in bytes.
  virtual void NotifyInternalUse(const void* address, size_t size) = 0;

  // Reports the given range of memory as reserved for future external use
  // by the runtime. That is, this is memory that is set aside for handing out
  // to the instrumented application via a heap allocation.
  // @param address The address of the memory range.
  // @param size The size of the memory range, in bytes.
  virtual void NotifyFutureHeapUse(const void* address, size_t size) = 0;

  // Reports that the given range of memory has been returned to the OS and is
  // no longer under the direct control of the runtime.
  // @param address The address of the memory range.
  // @param size The size of the memory range, in bytes.
  virtual void NotifyReturnedToOS(const void* address, size_t size) = 0;
};

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

  // Constructor with a notification object.
  // @param memory_notification A pointer to the memory notification object
  //     that this allocate will notify.
  explicit MemoryNotifierAllocator(
      MemoryNotifierInterface* memory_notification);

  // Copy constructor. Necessary for STL compatibility.
  MemoryNotifierAllocator(const MemoryNotifierAllocator& other);

  // Copy constructor from another type. Necessary for STL compatibility.
  // This simply copies the memory notification API.
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
  MemoryNotifierInterface* memory_notification() const;

 protected:
  MemoryNotifierInterface* memory_notification_;
};

}  // namespace asan
}  // namespace agent

#include "syzygy/agent/asan/memory_notifier_impl.h"

#endif  // SYZYGY_AGENT_ASAN_MEMORY_NOTIFIER_H_
