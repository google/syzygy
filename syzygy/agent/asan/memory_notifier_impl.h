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
// Internal implementation details for memory_notification.h. Not meant to
// be included directly.

#ifndef SYZYGY_AGENT_ASAN_MEMORY_NOTIFIER_IMPL_H_
#define SYZYGY_AGENT_ASAN_MEMORY_NOTIFIER_IMPL_H_

#include "base/logging.h"

namespace agent {
namespace asan {

template <typename T>
MemoryNotifierAllocator<T>::MemoryNotifierAllocator(
    MemoryNotifierInterface* memory_notification)
    : memory_notification_(memory_notification) {
  DCHECK_NE(static_cast<MemoryNotifierInterface*>(NULL),
            memory_notification_);
}

template <typename T>
MemoryNotifierAllocator<T>::MemoryNotifierAllocator(
    const MemoryNotifierAllocator& other)
    : memory_notification_(other.memory_notification_) {
  DCHECK_NE(static_cast<MemoryNotifierInterface*>(NULL),
            memory_notification_);
}

template <typename T>
template <typename T2>
MemoryNotifierAllocator<T>::MemoryNotifierAllocator(
    const MemoryNotifierAllocator<T2>& other)
    : memory_notification_(other.memory_notification()) {
  DCHECK_NE(static_cast<MemoryNotifierInterface*>(NULL),
            memory_notification_);
}

template <typename T>
typename MemoryNotifierAllocator<T>::pointer
MemoryNotifierAllocator<T>::allocate(
    size_type count, const void* hint) {
  DCHECK_NE(static_cast<MemoryNotifierInterface*>(NULL),
            memory_notification_);

  pointer objects = std::allocator<T>::allocate(count, hint);
  if (count > 0)
    memory_notification_->NotifyInternalUse(objects, sizeof(T) * count);

  return objects;
}

template <typename T>
void MemoryNotifierAllocator<T>::deallocate(
    pointer objects, size_type count) {
  DCHECK_NE(static_cast<MemoryNotifierInterface*>(NULL),
            memory_notification_);

  if (count > 0)
    memory_notification_->NotifyReturnedToOS(objects, sizeof(T) * count);
  std::allocator<T>::deallocate(objects, count);
}

template <typename T>
MemoryNotifierInterface*
MemoryNotifierAllocator<T>::memory_notification() const {
  DCHECK_NE(static_cast<MemoryNotifierInterface*>(NULL),
            memory_notification_);

  return memory_notification_;
}

}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_MEMORY_NOTIFIER_IMPL_H_
