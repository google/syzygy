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
// Internal implementation details for circular_queue.h. Not meant to
// be included directly.

#ifndef SYZYGY_AGENT_ASAN_CIRCULAR_QUEUE_IMPL_H_
#define SYZYGY_AGENT_ASAN_CIRCULAR_QUEUE_IMPL_H_

#include "base/logging.h"
#include "syzygy/agent/asan/memory_notifier.h"

namespace agent {
namespace asan {

template<typename T, typename Alloc>
CircularQueue<T, Alloc>::CircularQueue(size_t max_capacity)
    : head_(0u), tail_(0u), size_(0u) {
  buffer_.resize(max_capacity);
}

template<typename T, typename Alloc>
template<typename>
CircularQueue<T, Alloc>::CircularQueue(
    size_t max_capacity,
    MemoryNotifierInterface* memory_notifier)
    : buffer_(MemoryNotifierAllocator<T>(memory_notifier)),
      head_(0u),
      tail_(0u),
      size_(0u) {
  buffer_.resize(max_capacity);
}

template<typename T, typename Alloc>
bool CircularQueue<T, Alloc>::push(const T& elem) {
  DCHECK_LE(size_, buffer_.size());
  if (size_ == buffer_.size())
    return false;
  DCHECK_LT(tail_, buffer_.size());
  buffer_[tail_++] = elem;
  if (tail_ >= buffer_.size())
    tail_ = 0;
  ++size_;
  return true;
}

template<typename T, typename Alloc>
bool CircularQueue<T, Alloc>::pop() {
  if (empty())
    return false;
  DCHECK_LT(head_, buffer_.size());
  ++head_;
  if (head_ == buffer_.size())
    head_ = 0;
  --size_;
  return true;
}

template<typename T, typename Alloc>
const T& CircularQueue<T, Alloc>::front() const {
  DCHECK(!empty());
  return buffer_[head_];
}

template<typename T, typename Alloc>
size_t CircularQueue<T, Alloc>::size() const {
  return size_;
}

template<typename T, typename Alloc>
bool CircularQueue<T, Alloc>::empty() const {
  return size() == 0;
}

template<typename T, typename Alloc>
size_t CircularQueue<T, Alloc>::max_capacity() const {
  return buffer_.size();
}

}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_CIRCULAR_QUEUE_IMPL_H_
