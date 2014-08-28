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
// A simple circular queue.
// The queue has two ends, the front/head and the back/tail.
// Elements are pushed in the back/tail end, and popped from the front/head end.
// The queue will refuse to push elements when it is full.
// The underlying container reserves the memory only once, making the queue
// memory-wise efficient, avoiding the memory fragmentation caused by lots of
// small allocations.
// To avoid misuse, the constructor taking a MemoryNotiferInterface*
// parameter is enabled IFF the specified allocator is of type
// MemoryNotifierAllocator<T>.
//
// CORRECT USAGE:
// CircularQueue<int, MemoryNotifierAllocator<int>> q(capacity, &notifier);
// CircularQueue<int> q(capacity);  // Using default allocator without notifier.
//
// INCORRECT USAGE (causes compilation error):
// CircularQueue<int> q(capacity, &notifier);

#ifndef SYZYGY_AGENT_ASAN_CIRCULAR_QUEUE_H_
#define SYZYGY_AGENT_ASAN_CIRCULAR_QUEUE_H_

#include <memory>
#include <vector>

#include "syzygy/agent/asan/memory_notifier.h"

namespace agent {
namespace asan {

// A simple circular queue.
// @tparam T the type of the elements.
// @tparam Alloc the type of the allocator used by the underlying container.
template<typename T, typename Alloc = std::allocator<T>>
class CircularQueue {
 public:
  typedef typename std::vector<T, Alloc> Container;

  // Constructor.
  // @param max_capacity Maximum number of elements the queue can store.
  explicit CircularQueue(size_t max_capacity);

  // Constructor.
  // @param max_capacity Maximum number of elements the queue can store.
  // @param alloc The allocator to use with this container.
  CircularQueue(size_t max_capacity, const Alloc& alloc);

  // Inserts an element in the back/tail of the queue if possible.
  // @param the element to be inserted.
  // @returns true if the operation succeeded and the element was inserted,
  //     false if the queue is full.
  bool push(const T&);

  // Removes an element from the front/head of the queue if possible.
  // @returns true if an element was popped fron the front/head,
  //     false if the queue is empty.
  bool pop();

  // @returns the element in the front/head of the queue.
  const T& front() const;

  // Gives the current number of elements in the queue.
  // @returns the number of elements currently stored in the queue.
  size_t size() const;

  // Tests if the queue is empty.
  // @returns true if the queue is empty, false otherwise.
  bool empty() const;

  // @returns the maximum number of elements the queue can handle.
  size_t max_capacity() const;

 private:
  // The index of the first enqueued/pushed element.
  size_t head_;

  // The index of the next free position.
  // The index to be used to store an element in the next call to Push.
  size_t tail_;

  // The number of elements contained in the queue.
  size_t size_;

  // The queue underlying container.
  Container buffer_;
};

}  // namespace asan
}  // namespace agent

#include "syzygy/agent/asan/circular_queue_impl.h"

#endif  // SYZYGY_AGENT_ASAN_CIRCULAR_QUEUE_H_
