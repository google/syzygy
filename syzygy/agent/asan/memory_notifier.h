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

}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_MEMORY_NOTIFIER_H_
