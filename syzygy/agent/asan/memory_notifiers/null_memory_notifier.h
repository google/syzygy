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

#ifndef SYZYGY_AGENT_ASAN_MEMORY_NOTIFIERS_NULL_MEMORY_NOTIFIER_H_
#define SYZYGY_AGENT_ASAN_MEMORY_NOTIFIERS_NULL_MEMORY_NOTIFIER_H_

#include "base/logging.h"
#include "syzygy/agent/asan/memory_notifier.h"

namespace agent {
namespace asan {
namespace memory_notifiers {

// Dummy notifier, useful to test objects relying on a memory notifier.
class NullMemoryNotifier : public MemoryNotifierInterface {
 public:
  // Constructor.
  NullMemoryNotifier() { }

  // Virtual destructor.
  virtual ~NullMemoryNotifier() { }

  // @name MemoryNotifierInterface implementation.
  // @{
  virtual void NotifyInternalUse(const void* address, size_t size) { }
  virtual void NotifyFutureHeapUse(const void* address, size_t size) { }
  virtual void NotifyReturnedToOS(const void* address, size_t size) { }
  // @}
 private:
  DISALLOW_COPY_AND_ASSIGN(NullMemoryNotifier);
};

}  // namespace memory_notifiers
}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_MEMORY_NOTIFIERS_NULL_MEMORY_NOTIFIER_H_
