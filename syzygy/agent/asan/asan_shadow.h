// Copyright 2012 Google Inc. All Rights Reserved.
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
// Implements an all-static class that manages shadow memory for ASAN.
#ifndef SYZYGY_AGENT_ASAN_ASAN_SHADOW_H_
#define SYZYGY_AGENT_ASAN_ASAN_SHADOW_H_

#include "base/basictypes.h"

namespace agent {
namespace asan {

// An all-static class that manages the ASAN shadow memory.
class Shadow {
 public:
  // Poisons @p size bytes starting at @p addr.
  // @pre addr + size mod 8 == 0.
  static void Poison(const void* addr, size_t size);

  // Un-poisons @p size bytes starting at @p addr.
  // @pre addr mod 8 == 0 && size mod 8 == 0.
  static void Unpoison(const void* addr, size_t size);

  // Returns true iff the byte at @p addr is not poisoned.
  static bool IsAccessible(const void* addr);

  // Print the content of the shadow memory for @p addr.
  static void PrintShadowMemoryForAddress(const void* addr);

 private:
  // Print the shadow bytes from shadow_[index] to shadow_[index + 7] on a line
  // prefixed by @p prefix.
  static void PrintShadowBytes(const char *prefix, uintptr_t index);

  // One shadow byte for every 8 bytes in a 4G address space.
  static const size_t kShadowSize = 1 << (32 - 3);
  static uint8 shadow_[kShadowSize];
};

}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_ASAN_SHADOW_H_
