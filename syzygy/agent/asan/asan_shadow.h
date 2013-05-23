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

#include <string>

#include "base/basictypes.h"

namespace agent {
namespace asan {

// An all-static class that manages the ASAN shadow memory.
class Shadow {
 public:
  // Set up the shadow memory.
  static void SetUp();

  // Tear down the shadow memory.
  static void TearDown();

  // The different markers we use to mark the shadow memory.
  enum ShadowMarker {
    kHeapAddressableByte = 0x00,
    kHeapNonAccessibleByteMask = 0xf0,
    kHeapLeftRedzone = 0xfa,
    kHeapRightRedzone = 0xfb,
    kHeapFreedByte = 0xfd,
  };

  // Poisons @p size bytes starting at @p addr with @p shadow_val value.
  // @pre addr + size mod 8 == 0.
  static void Poison(const void* addr, size_t size, ShadowMarker shadow_val);

  // Un-poisons @p size bytes starting at @p addr.
  // @pre addr mod 8 == 0 && size mod 8 == 0.
  static void Unpoison(const void* addr, size_t size);

  // Mark @p size bytes starting at @p addr as freed.
  static void MarkAsFreed(const void* addr, size_t size);

  // Returns true iff the byte at @p addr is not poisoned.
  static bool IsAccessible(const void* addr);

  // Appends a textual description of the shadow memory for @p addr to
  // @p output.
  static void AppendShadowMemoryText(const void* addr, std::string* output);

 protected:
  // Reset the shadow memory.
  static void Reset();

  // Appends a line of shadow byte text for the bytes ranging from
  // shadow_[index] to shadow_[index + 7], prefixed by @p prefix. If the index
  // @p bug_index is present in this range then its value will be surrounded by
  // brackets.
  static void AppendShadowByteText(const char *prefix,
                                   uintptr_t index,
                                   std::string* output,
                                   size_t bug_index);

  // One shadow byte for every 8 bytes in a 2G address space. By default Chrome
  // is not large address aware, so we shouldn't be using the high memory.
  static const size_t kShadowSize = 1 << (31 - 3);
  static uint8 shadow_[kShadowSize];
};

}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_ASAN_SHADOW_H_
