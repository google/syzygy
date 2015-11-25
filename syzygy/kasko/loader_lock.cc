// Copyright 2015 Google Inc. All Rights Reserved.
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

#include "syzygy/kasko/loader_lock.h"

#include <stdint.h>
#include <winternl.h>

namespace kasko {

namespace {

void* AddOffset(void* ptr, int offset) {
  return reinterpret_cast<uint8_t*>(ptr) + offset;
}

}  // namespace

CRITICAL_SECTION* GetLoaderLock() {
  // The offset to the loader lock in the PEB structure. This value
  // is undocumented but appears to never change.
  static const uint32_t kLoaderLockOffset = 0xa0;
  static_assert(4 == sizeof(void*), "Only supported in 32 bit.");
  // In 64 bit processes, the offset is 0x110.

  PEB* peb = NtCurrentTeb()->ProcessEnvironmentBlock;
  CRITICAL_SECTION* loader_lock =
      *reinterpret_cast<CRITICAL_SECTION**>(AddOffset(peb, kLoaderLockOffset));

  return loader_lock;
}

}  // namespace kasko
