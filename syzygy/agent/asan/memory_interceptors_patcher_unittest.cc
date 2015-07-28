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

#include "syzygy/agent/asan/memory_interceptors_patcher.h"

#include "gtest/gtest.h"
#include "syzygy/agent/asan/memory_interceptors.h"
#include "syzygy/agent/asan/shadow.h"

// The linker satisfies this symbol. This gets us a pointer to our own module
// when we're loaded.
extern "C" IMAGE_DOS_HEADER __ImageBase;

namespace agent {
namespace asan {

namespace {

void ExpectShadowReferencesTo(const uint8_t* shadow_memory) {
  for (const void** cursor = asan_shadow_references; *cursor != 0; ++cursor) {
    EXPECT_EQ(shadow_memory, *reinterpret_cast<uint8_t const* const*>(*cursor));
  }
}

}  // namespace

TEST(MemoryInterceptorPatcherTest, PatchMemoryInterceptorShadowReferences) {
  // The references should initially be to the static shadow memory.
  EXPECT_NO_FATAL_FAILURE(
      ExpectShadowReferencesTo(asan_memory_interceptors_shadow_memory));

  // Patch the references to point to a new shadow memory.
  uint8_t dummy_shadow[1] = {};
  EXPECT_TRUE(PatchMemoryInterceptorShadowReferences(
      asan_memory_interceptors_shadow_memory, dummy_shadow));
  EXPECT_NO_FATAL_FAILURE(ExpectShadowReferencesTo(dummy_shadow));

  // Try patching again. The 'current' shadow memory matching will fail
  // and the functions should still point to the new shadow.
  EXPECT_FALSE(PatchMemoryInterceptorShadowReferences(
      asan_memory_interceptors_shadow_memory, dummy_shadow));
  EXPECT_NO_FATAL_FAILURE(ExpectShadowReferencesTo(dummy_shadow));

  // Patch this back to the original shadow memory so the unittest leaves no
  // side effects.
  EXPECT_TRUE(PatchMemoryInterceptorShadowReferences(
      dummy_shadow, asan_memory_interceptors_shadow_memory));
  EXPECT_NO_FATAL_FAILURE(
      ExpectShadowReferencesTo(asan_memory_interceptors_shadow_memory));
}

}  // namespace asan
}  // namespace agent
