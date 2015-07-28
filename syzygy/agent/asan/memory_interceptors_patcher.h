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
//
// Declares a helper function for in-place patching the memory interceptors
// to point to a new shadow memory array.

#ifndef SYZYGY_AGENT_ASAN_MEMORY_INTERCEPTORS_PATCHER_H_
#define SYZYGY_AGENT_ASAN_MEMORY_INTERCEPTORS_PATCHER_H_

#include <windows.h>
#include <cstdint>

namespace agent {
namespace asan {

// Patches the memory interceptors found in the .probes section of the current
// module.
// @param new_shadow_memory The shadow memory that is to be patched into the
//     probes.
// @param old_shadow_memory The shadow memory that the probe should currently
//     be referring to.
// @note This function is BYOL - bring your own locking.
// @note Patching is inherently racy. It's wise to call this function from
//     under a lock that prevents concurrent patching on the same module, and
//     the caller must guarantee that the module is not unloaded during
//     patching.
// @returns true on success, false otherwise. Logs verbosely on failure.
bool PatchMemoryInterceptorShadowReferences(const uint8_t* old_shadow_memory,
                                            const uint8_t* new_shadow_memory);

}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_MEMORY_INTERCEPTORS_PATCHER_H_
