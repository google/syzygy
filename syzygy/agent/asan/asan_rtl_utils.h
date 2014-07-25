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
// Utility functions used by the ASan check functions..
#ifndef SYZYGY_AGENT_ASAN_ASAN_RTL_UTILS_H_
#define SYZYGY_AGENT_ASAN_ASAN_RTL_UTILS_H_

#include <windows.h>

#include "syzygy/agent/asan/asan_heap.h"
#include "syzygy/agent/asan/error_info.h"

namespace agent {
namespace asan {

// Forward declarations.
class AsanRuntime;

using agent::asan::HeapProxy;

// Contents of the registers before calling the ASAN memory check function.
#pragma pack(push, 1)
struct AsanContext {
  DWORD original_edi;
  DWORD original_esi;
  DWORD original_ebp;
  DWORD original_esp;
  DWORD original_ebx;
  DWORD original_edx;
  DWORD original_ecx;
  DWORD original_eax;
  DWORD original_eflags;
  DWORD original_eip;
};
#pragma pack(pop)

// Set the AsanRuntime instance that should be used to report the crash.
// @param runtime The runtime instance to use.
void SetAsanRuntimeInstance(AsanRuntime* runtime);

// Convert a CONTEXT struct to an ASan context.
// @param context The context to convert.
// @param asan_context Receives the ASan context.
void ContextToAsanContext(const CONTEXT& context, AsanContext* asan_context);

// Report a bad access to the memory.
// @param location The memory address of the access.
// @param access_mode The mode of the access.
// @param access_size The size of the access.
// @param asan_context The context of the access.
void ReportBadMemoryAccess(void* location,
                           AccessMode access_mode,
                           size_t access_size,
                           const AsanContext& asan_context);

// Report an invalid access to @p location.
// @param location The memory address of the access.
// @param access_mode The mode of the access.
void ReportBadAccess(const uint8* location, AccessMode access_mode);

// Test that a memory range is accessible. Report an error if it's not.
// @param memory The pointer to the beginning of the memory range that we want
//     to check.
// @param size The size of the memory range that we want to check.
// @param access_mode The access mode.
void TestMemoryRange(const uint8* memory,
                     size_t size,
                     AccessMode access_mode);

// Helper function to test if the memory range of a given structure is
// accessible.
// @tparam T the type of the structure to be tested.
// @param structure A pointer to this structure.
// @param access mode The access mode.
template <typename T>
void TestStructure(const T* structure, AccessMode access_mode) {
  TestMemoryRange(reinterpret_cast<const uint8*>(structure),
                  sizeof(T),
                  access_mode);
}

}  // namespace asan
}  // namespace agent


#endif  // SYZYGY_AGENT_ASAN_ASAN_RTL_UTILS_H_
