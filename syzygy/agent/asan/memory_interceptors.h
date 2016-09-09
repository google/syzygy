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
// Declarations relating to memory intercept functions.
#ifndef SYZYGY_AGENT_ASAN_MEMORY_INTERCEPTORS_H_
#define SYZYGY_AGENT_ASAN_MEMORY_INTERCEPTORS_H_

#include "base/callback.h"

namespace agent {
namespace asan {

class Shadow;

// Configures the shadow memory to be used by the memory interceptors.
// @param shadow The shadow memory to use. May be null, effectively
//     disabling the string interceptors.
// @returns the previously configured shadow memory.
// @note This only updates uses of the shadow via the Shadow API. Interceptors
//     that make direct reference to the shadow memory must be patched in
//     place using 'PatchMemoryInterceptorShadowReferences'.
Shadow* SetMemoryInterceptorShadow(Shadow* shadow);

// Memory accessor mode select.
enum MemoryAccessorMode {
  MEMORY_ACCESSOR_MODE_NOOP,  // Noop mode - no checking performed.
  MEMORY_ACCESSOR_MODE_2G,    // 2G address space mode
  MEMORY_ACCESSOR_MODE_4G,    // 4G address space mode
  MEMORY_ACCESSOR_MODE_MAX,   // This must be last.
};

// Type of the callback invoked on entry to the redirector stub. This is
// invoked any time a redirector stub is invoked. The intent is for this
// callback to reach back and patch the caller's import address table to the
// correct memory accessors.
// @param caller_address the return address for this invocation, allows
//     identifying the caller's module.
// @returns the selected memory accessor mode.
// @note it's possible to get calls to this callback on multiple threads
//    concurrently, whether from a single or multiple modules. The
//    implementation therefore may find the IAT in question already patched.
using RedirectEntryCallback =
    base::Callback<MemoryAccessorMode(const void* caller_address)>;

// Sets the callback invoked on entry to a redirect stub.
void SetRedirectEntryCallback(const RedirectEntryCallback& callback);

// This type is not accurate, as the memory accessors have a custom calling
// convention, but it's nice to have a type for them.
typedef void (*MemoryAccessorFunction)();

struct MemoryAccessorVariants {
  // Canonical name of the exported function, e.g. asan_XXX.
  const char* name;
  MemoryAccessorFunction redirect_accessor;
  union {
    struct {
      // The MemoryAccessorMode enumeration and the following list must remain
      // in sync.
      MemoryAccessorFunction accessor_noop;
      MemoryAccessorFunction accessor_2G;
      MemoryAccessorFunction accessor_4G;
    };
    MemoryAccessorFunction accessors[MEMORY_ACCESSOR_MODE_MAX];
  };
};
static_assert(sizeof(MemoryAccessorVariants) == 5 * sizeof(uintptr_t),
              "MemoryAccessorVariants definition is out of sync");

extern const MemoryAccessorVariants kMemoryAccessorVariants[];
extern const size_t kNumMemoryAccessorVariants;

// List of the memory accessor function variants this file implements.
#define ASAN_MEM_INTERCEPT_FUNCTIONS(F) \
    F(1, read_access, AsanReadAccess) \
    F(2, read_access, AsanReadAccess) \
    F(4, read_access, AsanReadAccess) \
    F(8, read_access, AsanReadAccess) \
    F(10, read_access, AsanReadAccess) \
    F(16, read_access, AsanReadAccess) \
    F(32, read_access, AsanReadAccess) \
    F(1, write_access, AsanWriteAccess) \
    F(2, write_access, AsanWriteAccess) \
    F(4, write_access, AsanWriteAccess) \
    F(8, write_access, AsanWriteAccess) \
    F(10, write_access, AsanWriteAccess) \
    F(16, write_access, AsanWriteAccess) \
    F(32, write_access, AsanWriteAccess)

#define ASAN_STRING_INTERCEPT_FUNCTIONS(F)                       \
  F(cmps, _repz_, ecx, AsanReadAccess, AsanReadAccess, 4, 1)     \
  F(cmps, _repz_, ecx, AsanReadAccess, AsanReadAccess, 2, 1)     \
  F(cmps, _repz_, ecx, AsanReadAccess, AsanReadAccess, 1, 1)     \
  F(cmps, _, 1, AsanReadAccess, AsanReadAccess, 4, 1)            \
  F(cmps, _, 1, AsanReadAccess, AsanReadAccess, 2, 1)            \
  F(cmps, _, 1, AsanReadAccess, AsanReadAccess, 1, 1)            \
  F(lods, _repz_, ecx, AsanWriteAccess, AsanReadAccess, 4, 0)    \
  F(lods, _repz_, ecx, AsanWriteAccess, AsanReadAccess, 2, 0)    \
  F(lods, _repz_, ecx, AsanWriteAccess, AsanReadAccess, 1, 0)    \
  F(lods, _, 1, AsanWriteAccess, AsanReadAccess, 4, 0)           \
  F(lods, _, 1, AsanWriteAccess, AsanReadAccess, 2, 0)           \
  F(lods, _, 1, AsanWriteAccess, AsanReadAccess, 1, 0)           \
  F(movs, _repz_, ecx, AsanWriteAccess, AsanReadAccess, 4, 0)    \
  F(movs, _repz_, ecx, AsanWriteAccess, AsanReadAccess, 2, 0)    \
  F(movs, _repz_, ecx, AsanWriteAccess, AsanReadAccess, 1, 0)    \
  F(movs, _, 1, AsanWriteAccess, AsanReadAccess, 4, 0)           \
  F(movs, _, 1, AsanWriteAccess, AsanReadAccess, 2, 0)           \
  F(movs, _, 1, AsanWriteAccess, AsanReadAccess, 1, 0)           \
  F(stos, _repz_, ecx, AsanWriteAccess, AsanUnknownAccess, 4, 0) \
  F(stos, _repz_, ecx, AsanWriteAccess, AsanUnknownAccess, 2, 0) \
  F(stos, _repz_, ecx, AsanWriteAccess, AsanUnknownAccess, 1, 0) \
  F(stos, _, 1, AsanWriteAccess, AsanUnknownAccess, 4, 0)        \
  F(stos, _, 1, AsanWriteAccess, AsanUnknownAccess, 2, 0)        \
  F(stos, _, 1, AsanWriteAccess, AsanUnknownAccess, 1, 0)

}  // namespace asan
}  // namespace agent

extern "C" {

// The no-op memory access checker.
void asan_no_check();

// The no-op string instruction memory access checker.
void asan_string_no_check();

// The table containing the array of shadow memory references. This is made
// visible so that it can be used by the memory interceptor patcher. The table
// itself will not be modified, but the pointers it points to will be.
extern const void* asan_shadow_references[];

#define DECLARE_MEM_INTERCEPT_FUNCTIONS(access_size, access_mode_str,      \
                                        access_mode_value)                 \
  void asan_redirect_##access_size##_byte_##access_mode_str();             \
  void asan_check_##access_size##_byte_##access_mode_str##_2gb();          \
  void asan_check_##access_size##_byte_##access_mode_str##_4gb();          \
  void asan_redirect_##access_size##_byte_##access_mode_str##_no_flags();  \
  void asan_check_##access_size##_byte_##access_mode_str##_no_flags_2gb(); \
  void asan_check_##access_size##_byte_##access_mode_str##_no_flags_4gb();

// Declare all the memory interceptor functions. Note that these functions have
// a custom calling convention, and can't be invoked directly.
ASAN_MEM_INTERCEPT_FUNCTIONS(DECLARE_MEM_INTERCEPT_FUNCTIONS)

#undef DECLARE_MEM_INTERCEPT_FUNCTIONS

#define DECLARE_STRING_INTERCEPT_FUNCTIONS(func, prefix, counter, dst_mode, \
                                           src_mode, access_size, compare) \
  void asan_redirect ## prefix ## access_size ## _byte_ ## func ## _access(); \
  void asan_check ## prefix ## access_size ## _byte_ ## func ## _access(); \

// Declare all the string instruction interceptor functions. Note that these
// functions have a custom calling convention, and can't be invoked directly.
ASAN_STRING_INTERCEPT_FUNCTIONS(DECLARE_STRING_INTERCEPT_FUNCTIONS)

#undef DECLARE_STRING_INTERCEPT_FUNCTIONS

}  // extern "C"

#endif  // SYZYGY_AGENT_ASAN_MEMORY_INTERCEPTORS_H_
