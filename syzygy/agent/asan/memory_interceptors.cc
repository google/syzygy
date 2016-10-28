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
#include "syzygy/agent/asan/memory_interceptors.h"

#include <stdint.h>

#include "base/logging.h"
#include "base/macros.h"
#include "syzygy/agent/asan/memory_interceptors_impl.h"
#include "syzygy/agent/asan/rtl_utils.h"
#include "syzygy/agent/asan/shadow.h"

using agent::asan::Shadow;

namespace agent {
namespace asan {
namespace {

RedirectEntryCallback redirect_entry_callback;

// The global shadow memory that is used by the memory interceptors.
// This is only used by interceptors that make use of the Shadow API.
// Interceptors with direct reference (the basic read/write probes) to the
// shadow memory must be patched directly.
Shadow* memory_interceptor_shadow_ = nullptr;

// Helper function to find a redirector variant.
// @param variants The array containing all the different probe variants,
//     it should be an array of MemoryAccessorVariants or any type derived
//     from this.
// @param caller_address The address of the function that called the Asan
//     redirector.
// @param called_redirect The address of the redirect probe that has been
//     called.
// @tparam T The type of the function pointers returned by the probes defined
//     in |variants|.
// @tparam T2 The type of the entry in the array |variants|.
// @tparam N The size of the array |variants|.
template <typename T, typename T2, size_t N>
T FindMemoryRedirectorVariant(const T2(&variants)[N],
                              const void* caller_address,
                              T called_redirect) {
  MemoryAccessorMode mode = MEMORY_ACCESSOR_MODE_NOOP;

  // TODO(siggi): Does it make sense to CHECK on this?
  if (!redirect_entry_callback.is_null())
    mode = redirect_entry_callback.Run(caller_address);

  for (size_t i = 0; i < N; ++i) {
    if (variants[i].redirect_accessor != called_redirect)
      continue;
    CHECK_LE(0u, mode);
    CHECK_GT(MEMORY_ACCESSOR_MODE_MAX, mode);
    return variants[i].accessors[mode];
  }

  NOTREACHED();
  return NULL;
}

}  // namespace

Shadow* SetMemoryInterceptorShadow(Shadow* shadow) {
  Shadow* old_shadow = memory_interceptor_shadow_;
  memory_interceptor_shadow_ = shadow;
  return old_shadow;
}

#ifndef _WIN64
const MemoryAccessorVariants kMemoryAccessorVariants[] = {
#define ENUM_MEM_INTERCEPT_FUNCTION_VARIANTS(access_size, access_mode_str,   \
                                             access_mode_value)              \
  { "asan_check_" #access_size "_byte_" #access_mode_str,                    \
    asan_redirect_##access_size##_byte_##access_mode_str, asan_no_check,     \
    asan_check_##access_size##_byte_##access_mode_str##_2gb,                 \
    asan_check_##access_size##_byte_##access_mode_str##_4gb                  \
  },                                                                         \
  { "asan_check_" #access_size "_byte_" #access_mode_str "_no_flags",        \
     asan_redirect_##access_size##_byte_##access_mode_str##_no_flags,        \
     asan_no_check,                                                          \
     asan_check_##access_size##_byte_##access_mode_str##_no_flags_2gb,       \
     asan_check_##access_size##_byte_##access_mode_str##_no_flags_4gb},

    ASAN_MEM_INTERCEPT_FUNCTIONS(ENUM_MEM_INTERCEPT_FUNCTION_VARIANTS)

#undef ENUM_MEM_INTERCEPT_FUNCTION_VARIANTS

#define ENUM_STRING_INTERCEPT_FUNCTION_VARIANTS( \
    func, prefix, counter, dst_mode, src_mode, access_size, compare)         \
  { "asan_check" #prefix #access_size "_byte_" #func "_access",              \
    asan_redirect ## prefix ## access_size ## _byte_ ## func ## _access,     \
    asan_string_no_check,                                                    \
    asan_check ## prefix ## access_size ## _byte_ ## func ## _access,        \
    asan_check ## prefix ## access_size ## _byte_ ## func ## _access,        \
  },

        ASAN_STRING_INTERCEPT_FUNCTIONS(ENUM_STRING_INTERCEPT_FUNCTION_VARIANTS)

#undef ENUM_STRING_INTERCEPT_FUNCTION_VARIANTS
};

const size_t kNumMemoryAccessorVariants = arraysize(kMemoryAccessorVariants);

#endif

const ClangMemoryAccessorVariants kClangMemoryAccessorVariants[] = {
#ifndef _WIN64
#define ENUM_MEM_INTERCEPT_CLANG_FUNCTION_VARIANTS(                          \
    access_size, access_mode_str, access_mode_value)                         \
  {                                                                          \
    "__asan_" #access_mode_str #access_size,                                 \
        asan_redirect_##access_mode_str##access_size##, asan_clang_no_check, \
        asan_##access_mode_str##access_size##_2gb,                           \
        asan_##access_mode_str##access_size##_4gb,                           \
  }                                                                          \
  ,
#else
#define ENUM_MEM_INTERCEPT_CLANG_FUNCTION_VARIANTS(                          \
    access_size, access_mode_str, access_mode_value)                         \
  {                                                                          \
    "__asan_" #access_mode_str #access_size,                                 \
        asan_redirect_##access_mode_str##access_size##, asan_clang_no_check, \
        asan_##access_mode_str##access_size##_8tb,                           \
        asan_##access_mode_str##access_size##_128tb,                         \
  }                                                                          \
  ,
#endif

    CLANG_ASAN_MEM_INTERCEPT_FUNCTIONS(
        ENUM_MEM_INTERCEPT_CLANG_FUNCTION_VARIANTS)

#undef ENUM_MEM_INTERCEPT_CLANG_FUNCTION_VARIANTS
};

const size_t kNumClangMemoryAccessorVariants =
    arraysize(kClangMemoryAccessorVariants);

void SetRedirectEntryCallback(const RedirectEntryCallback& callback) {
  redirect_entry_callback = callback;
}

// Check if the memory location is accessible and report an error on bad memory
// accesses.
// @param location The memory address of the access.
// @param access_mode The mode of the access.
// @param access_size The size of the access.
// @param context The registers context of the access.
void CheckMemoryAccess(void* location,
                       AccessMode access_mode,
                       size_t access_size,
                       const AsanContext& context) {
  if (memory_interceptor_shadow_ &&
      !memory_interceptor_shadow_->IsAccessible(location)) {
    ReportBadMemoryAccess(location, access_mode, access_size, context);
  }
}

// The slow path relies on the fact that the shadow memory non accessible byte
// mask has its upper bit set to 1.
static_assert((kHeapNonAccessibleMarkerMask & (1 << 7)) != 0,
              "Asan shadow mask upper bit is 0.");

extern "C" {

#ifndef _WIN64
// Check if the memory accesses done by a string instructions are valid.
// @param dst The destination memory address of the access.
// @param dst_access_mode The destination mode of the access.
// @param src The source memory address of the access.
// @param src_access_mode The source mode of the access.
// @param length The number of memory accesses.
// @param access_size The size of each the access in byte.
// @param increment The increment to move dst/src after each access.
// @param compare Flag to activate shortcut of the execution on difference.
// @param context The registers context of the access.
void asan_check_strings_memory_accesses(uint8_t* dst,
                                        AccessMode dst_access_mode,
                                        uint8_t* src,
                                        AccessMode src_access_mode,
                                        uint32_t length,
                                        size_t access_size,
                                        int32_t increment,
                                        bool compare,
                                        const AsanContext& context) {
  int32_t offset = 0;

  for (uint32_t i = 0; i < length; ++i) {
    // Check next memory location at src[offset].
    if (src_access_mode != agent::asan::ASAN_UNKNOWN_ACCESS)
      CheckMemoryAccess(&src[offset], src_access_mode, access_size, context);

    // Check next memory location at dst[offset].
    if (dst_access_mode != agent::asan::ASAN_UNKNOWN_ACCESS)
      CheckMemoryAccess(&dst[offset], dst_access_mode, access_size, context);

    // For CMPS instructions, we shortcut the execution of prefix REPZ when
    // memory contents differ.
    if (compare) {
      uint32_t src_content = 0;
      uint32_t dst_content = 0;
      switch (access_size) {
      case 4:
        src_content = *reinterpret_cast<uint32_t*>(&src[offset]);
        dst_content = *reinterpret_cast<uint32_t*>(&dst[offset]);
        break;
      case 2:
        src_content = *reinterpret_cast<uint16_t*>(&src[offset]);
        dst_content = *reinterpret_cast<uint16_t*>(&dst[offset]);
        break;
      case 1:
        src_content = *reinterpret_cast<uint8_t*>(&src[offset]);
        dst_content = *reinterpret_cast<uint8_t*>(&dst[offset]);
        break;
      default:
        NOTREACHED() << "Unexpected access_size.";
        break;
      }

      if (src_content != dst_content)
        return;
    }

    // Increments offset of dst/src to the next memory location.
    offset += increment;
  }
}

// Redirect stub for the SyzyAsan probes.
MemoryAccessorFunction asan_redirect_stub_entry(
    const void* caller_address,
    MemoryAccessorFunction called_redirect) {
  return FindMemoryRedirectorVariant(kMemoryAccessorVariants, caller_address,
                                     called_redirect);
}
#endif

// Redirect stub for the Clang-Asan probes.
ClangMemoryAccessorFunction asan_redirect_clang_stub_entry(
    const void* caller_address,
    ClangMemoryAccessorFunction called_redirect) {
  return FindMemoryRedirectorVariant(kClangMemoryAccessorVariants,
                                     caller_address, called_redirect);
}

// A simple wrapper to agent::asan::ReportBadMemoryAccess that has C linkage
// so it can be referred to in memory_interceptors.asm.
void asan_report_bad_memory_access(void* location,
                                   AccessMode access_mode,
                                   size_t access_size,
                                   const AsanContext& asan_context) {
  return agent::asan::ReportBadMemoryAccess(location, access_mode, access_size,
                                            asan_context);
}

}  // extern "C"

}  // namespace asan
}  // namespace agent
