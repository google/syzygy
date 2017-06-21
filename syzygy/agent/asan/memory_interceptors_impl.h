// Copyright 2016 Google Inc. All Rights Reserved.
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

#ifndef SYZYGY_AGENT_ASAN_MEMORY_INTERCEPTORS_IMPL_H_
#define SYZYGY_AGENT_ASAN_MEMORY_INTERCEPTORS_IMPL_H_

// The Clang-asan compatible implementation of the Asan probes.

#include "syzygy/agent/asan/error_info.h"
#include "syzygy/agent/asan/rtl_utils.h"
#include "syzygy/agent/asan/runtime.h"
#include "syzygy/agent/asan/shadow.h"

using agent::asan::AccessMode;
using agent::asan::AsanContext;
using agent::asan::AsanRuntime;

// The template function that performs the checks.
// @tparam access_size Access size in bytes.
// @tparam address_space_size The virtual address space size limit in bytes.
//     It's 8 TB for Win7 and Win8 and 128 TB for Win8.1+.
// @tparam access_mode The access mode, which can be any of AccessMode values,
//     allthough this file only exports the probes for read and write accesses.
// @param addr The address being accessed.
template <size_t access_size, size_t address_space_size, AccessMode access_mode>
void asan_check(const void* addr) {
  if (reinterpret_cast<uintptr_t>(addr) > address_space_size ||
      !AsanRuntime::runtime()->shadow()->IsAccessible(addr)) {
    CONTEXT ctx = {};
    ::RtlCaptureContext(&ctx);
    AsanContext asan_ctx = {};
    ContextToAsanContext(ctx, &asan_ctx);
    ReportBadMemoryAccess(addr, access_mode, access_size, asan_ctx);
  }
}

// A few macros to instantiate 'asan_check' and export the instantiations
// with appropriate names.

#define EXPORT_INTERCEPTOR_READ(access_size, suffix, address_space_size) \
  void asan_load##access_size##_##suffix(const void* addr) {             \
    return asan_check<access_size, address_space_size,                   \
                      agent::asan::ASAN_READ_ACCESS>(addr);              \
  }

#define EXPORT_INTERCEPTOR_WRITE(access_size, suffix, address_space_size) \
  void asan_store##access_size##_##suffix(const void* addr) {             \
    return asan_check<access_size, address_space_size,                    \
                      agent::asan::ASAN_WRITE_ACCESS>(addr);              \
  }

#define EXPORT_INTERCEPTOR(access_size, suffix, address_space_size) \
  EXPORT_INTERCEPTOR_READ(access_size, suffix, address_space_size)  \
  EXPORT_INTERCEPTOR_WRITE(access_size, suffix, address_space_size)

#define EXPORT_INTERCEPTORS_ALL_SIZES(suffix, address_space_size) \
  EXPORT_INTERCEPTOR(1, suffix, address_space_size)               \
  EXPORT_INTERCEPTOR(2, suffix, address_space_size)               \
  EXPORT_INTERCEPTOR(4, suffix, address_space_size)               \
  EXPORT_INTERCEPTOR(8, suffix, address_space_size)               \
  EXPORT_INTERCEPTOR(10, suffix, address_space_size)              \
  EXPORT_INTERCEPTOR(16, suffix, address_space_size)              \
  EXPORT_INTERCEPTOR(32, suffix, address_space_size)

#ifdef _WIN64
namespace {
const size_t ONE_TB = static_cast<size_t>(1) << 40;
}
#endif

extern "C" {
void asan_init() {
  return;
}

void* asan_get_shadow_memory_dynamic_address() {
  return nullptr;
  NOTREACHED();
}

// Currently this is a dummy function.
// Returning zero means do not detect stack use after return.
// TODO (njanevsk): Implement this function.
int asan_should_detect_stack_use_after_return() {
  return 0;
}

// Currently this is a dummy function.
// This one always returns 0.
// TODO (njanevsk): Implement this function.
int asan_set_seh_filter() {
  return 0;
}

// TODO (njanevsk): Implement this function.
void asan_version_mismatch_check_v8() {
  return;
}

// TODO (njanevsk): Implement this function.
void asan_clang_no_check(const void*) {
  return;
}

// TODO (njanevsk): Implement this function.
void asan_handle_no_return() {
}

#ifdef _WIN64
void asan_string_no_check() {
  return;
}
const void* asan_shadow_references[] = {nullptr};
EXPORT_INTERCEPTORS_ALL_SIZES(8tb, 8 * ONE_TB - 1)
EXPORT_INTERCEPTORS_ALL_SIZES(128tb, 128 * ONE_TB - 1)
#else
EXPORT_INTERCEPTORS_ALL_SIZES(2gb, 0x7FFFFFFF)
EXPORT_INTERCEPTORS_ALL_SIZES(4gb, 0xFFFFFFFF)
#endif
}

#endif  // SYZYGY_AGENT_ASAN_MEMORY_INTERCEPTORS_IMPL_H_
