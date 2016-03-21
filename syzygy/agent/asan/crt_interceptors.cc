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

#include "syzygy/agent/asan/crt_interceptors.h"

#include <algorithm>

#include "base/logging.h"
#include "syzygy/agent/asan/error_info.h"
#include "syzygy/agent/asan/rtl_utils.h"
#include "syzygy/agent/asan/shadow.h"

namespace {

using agent::asan::Shadow;
using agent::asan::TestMemoryRange;

// The global shadow memory that is used by the CRT interceptors.
Shadow* crt_interceptor_shadow_ = nullptr;

}  // namespace

namespace agent {
namespace asan {

Shadow* SetCrtInterceptorShadow(Shadow* shadow) {
  Shadow* old_shadow = crt_interceptor_shadow_;
  crt_interceptor_shadow_ = shadow;
  return old_shadow;
}

}  // namespace asan
}  // namespace agent

extern "C" {

void* __cdecl asan_memcpy(void* destination,
                          const void* source,
                          size_t num) {
  TestMemoryRange(crt_interceptor_shadow_,
                  reinterpret_cast<const uint8_t*>(source), num,
                  agent::asan::ASAN_READ_ACCESS);
  TestMemoryRange(crt_interceptor_shadow_,
                  reinterpret_cast<uint8_t*>(destination), num,
                  agent::asan::ASAN_WRITE_ACCESS);
  return ::memcpy(destination, source, num);
}

void* __cdecl asan_memmove(void* destination,
                           const void* source,
                           size_t num) {
  TestMemoryRange(crt_interceptor_shadow_,
                  reinterpret_cast<const uint8_t*>(source), num,
                  agent::asan::ASAN_READ_ACCESS);
  TestMemoryRange(crt_interceptor_shadow_,
                  reinterpret_cast<uint8_t*>(destination), num,
                  agent::asan::ASAN_WRITE_ACCESS);
  return ::memmove(destination, source, num);
}

void* __cdecl asan_memset(void* ptr, int value, size_t num) {
  TestMemoryRange(crt_interceptor_shadow_,
                  reinterpret_cast<uint8_t*>(ptr), num,
                  agent::asan::ASAN_WRITE_ACCESS);
  return ::memset(ptr, value, num);
}

const void* __cdecl asan_memchr(const void* ptr,
                                int value,
                                size_t num) {
  TestMemoryRange(crt_interceptor_shadow_,
                  reinterpret_cast<const uint8_t*>(ptr), num,
                  agent::asan::ASAN_READ_ACCESS);
  return ::memchr(ptr, value, num);
}

size_t __cdecl asan_strcspn(const char* str1, const char* str2) {
  // TODO(sebmarchand): Provide an implementation that guarantees the same
  //     behavior as the original function.
  NOTIMPLEMENTED();
  return 0;
}

size_t __cdecl asan_strlen(const char* str) {
  if (!crt_interceptor_shadow_)
    return ::strlen(str);

  size_t size = 0;
  if (!crt_interceptor_shadow_->GetNullTerminatedArraySize<char>(str, 0U,
                                                                 &size)) {
    ReportBadAccess(reinterpret_cast<const uint8_t*>(str) + size,
                    agent::asan::ASAN_READ_ACCESS);
    return ::strlen(str);
  }
  return size - 1;
}

size_t __cdecl asan_strnlen(const char* str, size_t max_count) {
  if (!crt_interceptor_shadow_)
    return ::strnlen(str, max_count);

  size_t size = 0;
  if (!crt_interceptor_shadow_->GetNullTerminatedArraySize<char>(
          str, max_count, &size)) {
    ReportBadAccess(reinterpret_cast<const uint8_t*>(str) + size,
                    agent::asan::ASAN_READ_ACCESS);
    return ::strnlen(str, max_count);
  }
  return size - 1;
}

const char* __cdecl asan_strrchr(const char* str, int character) {
  if (!crt_interceptor_shadow_)
    return ::strrchr(str, character);

  size_t size = 0;
  if (!crt_interceptor_shadow_->GetNullTerminatedArraySize<char>(str, 0U,
                                                                 &size)) {
    ReportBadAccess(reinterpret_cast<const uint8_t*>(str) + size,
                    agent::asan::ASAN_READ_ACCESS);
  }
  return ::strrchr(str, character);
}

size_t __cdecl asan_wcsnlen(const wchar_t* str, size_t max_count) {
  if (!crt_interceptor_shadow_)
    return ::wcsnlen(str, max_count);

  // GetNullTerminatedArraySize always speaks in bytes.
  size_t size = 0;
  if (crt_interceptor_shadow_->GetNullTerminatedArraySize<wchar_t>(
          str, sizeof(wchar_t) * max_count, &size)) {
    return (size / sizeof(wchar_t)) - 1;
  }

  ReportBadAccess(reinterpret_cast<const uint8_t*>(str) + size,
                  agent::asan::ASAN_READ_ACCESS);
  return ::wcsnlen(str, max_count);
}

const wchar_t* asan_wcsrchr(const wchar_t* str, wchar_t character) {
  if (!crt_interceptor_shadow_)
    return ::wcsrchr(str, character);

  size_t size = 0;
  if (!crt_interceptor_shadow_->GetNullTerminatedArraySize<wchar_t>(str, 0U,
                                                                    &size)) {
    ReportBadAccess(reinterpret_cast<const uint8_t*>(str) + size,
                    agent::asan::ASAN_READ_ACCESS);
  }
  return ::wcsrchr(str, character);
}

const wchar_t* asan_wcsstr(const wchar_t* str, const wchar_t* keys) {
  if (!crt_interceptor_shadow_)
    return ::wcsstr(str, keys);

  size_t size = 0;
  if (!crt_interceptor_shadow_->GetNullTerminatedArraySize<wchar_t>(keys, 0U,
                                                                    &size)) {
    ReportBadAccess(reinterpret_cast<const uint8_t*>(keys) + size,
                    agent::asan::ASAN_READ_ACCESS);
  }
  const wchar_t* ret = ::wcsstr(str, keys);
  if (ret != NULL && !crt_interceptor_shadow_->IsAccessible(ret)) {
    ReportBadAccess(reinterpret_cast<const uint8_t*>(ret),
                    agent::asan::ASAN_READ_ACCESS);
  }
  return ret;
}

const wchar_t* asan_wcschr(const wchar_t* str, wchar_t character) {
  if (!crt_interceptor_shadow_)
    return ::wcschr(str, character);

  const wchar_t* s = str;
  while (crt_interceptor_shadow_->IsAccessible(s) && *s != character &&
         *s != NULL) {
    s++;
  }
  if (!crt_interceptor_shadow_->IsAccessible(s)) {
    ReportBadAccess(reinterpret_cast<const uint8_t*>(s),
                    agent::asan::ASAN_READ_ACCESS);
    return ::wcschr(str, character);
  }
  if (*s == NULL)
    return NULL;
  return s;
}

int __cdecl asan_strcmp(const char* str1, const char* str2) {
  // TODO(sebmarchand): Provide an implementation that guarantees the same
  //     behavior as the original function.
  NOTIMPLEMENTED();
  return 0;
}

const char* __cdecl asan_strpbrk(const char* str1, const char* str2) {
  // TODO(sebmarchand): Provide an implementation that guarantees the same
  //     behavior as the original function.
  NOTIMPLEMENTED();
  return NULL;
}

const char* __cdecl asan_strstr(const char* str1, const char* str2) {
  // TODO(sebmarchand): Provide an implementation that guarantees the same
  //     behavior as the original function.
  NOTIMPLEMENTED();
  return NULL;
}

size_t __cdecl asan_strspn(const char* str1, const char* str2) {
  // TODO(sebmarchand): Provide an implementation that guarantees the same
  //     behavior as the original function.
  NOTIMPLEMENTED();
  return 0;
}

char* __cdecl asan_strncpy(char* destination, const char* source, size_t num) {
  if (!crt_interceptor_shadow_)
    return ::strncpy(destination, source, num);

  if (num != 0U) {
    size_t src_size = 0;
    if (!crt_interceptor_shadow_->GetNullTerminatedArraySize<char>(source, num,
                                                                   &src_size) &&
        src_size <= num) {
      ReportBadAccess(reinterpret_cast<const uint8_t*>(source) + src_size,
                      agent::asan::ASAN_READ_ACCESS);
    }
    // We can't use the GetNullTerminatedArraySize function here, as destination
    // might not be null terminated.
    TestMemoryRange(crt_interceptor_shadow_,
                    reinterpret_cast<const uint8_t*>(destination), num,
                    agent::asan::ASAN_WRITE_ACCESS);
  }
  return ::strncpy(destination, source, num);
}

char* __cdecl asan_strncat(char* destination, const char* source, size_t num) {
  if (!crt_interceptor_shadow_)
    return ::strncat(destination, source, num);

  if (num != 0U) {
    size_t src_size = 0;
    if (!crt_interceptor_shadow_->GetNullTerminatedArraySize<char>(source, num,
                                                                   &src_size) &&
        src_size <= num) {
      ReportBadAccess(reinterpret_cast<const uint8_t*>(source) + src_size,
                      agent::asan::ASAN_READ_ACCESS);
    }
    size_t dst_size = 0;
    if (!crt_interceptor_shadow_->GetNullTerminatedArraySize<char>(
            destination, 0U, &dst_size)) {
      ReportBadAccess(reinterpret_cast<const uint8_t*>(destination) + dst_size,
                      agent::asan::ASAN_WRITE_ACCESS);
    } else {
      // Test if we can append the source to the destination.
      TestMemoryRange(crt_interceptor_shadow_,
                      reinterpret_cast<const uint8_t*>(destination + dst_size),
                      std::min(num, src_size), agent::asan::ASAN_WRITE_ACCESS);
    }
  }
  return ::strncat(destination, source, num);
}

}  // extern "C"
