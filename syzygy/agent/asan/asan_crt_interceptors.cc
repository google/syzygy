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

#include "syzygy/agent/asan/asan_crt_interceptors.h"

#include <algorithm>

#include "base/logging.h"
#include "syzygy/agent/asan/asan_heap.h"
#include "syzygy/agent/asan/asan_rtl_utils.h"
#include "syzygy/agent/asan/shadow.h"

namespace {

using agent::asan::HeapProxy;
using agent::asan::Shadow;
using agent::asan::TestMemoryRange;

}  // namespace

extern "C" {

void* __cdecl asan_memcpy(unsigned char* destination,
                          const unsigned char* source,
                          size_t num) {
  TestMemoryRange(source, num, HeapProxy::ASAN_READ_ACCESS);
  TestMemoryRange(destination, num, HeapProxy::ASAN_WRITE_ACCESS);
  return ::memcpy(destination, source, num);
}

void* __cdecl asan_memmove(unsigned char* destination,
                           const unsigned char* source,
                           size_t num) {
  TestMemoryRange(source, num, HeapProxy::ASAN_READ_ACCESS);
  TestMemoryRange(destination, num, HeapProxy::ASAN_WRITE_ACCESS);
  return ::memmove(destination, source, num);
}

void* __cdecl asan_memset(unsigned char* ptr, int value, size_t num) {
  TestMemoryRange(ptr, num, HeapProxy::ASAN_WRITE_ACCESS);
  return ::memset(ptr, value, num);
}

const void* __cdecl asan_memchr(const unsigned char* ptr,
                                int value,
                                size_t num) {
  TestMemoryRange(ptr, num, HeapProxy::ASAN_READ_ACCESS);
  return ::memchr(ptr, value, num);
}

size_t __cdecl asan_strcspn(const char* str1, const char* str2) {
  // TODO(sebmarchand): Provide an implementation that guarantees the same
  //     behavior as the original function.
  NOTIMPLEMENTED();
  return 0;
}

size_t __cdecl asan_strlen(const char* str) {
  size_t size = 0;
  if (!agent::asan::Shadow::GetNullTerminatedArraySize<char>(str, 0U, &size)) {
    ReportBadAccess(reinterpret_cast<const uint8*>(str) + size,
                    HeapProxy::ASAN_READ_ACCESS);
    return ::strlen(str);
  }
  return size - 1;
}

const char* __cdecl asan_strrchr(const char* str, int character) {
  size_t size = 0;
  if (!agent::asan::Shadow::GetNullTerminatedArraySize<char>(str, 0U, &size)) {
    ReportBadAccess(reinterpret_cast<const uint8*>(str) + size,
                    HeapProxy::ASAN_READ_ACCESS);
  }
  return ::strrchr(str, character);
}

const wchar_t* asan_wcsrchr(const wchar_t* str, wchar_t character) {
  size_t size = 0;
  if (!agent::asan::Shadow::GetNullTerminatedArraySize<wchar_t>(str,
                                                                0U,
                                                                &size)) {
    ReportBadAccess(reinterpret_cast<const uint8*>(str) + size,
                    HeapProxy::ASAN_READ_ACCESS);
  }
  return ::wcsrchr(str, character);
}

const wchar_t* asan_wcsstr(const wchar_t* str, const wchar_t* keys) {
  size_t size = 0;
  if (!agent::asan::Shadow::GetNullTerminatedArraySize<wchar_t>(keys,
                                                                0U,
                                                                &size)) {
    ReportBadAccess(reinterpret_cast<const uint8*>(keys) + size,
                    HeapProxy::ASAN_READ_ACCESS);
  }
  const wchar_t* ret = ::wcsstr(str, keys);
  if (!agent::asan::Shadow::IsAccessible(ret)) {
    ReportBadAccess(reinterpret_cast<const uint8*>(ret),
                    HeapProxy::ASAN_READ_ACCESS);
  }
  return ret;
}

const wchar_t* asan_wcschr(const wchar_t* str, wchar_t character) {
  const wchar_t* s = str;
  while (agent::asan::Shadow::IsAccessible(s) && *s != character && *s != NULL)
    s++;
  if (!agent::asan::Shadow::IsAccessible(s)) {
    ReportBadAccess(reinterpret_cast<const uint8*>(s),
                    HeapProxy::ASAN_READ_ACCESS);
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
  if (num != 0U) {
    size_t src_size = 0;
    if (!agent::asan::Shadow::GetNullTerminatedArraySize<char>(source,
                                                               num,
                                                               &src_size) &&
        src_size <= num) {
      ReportBadAccess(reinterpret_cast<const uint8*>(source) + src_size,
                      HeapProxy::ASAN_READ_ACCESS);
    }
    // We can't use the GetNullTerminatedArraySize function here, as destination
    // might not be null terminated.
    TestMemoryRange(reinterpret_cast<const uint8*>(destination),
                    num,
                    HeapProxy::ASAN_WRITE_ACCESS);
  }
  return ::strncpy(destination, source, num);
}

char* __cdecl asan_strncat(char* destination, const char* source, size_t num) {
  if (num != 0U) {
    size_t src_size = 0;
    if (!agent::asan::Shadow::GetNullTerminatedArraySize<char>(source,
                                                               num,
                                                               &src_size) &&
        src_size <= num) {
      ReportBadAccess(reinterpret_cast<const uint8*>(source) + src_size,
                      HeapProxy::ASAN_READ_ACCESS);
    }
    size_t dst_size = 0;
    if (!agent::asan::Shadow::GetNullTerminatedArraySize<char>(destination,
                                                               0U,
                                                               &dst_size)) {
      ReportBadAccess(reinterpret_cast<const uint8*>(destination) + dst_size,
                      HeapProxy::ASAN_WRITE_ACCESS);
    } else {
      // Test if we can append the source to the destination.
      TestMemoryRange(reinterpret_cast<const uint8*>(destination + dst_size),
                      std::min(num, src_size),
                      HeapProxy::ASAN_WRITE_ACCESS);
    }
  }
  return ::strncat(destination, source, num);
}

}  // extern "C"
