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
// Dummy CRT interceptors for the memory profiler. This is simply for
// maintaining ABI compatibility.

#include <string.h>

extern "C" {

void* asan_memcpy(void* dst, const void* src, size_t size) {
  return ::memcpy(dst, src, size);
}

void* asan_memmove(void* dst, const void* src, size_t size) {
  return ::memmove(dst, src, size);
}

void* asan_memset(void* dst, int val, size_t size) {
  return ::memset(dst, val, size);
}

const void* asan_memchr(const void* buf, int val, size_t max_count) {
  return ::memchr(buf, val, max_count);
}

size_t asan_strcspn(const char* str, const  char* control) {
  return ::strcspn(str, control);
}

size_t asan_strlen(const char* str) {
  return ::strlen(str);
}

const char* asan_strrchr(const char* str, int ch) {
  return ::strrchr(str, ch);
}

wchar_t* asan_wcsrchr(wchar_t* str, wchar_t ch) {
  return ::wcsrchr(str, ch);
}

wchar_t* asan_wcschr(wchar_t* str, wchar_t ch) {
  return ::wcschr(str, ch);
}

int asan_strcmp(const char* str1, const char* str2) {
  return ::strcmp(str1, str2);
}

const char* asan_strpbrk(const char* str, const char* control) {
  return ::strpbrk(str, control);
}

const char* asan_strstr(const char* str, const char* substr) {
  return ::strstr(str, substr);
}

const wchar_t* asan_wcsstr(const wchar_t* str, const wchar_t* substr) {
  return ::wcsstr(str, substr);
}

size_t asan_strspn(const char* str, const char* control) {
  return ::strspn(str, control);
}

char* asan_strncpy(char* dst, const char* src, size_t count) {
  return ::strncpy(dst, src, count);
}

char* asan_strncat(char* dst, char* src, size_t count) {
  return ::strncat(dst, src, count);
}

}  // extern "C"
