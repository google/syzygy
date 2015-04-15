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

#include "syzygy/agent/asan/asan_hp_crt_interceptors.h"

#include <cstring>

extern "C" {

const void* __cdecl hp_memchr(const unsigned char* ptr,
                              int value,
                              size_t num) {
  return ::memchr(ptr, value, num);
}

void* __cdecl hp_memcpy(unsigned char* destination,
                        const unsigned char* source,
                        size_t num) {
  return ::memcpy(destination, source, num);
}

void* __cdecl hp_memmove(unsigned char* destination,
                         const unsigned char* source,
                         size_t num) {
  return ::memmove(destination, source, num);
}

void* __cdecl hp_memset(unsigned char* ptr, int value, size_t num) {
  return ::memset(ptr, value, num);
}

int __cdecl hp_strcmp(const char* str1, const char* str2) {
  return ::strcmp(str1, str2);
}

size_t __cdecl hp_strcspn(const char* str1, const char* str2) {
  return ::strcspn(str1, str2);
}

size_t __cdecl hp_strlen(const char* str) {
  return ::strlen(str);
}

const char* __cdecl hp_strpbrk(const char* str1, const char* str2) {
  return ::strpbrk(str1, str2);
}

const char* __cdecl hp_strrchr(const char* str, int character) {
  return ::strrchr(str, character);
}

char* __cdecl hp_strncat(char* destination, const char* source, size_t num) {
  return ::strncat(destination, source, num);
}

char* __cdecl hp_strncpy(char* destination, const char* source, size_t num) {
  return ::strncpy(destination, source, num);
}

const char* __cdecl hp_strstr(const char* str1, const char* str2) {
  return ::strstr(str1, str2);
}

size_t __cdecl hp_strspn(const char* str1, const char* str2) {
  return ::strspn(str1, str2);
}

const wchar_t* hp_wcschr(const wchar_t* str, wchar_t character) {
  return ::wcschr(str, character);
}

const wchar_t* hp_wcsrchr(const wchar_t* str, wchar_t character) {
  return ::wcsrchr(str, character);
}

const wchar_t* hp_wcsstr(const wchar_t* str, const wchar_t* keys) {
  return ::wcsstr(str, keys);
}

}  // extern "C"
