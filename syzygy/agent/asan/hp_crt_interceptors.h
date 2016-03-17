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
// Defines the Asan Hot Patching CRT interceptors.
//
// Hot Patching Asan transformed links modules against these functions
// instead of the CRT ones. When hot patching is inactive, these functions
// call the respective system functions.
// TODO(cseri): When hot patching Asan mode is activated, the import entries
// of these functions must be overwritten to call the respective functions
// from the SyzyAsan runtime library.
#ifndef SYZYGY_AGENT_ASAN_HP_CRT_INTERCEPTORS_H_
#define SYZYGY_AGENT_ASAN_HP_CRT_INTERCEPTORS_H_

// Exposes the CRT interceptors.
extern "C" {

const void* __cdecl hp_asan_memchr(const unsigned char* ptr,
                                   int value,
                                   size_t num);

void* __cdecl hp_asan_memcpy(unsigned char* destination,
                             const unsigned char* source,
                             size_t num);

void* __cdecl hp_asan_memmove(unsigned char* destination,
                         const unsigned char* source,
                         size_t num);

void* __cdecl hp_asan_memset(unsigned char* ptr, int value, size_t num);

int __cdecl hp_asan_strcmp(const char* str1, const char* str2);

size_t __cdecl hp_asan_strcspn(const char* str1, const char* str2);

size_t __cdecl hp_asan_strlen(const char* str);

size_t __cdecl hp_asan_strnlen(const char* str, size_t max_len);

char* __cdecl hp_asan_strncat(char* destination,
                              const char* source,
                              size_t num);

char* __cdecl hp_asan_strncpy(char* destination,
                              const char* source,
                              size_t num);

const char* __cdecl hp_asan_strpbrk(const char* str1, const char* str2);

const char* __cdecl hp_asan_strrchr(const char* str, int character);

size_t __cdecl hp_asan_strspn(const char* str1, const char* str2);

const char* __cdecl hp_asan_strstr(const char* str1, const char* str2);

const wchar_t* hp_asan_wcschr(const wchar_t* str, wchar_t character);

const wchar_t* hp_asan_wcsrchr(const wchar_t* str, wchar_t character);

const wchar_t* hp_asan_wcsstr(const wchar_t* str, const wchar_t* keys);

}  // extern "C"

#endif  // SYZYGY_AGENT_ASAN_HP_CRT_INTERCEPTORS_H_
