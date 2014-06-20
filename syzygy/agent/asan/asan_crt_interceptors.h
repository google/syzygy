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
// Defines the ASan CRT interceptors.
#ifndef SYZYGY_AGENT_ASAN_ASAN_CRT_INTERCEPTORS_H_
#define SYZYGY_AGENT_ASAN_ASAN_CRT_INTERCEPTORS_H_

// Exposes the CRT interceptors.
extern "C" {

void* __cdecl asan_memcpy(unsigned char* destination,
                          const unsigned char* source,
                          size_t num);

void* __cdecl asan_memmove(unsigned char* destination,
                           const unsigned char* source,
                           size_t num);

void* __cdecl asan_memset(unsigned char* ptr, int value, size_t num);

const void* __cdecl asan_memchr(const unsigned char* ptr,
                                int value,
                                size_t num);

size_t __cdecl asan_strcspn(const char* str1, const char* str2);

size_t __cdecl asan_strlen(const char* str);

const char* __cdecl asan_strrchr(const char* str, int character);

const wchar_t* asan_wcsrchr(const wchar_t* str, wchar_t character);

const wchar_t* asan_wcschr(const wchar_t* str, wchar_t character);

int __cdecl asan_strcmp(const char* str1, const char* str2);

const char* __cdecl asan_strpbrk(const char* str1, const char* str2);

const char* __cdecl asan_strstr(const char* str1, const char* str2);

const wchar_t* asan_wcsstr(const wchar_t* str, const wchar_t* keys);

size_t __cdecl asan_strspn(const char* str1, const char* str2);

char* __cdecl asan_strncpy(char* destination, const char* source, size_t num);

char* __cdecl asan_strncat(char* destination, const char* source, size_t num);

}  // extern "C"

#endif  // SYZYGY_AGENT_ASAN_ASAN_CRT_INTERCEPTORS_H_
