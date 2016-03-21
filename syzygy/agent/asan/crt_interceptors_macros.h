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
// Macros for dealing with CRT interceptors.

#ifndef SYZYGY_AGENT_ASAN_CRT_INTERCEPTORS_MACROS_H_
#define SYZYGY_AGENT_ASAN_CRT_INTERCEPTORS_MACROS_H_

// Macros for building CRT interceptors. The format is:
// (0:calling_convention, 1:return_value, 2:function_name, 3:args, 4:arg_names,
//  5...:user_data ...)
#define ASAN_CRT_INTERCEPTORS(F, ...)  \
    F(__cdecl, void*, memcpy,  \
      (void* destination, const void* source,  size_t num),  \
      (destination, source, num), __VA_ARGS__)  \
    F(__cdecl, void*, memmove,  \
      (void* destination, const void* source, size_t num),  \
      (destination, source, num), __VA_ARGS__)  \
    F(__cdecl, void*, memset, (void* ptr, int value, size_t num),  \
      (ptr, value, num), __VA_ARGS__)  \
    F(__cdecl, const void*, memchr,  \
      (const void* ptr, int value, size_t num),  \
      (ptr, value, num), __VA_ARGS__)  \
    F(__cdecl, size_t, strcspn, (const char* str1, const char* str2),  \
      (str1, str2), __VA_ARGS__)  \
    F(__cdecl, size_t, strlen, (const char* str), (str), __VA_ARGS__)  \
    F(__cdecl, size_t, strnlen, (const char* str, size_t max_len),  \
      (str, max_len), __VA_ARGS__)  \
    F(__cdecl, const char*, strrchr, (const char* str, int character),  \
      (str, character), __VA_ARGS__)  \
    F(__cdecl, const wchar_t*, wcsrchr,  \
      (const wchar_t* str, wchar_t character),  \
      (str, character), __VA_ARGS__)  \
    F(__cdecl, const wchar_t*, wcschr,  \
      (const wchar_t* str, wchar_t character),  \
      (str, character), __VA_ARGS__)  \
    F(__cdecl, int, strcmp, (const char* str1, const char* str2),  \
      (str1, str2), __VA_ARGS__)  \
    F(__cdecl, const char*, strpbrk, (const char* str1, const char* str2),  \
      (str1, str2), __VA_ARGS__)  \
    F(__cdecl, const char*, strstr, (const char* str1, const char* str2),  \
      (str1, str2), __VA_ARGS__)  \
    F(__cdecl, size_t, wcsnlen, (const wchar_t* str, size_t max_len),  \
      (str, max_len), __VA_ARGS__)  \
    F(__cdecl, const wchar_t*, wcsstr, (const wchar_t* str1,  \
      const wchar_t* str2), (str1, str2), __VA_ARGS__)  \
    F(__cdecl, size_t, strspn, (const char* str1, const char* str2),  \
      (str1, str2), __VA_ARGS__)  \
    F(__cdecl, char*, strncpy,  \
      (char* destination, const char* source, size_t num),  \
      (destination, source, num), __VA_ARGS__)  \
    F(__cdecl, char*, strncat,  \
      (char* destination, const char* source, size_t num),  \
      (destination, source, num), __VA_ARGS__)

// Generates CRT interceptor function declarations.
#define ASAN_CRT_INTERCEPTORS_DECL(calling_convention,  \
                                   return_value,  \
                                   function_name,  \
                                   args,  \
                                   arg_names,  \
                                   prefix)  \
    return_value calling_convention prefix ## function_name args;

// Generates pass-through implementations of CRT interceptors.
#define ASAN_CRT_INTERCEPTORS_DEFN(calling_convention,  \
                                   return_value,  \
                                   function_name,  \
                                   args,  \
                                   arg_names,  \
                                   prefix)  \
    return_value calling_convention prefix ## function_name args {  \
      return :: function_name arg_names;  \
    }

#endif  // SYZYGY_AGENT_ASAN_CRT_INTERCEPTORS_MACROS_H_
