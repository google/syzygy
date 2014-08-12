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

namespace agent {
namespace asan {

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

#define ASAN_STRING_INTERCEPT_FUNCTIONS(F) \
    F(cmps, _repz_, ecx, AsanReadAccess, AsanReadAccess, 4, 1) \
    F(cmps, _repz_, ecx, AsanReadAccess, AsanReadAccess, 2, 1) \
    F(cmps, _repz_, ecx, AsanReadAccess, AsanReadAccess, 1, 1) \
    F(cmps, _, 1, AsanReadAccess, AsanReadAccess, 4, 1) \
    F(cmps, _, 1, AsanReadAccess, AsanReadAccess, 2, 1) \
    F(cmps, _, 1, AsanReadAccess, AsanReadAccess, 1, 1) \
    F(movs, _repz_, ecx, AsanWriteAccess, AsanReadAccess, 4, 0) \
    F(movs, _repz_, ecx, AsanWriteAccess, AsanReadAccess, 2, 0) \
    F(movs, _repz_, ecx, AsanWriteAccess, AsanReadAccess, 1, 0) \
    F(movs, _, 1, AsanWriteAccess, AsanReadAccess, 4, 0) \
    F(movs, _, 1, AsanWriteAccess, AsanReadAccess, 2, 0) \
    F(movs, _, 1, AsanWriteAccess, AsanReadAccess, 1, 0) \
    F(stos, _repz_, ecx, AsanWriteAccess, AsanUnknownAccess, 4, 0) \
    F(stos, _repz_, ecx, AsanWriteAccess, AsanUnknownAccess, 2, 0) \
    F(stos, _repz_, ecx, AsanWriteAccess, AsanUnknownAccess, 1, 0) \
    F(stos, _, 1, AsanWriteAccess, AsanUnknownAccess, 4, 0) \
    F(stos, _, 1, AsanWriteAccess, AsanUnknownAccess, 2, 0) \
    F(stos, _, 1, AsanWriteAccess, AsanUnknownAccess, 1, 0)

}  // namespace asan
}  // namespace agent

extern "C" {

#define DECLARE_MEM_INTERCEPT_FUNCTIONS(access_size, \
                                        access_mode_str, \
                                        access_mode_value) \
    void asan_check_ ## access_size ## _byte_ ## access_mode_str(); \
    void asan_check_ ## access_size ## _byte_ ## access_mode_str ## _no_flags();

// Declare all the memory interceptor functions. Note that these functions have
// a custom calling convention, and can't be invoked directly.
ASAN_MEM_INTERCEPT_FUNCTIONS(DECLARE_MEM_INTERCEPT_FUNCTIONS)

#undef DECLARE_MEM_INTERCEPT_FUNCTIONS

#define DECLARE_STRING_INTERCEPT_FUNCTIONS(func, prefix, counter, dst_mode, \
                                           src_mode, access_size, compare) \
  void asan_check ## prefix ## access_size ## _byte_ ## func ## _access();

// Declare all the string instruction interceptor functions. Note that these
// functions have a custom calling convention, and can't be invoked directly.
ASAN_STRING_INTERCEPT_FUNCTIONS(DECLARE_STRING_INTERCEPT_FUNCTIONS)

#undef DECLARE_STRING_INTERCEPT_FUNCTIONS

}

#endif  // SYZYGY_AGENT_ASAN_MEMORY_INTERCEPTORS_H_
