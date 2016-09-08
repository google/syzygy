// Copyright 2012 Google Inc. All Rights Reserved.
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

extern "C" {

// Memory probes are called with EDX on the stack, and the address to be
// checked in EDX. Thus, the top of the stack is the return address and below
// that is the original value of EDX.
#define DEFINE_NULL_MEMORY_PROBE(name)  \
  void __declspec(naked) name() {  \
    /* Restore the value of EDX. */  \
    __asm mov edx, DWORD PTR[esp + 4]  \
    /* Return and pop the saved EDX value off the stack. */  \
    __asm ret 4  \
  }

// Special instruction takes their addresses directly in some known registers,
// so no extra information gets pushed onto the stack and there's nothing to
// clean, we can simply return.
#define DEFINE_NULL_SPECIAL_PROBE(name)  \
  void __declspec(naked) name() {  \
    __asm ret  \
  }

// Define all of the null memory probes.
DEFINE_NULL_MEMORY_PROBE(asan_check_1_byte_read_access);
DEFINE_NULL_MEMORY_PROBE(asan_check_2_byte_read_access);
DEFINE_NULL_MEMORY_PROBE(asan_check_4_byte_read_access);
DEFINE_NULL_MEMORY_PROBE(asan_check_8_byte_read_access);
DEFINE_NULL_MEMORY_PROBE(asan_check_10_byte_read_access);
DEFINE_NULL_MEMORY_PROBE(asan_check_16_byte_read_access);
DEFINE_NULL_MEMORY_PROBE(asan_check_32_byte_read_access);
DEFINE_NULL_MEMORY_PROBE(asan_check_1_byte_write_access);
DEFINE_NULL_MEMORY_PROBE(asan_check_2_byte_write_access);
DEFINE_NULL_MEMORY_PROBE(asan_check_4_byte_write_access);
DEFINE_NULL_MEMORY_PROBE(asan_check_8_byte_write_access);
DEFINE_NULL_MEMORY_PROBE(asan_check_10_byte_write_access);
DEFINE_NULL_MEMORY_PROBE(asan_check_16_byte_write_access);
DEFINE_NULL_MEMORY_PROBE(asan_check_32_byte_write_access);
DEFINE_NULL_MEMORY_PROBE(asan_check_1_byte_read_access_no_flags);
DEFINE_NULL_MEMORY_PROBE(asan_check_2_byte_read_access_no_flags);
DEFINE_NULL_MEMORY_PROBE(asan_check_4_byte_read_access_no_flags);
DEFINE_NULL_MEMORY_PROBE(asan_check_8_byte_read_access_no_flags);
DEFINE_NULL_MEMORY_PROBE(asan_check_10_byte_read_access_no_flags);
DEFINE_NULL_MEMORY_PROBE(asan_check_16_byte_read_access_no_flags);
DEFINE_NULL_MEMORY_PROBE(asan_check_32_byte_read_access_no_flags);
DEFINE_NULL_MEMORY_PROBE(asan_check_1_byte_write_access_no_flags);
DEFINE_NULL_MEMORY_PROBE(asan_check_2_byte_write_access_no_flags);
DEFINE_NULL_MEMORY_PROBE(asan_check_4_byte_write_access_no_flags);
DEFINE_NULL_MEMORY_PROBE(asan_check_8_byte_write_access_no_flags);
DEFINE_NULL_MEMORY_PROBE(asan_check_10_byte_write_access_no_flags);
DEFINE_NULL_MEMORY_PROBE(asan_check_16_byte_write_access_no_flags);
DEFINE_NULL_MEMORY_PROBE(asan_check_32_byte_write_access_no_flags);
DEFINE_NULL_SPECIAL_PROBE(asan_check_repz_1_byte_cmps_access);
DEFINE_NULL_SPECIAL_PROBE(asan_check_repz_2_byte_cmps_access);
DEFINE_NULL_SPECIAL_PROBE(asan_check_repz_4_byte_cmps_access);
DEFINE_NULL_SPECIAL_PROBE(asan_check_repz_1_byte_lods_access);
DEFINE_NULL_SPECIAL_PROBE(asan_check_repz_2_byte_lods_access);
DEFINE_NULL_SPECIAL_PROBE(asan_check_repz_4_byte_lods_access);
DEFINE_NULL_SPECIAL_PROBE(asan_check_repz_1_byte_movs_access);
DEFINE_NULL_SPECIAL_PROBE(asan_check_repz_2_byte_movs_access);
DEFINE_NULL_SPECIAL_PROBE(asan_check_repz_4_byte_movs_access);
DEFINE_NULL_SPECIAL_PROBE(asan_check_repz_1_byte_stos_access);
DEFINE_NULL_SPECIAL_PROBE(asan_check_repz_2_byte_stos_access);
DEFINE_NULL_SPECIAL_PROBE(asan_check_repz_4_byte_stos_access);
DEFINE_NULL_SPECIAL_PROBE(asan_check_1_byte_cmps_access);
DEFINE_NULL_SPECIAL_PROBE(asan_check_2_byte_cmps_access);
DEFINE_NULL_SPECIAL_PROBE(asan_check_4_byte_cmps_access);
DEFINE_NULL_SPECIAL_PROBE(asan_check_1_byte_lods_access);
DEFINE_NULL_SPECIAL_PROBE(asan_check_2_byte_lods_access);
DEFINE_NULL_SPECIAL_PROBE(asan_check_4_byte_lods_access);
DEFINE_NULL_SPECIAL_PROBE(asan_check_1_byte_movs_access);
DEFINE_NULL_SPECIAL_PROBE(asan_check_2_byte_movs_access);
DEFINE_NULL_SPECIAL_PROBE(asan_check_4_byte_movs_access);
DEFINE_NULL_SPECIAL_PROBE(asan_check_1_byte_stos_access);
DEFINE_NULL_SPECIAL_PROBE(asan_check_2_byte_stos_access);
DEFINE_NULL_SPECIAL_PROBE(asan_check_4_byte_stos_access);
#undef DEFINE_NULL_MEMORY_PROBE
#undef DEFINE_NULL_STRING_PROBE

}  // extern "C"
