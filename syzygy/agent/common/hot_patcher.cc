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

#include "syzygy/agent/common/hot_patcher.h"

#include <stdint.h>
#include <windows.h>

#include "base/logging.h"
#include "syzygy/common/com_utils.h"

namespace agent {
namespace common {

bool HotPatcher::Patch(FunctionPointer function_entry_point,
                       FunctionPointer new_entry_point) {
  // The hot patching starts 5 bytes before the entry point of the function.
  uint8_t* hot_patch_start =
      reinterpret_cast<uint8_t*>(function_entry_point) - 5;
  const size_t hot_patch_length = 7U;

  // Change the page protection so that we can write.
  MEMORY_BASIC_INFORMATION memory_info;
  DWORD old_page_protection = 0;

  if (!::VirtualQuery(hot_patch_start, &memory_info, sizeof(memory_info))) {
    LOG(ERROR) << "Could not execute VirtualQuery(). Error code: "
               << ::common::LogWe();
    return false;
  }

  DWORD is_executable = (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                         PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY) &
                        memory_info.Protect;

  if (!::VirtualProtect(reinterpret_cast<LPVOID>(hot_patch_start),
                        hot_patch_length,
                        is_executable ? PAGE_EXECUTE_READWRITE :
                                        PAGE_READWRITE,
                        &old_page_protection)) {
    LOG(ERROR) << "Could not grant write privileges to page. Error code: "
               << ::common::LogWe();
    return false;
  }

  // The location where we have to write the PC-relative address of the new
  // entry point.
  int32_t* new_entry_point_place =
      reinterpret_cast<int32_t*>(hot_patch_start + 1);

  // The instrumenter uses 0xCC bytes for block padding. Before writing we check
  // if the target bytes contain these bytes.
  DCHECK_EQ(*hot_patch_start, 0xCC);
  DCHECK_EQ(*new_entry_point_place, static_cast<int>(0xCCCCCCCC));

  // Write the JMP instruction in the padding.
  // 0xE9 [32-bit PC-relative address]
  *hot_patch_start = 0xE9;
  *new_entry_point_place =
      reinterpret_cast<uint8_t*>(new_entry_point) - hot_patch_start - 5;

  // This is the location where the short jump overwriting the first two bytes
  // of the function should be placed.
  volatile uint16_t* jump_hook_place =
      reinterpret_cast<uint16_t*>(hot_patch_start + 5);

  // Writes on x86 architecture are atomic within a cross 4-byte boundary.
  // NOTE: This can be loosened. Any two bytes starting at an address that meets
  //     the (address % 4 != 3) condition does not cross 4-byte boundary.
  CHECK_EQ(0u, reinterpret_cast<uintptr_t>(jump_hook_place) % 2);

  // We write the instruction JMP -5 which is represented as: 0xEB 0xF9
  // We reverse the order of the bytes because of the little endian encoding
  // to get the final value 0xF9EB.
  *jump_hook_place = 0xF9EB;

  // Restore the old page protection.
  if (!::VirtualProtect(reinterpret_cast<LPVOID>(hot_patch_start),
                        hot_patch_length,
                        old_page_protection,
                        &old_page_protection)) {
    // We do not return false if this fails as the hot patching already
    // happened.
    LOG(ERROR) << "Could not reset old privileges to page. Error code: "
               << ::common::LogWe();
  }

  return true;
}

}  // namespace common
}  // namespace agent
