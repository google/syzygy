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

#ifndef SYZYGY_KASKO_MINIDUMP_REQUEST_H_
#define SYZYGY_KASKO_MINIDUMP_REQUEST_H_

#include <stdint.h>

#include <utility>
#include <vector>

#include "base/strings/string16.h"
#include "syzygy/core/address_range.h"

namespace kasko {

// Represents the inputs of a minidump request.
struct MinidumpRequest {
  // Specifies the type of Minidump to be included in a report.
  enum Type {
    // Minidump with stacks, PEB, TEB, and unloaded module list.
    SMALL_DUMP_TYPE,

    // Minidump with all of the above, plus memory referenced from stack.
    LARGER_DUMP_TYPE,

    // Large dump with all process memory.
    FULL_DUMP_TYPE
  };

  // Represents a custom stream to be included in the generated minidump.
  struct CustomStream {
    uint32_t type;
    const void* data;
    size_t length;
  };

  // Represents a user-selected memory range to be included in the generated
  // minidump.
  using MemoryRange = core::AddressRange<uint32_t, uint32_t>;

  // Represents a single crash key and its value.
  using CrashKey = std::pair<const base::char16*, const base::char16*>;

  // Instantiates a default request.
  MinidumpRequest();
  ~MinidumpRequest();

  // The requested dump type (default: SMALL_DUMP_TYPE).
  Type type;

  // True if exception_info_address is valid in the client process; false
  // otherwise.
  bool client_exception_pointers;

  // The address of an EXCEPTION_POINTERS structure (optional, default: 0).
  uint32_t exception_info_address;

  // Crash keys to be included with the report (default: empty).
  std::vector<CrashKey> crash_keys;

  // Custom streams to be included with the report (default: empty).
  std::vector<CustomStream> custom_streams;

  // User-selected memory ranges to be included in the minidump.
  std::vector<MemoryRange> user_selected_memory_ranges;
};

}  // namespace kasko

#endif  // SYZYGY_KASKO_MINIDUMP_REQUEST_H_
