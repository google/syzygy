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

#ifndef SYZYGY_KASKO_API_CLIENT_H_
#define SYZYGY_KASKO_API_CLIENT_H_

#include <windows.h>

#include "base/strings/string16.h"
#include "syzygy/kasko/api/crash_key.h"
#include "syzygy/kasko/api/kasko_export.h"
#include "syzygy/kasko/api/minidump_type.h"

namespace kasko {
namespace api {

// The stream type assigned to the protobuf stream in the uploaded minidump
// file. 0x4B6B is 'Kk'.
const uint32_t kProtobufStreamType = 0x4B6B0001;

struct MemoryRange {
  // The start of the range.
  const void* base_address;
  // The length of the range.
  size_t length;
};

// Initializes a diagnostic reporting client in the current process.
// @param endpoint_name The RPC endpoint name shared with the reporter process.
KASKO_EXPORT void InitializeClient(const base::char16* endpoint_name);

// Shuts down and frees resources associated with the previously initialized
// client.
KASKO_EXPORT void ShutdownClient();

// Registers the address of an array of crash keys. These crash keys will be
// included with any crash report that might be triggered. This method must only
// be called once per process.
// @param crash_keys An array of crash keys. Keys with empty names or values
//     will be ignored.
// @param crash_key_count The number of entries in crash_keys.
KASKO_EXPORT void RegisterCrashKeys(const CrashKey* crash_keys,
                                    size_t crash_key_count);

// Sends a diagnostic report for the current process.
// @param exception_info_address Optional exception information.
// @param minidump_type The type of minidump to be included in the report.
// @param protobuf An optional protobuf to be included in the report.
// @param protobuf_length The length of the protobuf.
// @param crash_keys An optional array of crash keys. Keys with empty names or
//     values will be ignored.
// @param crash_key_count The number of entries in crash_keys.
// @param user_selected_memory_ranges An optional array of memory ranges to be
//     included in the report.
// @param user_selected_memory_range_count The number of entries in
//     user_selected_memory_ranges..
KASKO_EXPORT void SendReport(const EXCEPTION_POINTERS* exception_pointers,
                             MinidumpType minidump_type,
                             const char* protobuf,
                             size_t protobuf_length,
                             const CrashKey* crash_keys,
                             size_t crash_key_count,
                             const MemoryRange* user_selected_memory_ranges,
                             size_t user_selected_memory_range_count);

}  // namespace api
}  // namespace kasko

#endif  // SYZYGY_KASKO_API_CLIENT_H_
