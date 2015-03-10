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

#include <Windows.h>

#include "base/strings/string16.h"
#include "syzygy/kasko/api/kasko_export.h"
#include "syzygy/kasko/api/minidump_type.h"

namespace kasko {
namespace api {

// Represents a property to include in a diagnostic report. This structure is
// intended to have the same layout as a google_breakpad::CustomInfoEntry to
// facilitate maintenance of a single property store in clients.
struct CrashKey {
  // Maximum name length.
  static const int kNameMaxLength = 64;
  // Maximum value length.
  static const int kValueMaxLength = 64;

  // The name of the property.
  base::char16 name[kNameMaxLength];
  // The value of the property.
  base::char16 value[kValueMaxLength];
};

// Initializes a diagnostic reporting client in the current process.
// @param endpoint_name The RPC endpoint name shared with the reporter process.
KASKO_EXPORT void InitializeClient(const base::char16* endpoint_name);

// Shuts down and frees resources associated with the previously initialized
// client.
KASKO_EXPORT void ShutdownClient();

// Sends a diagnostic report for the current process.
// @param exception_info_address Optional exception information.
// @param minidump_type The type of minidump to be included in the report.
// @param protobuf An optional protobuf to be included in the report.
// @param protobuf_length The length of the protobuf.
// @param crash_keys An optional array of crash keys. Keys with empty names or
//     values will be ignored.
// @param crash_key_count The number of entries in crash_keys.
KASKO_EXPORT void SendReport(const EXCEPTION_POINTERS* exception_pointers,
                             MinidumpType minidump_type,
                             const char* protobuf,
                             size_t protobuf_length,
                             const CrashKey* crash_keys,
                             size_t crash_key_count);

}  // namespace api
}  // namespace kasko

#endif  // SYZYGY_KASKO_API_CLIENT_H_
