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

namespace kasko {
namespace api {

// Initializes a diagnostic reporting client in the current process.
// @param endpoint_name The RPC endpoint name shared with the reporter process.
KASKO_EXPORT void InitializeClient(const base::char16* endpoint_name);

// Shuts down and frees resources associated with the previously initialized
// client.
KASKO_EXPORT void ShutdownClient();

// Sends a diagnostic report for the current process.
// @param exception_info_address Optional exception information.
// @param protobuf An optional protobuf to be included in the report.
// @param protobuf_length The length of the protobuf.
// @param keys An optional null-terminated array of crash key names
// @param values An optional null-terminated array of crash key values. Must be
//     of equal length to |keys|.
KASKO_EXPORT void SendReport(const EXCEPTION_POINTERS* exception_pointers,
                             const char* protobuf,
                             size_t protobuf_length,
                             const base::char16* const* keys,
                             const base::char16* const* values);

}  // namespace api
}  // namespace kasko

#endif  // SYZYGY_KASKO_API_CLIENT_H_
