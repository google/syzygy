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

#include "syzygy/kasko/api/client.h"

#include <vector>

#include "base/logging.h"
#include "syzygy/kasko/client.h"
#include "syzygy/kasko/dll_lifetime.h"

namespace kasko {
namespace api {

namespace {

static_assert(sizeof(CrashKey) == 256u,
              "CrashKey struct size must match that of the "
              "google_breakpad::CustomInfoEntry struct.");

const DllLifetime* g_dll_lifetime;
const Client* g_client = nullptr;

// Returns true if |buffer| is a null-terminated string whose length is greater
// than 0 and less than |buffer_length|.
bool IsValidNonEmptyString(const base::char16* buffer, size_t buffer_length) {
  size_t string_length = ::wcsnlen(buffer, buffer_length);
  return string_length > 0 && string_length < buffer_length;
}

}  // namespace

void InitializeClient(const base::char16* endpoint_name) {
  DCHECK(!g_dll_lifetime);
  g_dll_lifetime = new DllLifetime;

  DCHECK(!g_client);
  DCHECK(endpoint_name);
  g_client = new Client(endpoint_name);
}

void SendReport(const EXCEPTION_POINTERS* exception_pointers,
                const char* protobuf,
                size_t protobuf_length,
                const CrashKey* crash_keys,
                size_t crash_key_count) {
  if (!g_client) {
    LOG(ERROR) << "SendReport failed: uninitialized.";
    return;
  }
  std::vector<const base::char16*> keys;
  std::vector<const base::char16*> values;
  for (size_t i = 0; i < crash_key_count; ++i) {
    if (!IsValidNonEmptyString(crash_keys[i].name,
                               arraysize(crash_keys[i].name)) ||
        !IsValidNonEmptyString(crash_keys[i].value,
                               arraysize(crash_keys[i].value))) {
      continue;
    }
    keys.push_back(crash_keys[i].name);
    values.push_back(crash_keys[i].value);
  }
  keys.push_back(nullptr);
  values.push_back(nullptr);
  g_client->SendReport(exception_pointers, protobuf, protobuf_length,
                       keys.data(), values.data());
}

void ShutdownClient() {
  DCHECK(g_client);
  delete g_client;
  g_client = nullptr;
}

}  // namespace api
}  // namespace kasko
