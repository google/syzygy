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

#include "base/logging.h"
#include "syzygy/kasko/client.h"

namespace kasko {
namespace api {

namespace {
const Client* g_client = NULL;
}  // namespace

void InitializeClient(const base::char16* endpoint_name) {
  DCHECK(endpoint_name);
  DCHECK(!g_client);
  g_client = new Client(endpoint_name);
}

void SendReport(const EXCEPTION_POINTERS* exception_pointers,
                const char* protobuf,
                size_t protobuf_length,
                const base::char16* const* keys,
                const base::char16* const* values) {
  if (!g_client) {
    LOG(ERROR) << "SendReport failed: uninitialized.";
    return;
  }

  g_client->SendReport(exception_pointers, protobuf, protobuf_length, keys,
                       values);
}

void ShutdownClient() {
  DCHECK(g_client);
  delete g_client;
  g_client = NULL;
}

}  // namespace api
}  // namespace kasko
