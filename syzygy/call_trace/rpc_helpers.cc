// Copyright 2011 Google Inc.
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
// Declares utility functions used by the call trace client and its unit
// tests.

#include <windows.h>

#include "base/logging.h"
#include "sawbuck/common/com_utils.h"
#include "syzygy/call_trace/rpc_helpers.h"

namespace call_trace {
namespace client {

bool CreateRpcBinding(const wchar_t* protocol,
                      const wchar_t* endpoint,
                      handle_t* out_handle) {
  DCHECK(protocol != NULL);
  DCHECK(endpoint != NULL);
  DCHECK(out_handle != NULL);

  std::wstring protocol_temp(protocol);
  std::wstring endpoint_temp(endpoint);
  RPC_WSTR string_binding = NULL;

  RPC_STATUS status = ::RpcStringBindingCompose(
      NULL,  // UUID.
      reinterpret_cast<RPC_WSTR>(&protocol_temp[0]),
      NULL,  // Address.
      reinterpret_cast<RPC_WSTR>(&endpoint_temp[0]),
      NULL,  // Options.
      &string_binding);
  if (status != RPC_S_OK) {
    LOG(ERROR) << "Can't compose RPC binding: " << com::LogWe(status) << ".";
    return false;
  }

  handle_t binding = NULL;
  status = ::RpcBindingFromStringBinding(string_binding, &binding);

  ignore_result(::RpcStringFree(&string_binding));

  if (status != RPC_S_OK) {
    LOG(ERROR) << "Can't create RPC binding: " << com::LogWe(status) << ".";
    return false;
  }

  *out_handle = binding;
  return true;
}

}  // namespace call_trace::client
}  // namespace call_trace
