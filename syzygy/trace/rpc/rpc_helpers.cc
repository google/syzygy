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
// Declares utility functions used by the call trace client and its unit
// tests.

#include "syzygy/trace/rpc/rpc_helpers.h"

#include <windows.h>

#include "base/logging.h"
#include "syzygy/common/com_utils.h"

namespace trace {
namespace client {

bool CreateRpcBinding(const base::StringPiece16& protocol,
                      const base::StringPiece16& endpoint,
                      handle_t* out_handle) {
  DCHECK(!protocol.empty());
  DCHECK(!endpoint.empty());
  DCHECK(out_handle != NULL);

  std::wstring protocol_temp(protocol.begin(), protocol.end());
  std::wstring endpoint_temp(endpoint.begin(), endpoint.end());
  RPC_WSTR string_binding = NULL;

  RPC_STATUS status = ::RpcStringBindingCompose(
      NULL,  // UUID.
      reinterpret_cast<RPC_WSTR>(&protocol_temp[0]),
      NULL,  // Address.
      reinterpret_cast<RPC_WSTR>(&endpoint_temp[0]),
      NULL,  // Options.
      &string_binding);
  if (status != RPC_S_OK) {
    LOG(ERROR) << "Can't compose RPC binding: " << ::common::LogWe(status)
               << ".";
    return false;
  }

  handle_t binding = NULL;
  status = ::RpcBindingFromStringBinding(string_binding, &binding);

  ignore_result(::RpcStringFree(&string_binding));

  if (status != RPC_S_OK) {
    LOG(ERROR) << "Can't create RPC binding: " << ::common::LogWe(status)
               << ".";
    return false;
  }

  *out_handle = binding;
  return true;
}

std::wstring GetInstanceString(
    const base::StringPiece16& root, const base::StringPiece16& instance_id) {
  std::wstring result(root.begin(), root.end());
  if (!instance_id.empty()) {
    result += L'-';
    result.append(instance_id.begin(), instance_id.end());
  }

  return result;
}

ScopedRpcBinding::ScopedRpcBinding() : rpc_binding_(NULL) {
}

ScopedRpcBinding::~ScopedRpcBinding() {
  Close();
}

bool ScopedRpcBinding::Open(const base::StringPiece16& protocol,
                            const base::StringPiece16& endpoint) {
  if (!CreateRpcBinding(protocol, endpoint, &rpc_binding_)) {
    DCHECK(rpc_binding_ == NULL);
    return false;
  }

  return true;
}

bool ScopedRpcBinding::Close() {
  if (rpc_binding_ == NULL)
    return true;

  RPC_STATUS status = ::RpcBindingFree(&rpc_binding_);
  rpc_binding_ = NULL;
  if (status != RPC_S_OK)
    return false;

  return true;
}

}  // namespace client
}  // namespace trace
