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

#include "syzygy/common/rpc/helpers.h"

#include <windows.h>

#include "base/logging.h"
#include "base/win/windows_version.h"
#include "syzygy/common/com_utils.h"

namespace common {
namespace rpc {

bool CreateRpcBinding(const base::StringPiece16& protocol,
                      const base::StringPiece16& endpoint,
                      handle_t* out_handle) {
  DCHECK(!protocol.empty());
  DCHECK(!endpoint.empty());
  DCHECK(out_handle != NULL);

  std::wstring protocol_temp(protocol.begin(), protocol.end());
  std::wstring endpoint_temp(endpoint.begin(), endpoint.end());
  RPC_WSTR string_binding = NULL;

  RPC_STATUS status = ::RpcStringBindingCompose(NULL,  // UUID.
                                                AsRpcWstr(&protocol_temp[0]),
                                                NULL,  // Address.
                                                AsRpcWstr(&endpoint_temp[0]),
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

base::ProcessId GetClientProcessID(handle_t binding) {
  base::ProcessId result = 0;
  RPC_STATUS status = 0;
  // RPC_CALL_ATTRIBUTES_V2 isn't available before Windows Vista.
  if (base::win::GetVersion() >= base::win::VERSION_VISTA) {
    // Get the RPC call attributes.
    static const int kVersion = 2;
    RPC_CALL_ATTRIBUTES_V2 attribs = { kVersion, RPC_QUERY_CLIENT_PID };
    status = ::RpcServerInqCallAttributes(binding, &attribs);
    // TODO(loskutov): unify the PID sizes somehow.
    result = static_cast<base::ProcessId>(
        reinterpret_cast<uintptr_t>(attribs.ClientPID));
  } else {
    status = ::I_RpcBindingInqLocalClientPID(binding,
        reinterpret_cast<unsigned long*>(&result));
  }

  if (status == RPC_S_OK)
    return result;

  LOG(ERROR) << "Failed to query RPC call attributes: "
             << ::common::LogWe(status) << ".";
  return 0;
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

ScopedRpcInterfaceRegistration::ScopedRpcInterfaceRegistration(
    RPC_IF_HANDLE if_spec)
    : if_spec_(if_spec), status_(::RpcServerRegisterIf(if_spec_, NULL, NULL)) {
  if (status_ != RPC_S_OK) {
    LOG(ERROR) << "Failed to register RPC interface: "
               << ::common::LogWe(status_) << ".";
  }
}

ScopedRpcInterfaceRegistration::~ScopedRpcInterfaceRegistration() {
  if (status_ == RPC_S_OK) {
    status_ = ::RpcServerUnregisterIf(NULL, NULL, FALSE);
    if (status_ != RPC_S_OK) {
      LOG(ERROR) << "Failed to unregister RPC interface: "
                 << ::common::LogWe(status_) << ".";
    }
  }
}

}  // namespace rpc
}  // namespace common
