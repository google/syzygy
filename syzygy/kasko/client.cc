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

#include "syzygy/kasko/client.h"

#include "base/logging.h"
#include "base/threading/platform_thread.h"
#include "syzygy/common/rpc/helpers.h"
#include "syzygy/kasko/kasko_rpc.h"
#include "syzygy/kasko/minidump_request.h"

namespace kasko {

Client::Client(const base::string16& endpoint) : endpoint_(endpoint) {
}

Client::~Client(){
}

void Client::SendReport(const MinidumpRequest& request) const {
  // Establish the RPC binding.
  common::rpc::ScopedRpcBinding rpc_binding;
  if (!rpc_binding.Open(L"ncalrpc", endpoint_)) {
    LOG(ERROR) << "Failed to open an RPC binding.";
    return;
  }

  // Alias the crash key string buffers into the CrashKey array used for the RPC
  // invocation.
  std::vector<CrashKey> crash_keys;
  for (auto& client_crash_key : request.crash_keys) {
    CrashKey rpc_crash_key = {client_crash_key.first, client_crash_key.second};
    crash_keys.push_back(rpc_crash_key);
  }

  DumpType rpc_dump_type = SMALL_DUMP;
  switch (request.type) {
    case MinidumpRequest::SMALL_DUMP_TYPE:
      rpc_dump_type = SMALL_DUMP;
      break;
    case MinidumpRequest::LARGER_DUMP_TYPE:
      rpc_dump_type = LARGER_DUMP;
      break;
    case MinidumpRequest::FULL_DUMP_TYPE:
      rpc_dump_type = FULL_DUMP;
      break;
    default:
      NOTREACHED();
      break;
  }

  // Invoke SendDiagnosticReport via RPC.
  common::rpc::RpcStatus status = common::rpc::InvokeRpc(
      KaskoClient_SendDiagnosticReport, rpc_binding.Get(),
      request.exception_info_address, base::PlatformThread::CurrentId(),
      rpc_dump_type, request.protobuf_length,
      reinterpret_cast<const signed char*>(request.protobuf ? request.protobuf
                                                            : ""),
      crash_keys.size(), crash_keys.size() ? crash_keys.data() : nullptr);

  if (!status.succeeded())
    LOG(ERROR) << "Failed to invoke the SendDiagnosticReport RPC.";
}

}  // namespace kasko
