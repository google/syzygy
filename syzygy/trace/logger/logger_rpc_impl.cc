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

// This file implements the RPC stubs which bind the LoggerService RPC
// handlers to a Logger instance.

#include "syzygy/trace/logger/logger_rpc_impl.h"

#include "base/process.h"
#include "base/win/scoped_handle.h"
#include "sawbuck/common/com_utils.h"
#include "syzygy/trace/logger/logger.h"
#include "syzygy/trace/rpc/logger_rpc.h"

namespace {

using base::ProcessId;
using base::win::ScopedHandle;
using trace::logger::RpcLoggerInstanceManager;
using trace::logger::Logger;

bool GetClientProcessHandle(handle_t binding, ScopedHandle* handle) {
  DCHECK(handle != NULL);

  // Get the RPC call attributes.
  static const int kVersion = 2;
  RPC_CALL_ATTRIBUTES_V2 attribs = { kVersion, RPC_QUERY_CLIENT_PID };
  RPC_STATUS status = RpcServerInqCallAttributes(binding, &attribs);
  if (status != RPC_S_OK) {
    LOG(ERROR) << "Failed to query RPC call attributes: "
               << com::LogWe(status) << ".";
    return false;
  }

  // Extract the process id.
  ProcessId pid = reinterpret_cast<ProcessId>(attribs.ClientPID);

  // Open and return the handle to the process.
  static const DWORD kFlags =
      PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;
  handle->Set(::OpenProcess(kFlags, FALSE, pid));
  if (!handle->IsValid()) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "Failed to open PID=" << pid << ": " << com::LogWe(error)
               << ".";
    return false;
  }
  return true;
}

}  // namespace

// The instance to which the RPC callbacks are bound.
Logger* RpcLoggerInstanceManager::instance_ = NULL;

// RPC entrypoint for Logger::Write().
boolean LoggerService_Write(
    /* [in] */ handle_t binding,
    /* [string][in] */ const unsigned char *text) {
  Logger* instance = RpcLoggerInstanceManager::GetInstance();
  return instance->Write(reinterpret_cast<const char*>(text));
}

boolean LoggerService_WriteWithTrace(
  /* [in] */ handle_t binding,
  /* [in, string] */ const unsigned char* text,
  /* [in, size_is(trace_length)] */ const unsigned long* trace_data,
  /* [in] */ LONG trace_length) {
  // Get the PID of the caller.
  ScopedHandle handle;
  if (!GetClientProcessHandle(binding, &handle))
    return FALSE;

  std::string message(reinterpret_cast<const char*>(text));
  Logger* instance = RpcLoggerInstanceManager::GetInstance();
  instance->AppendTrace(handle, trace_data, trace_length, &message);

  return instance->Write(message);
}

// RPC entrypoint for Logger::Stop().
boolean LoggerService_Stop(/* [in] */ handle_t binding) {
  Logger* instance = RpcLoggerInstanceManager::GetInstance();
  return instance->Stop();
}
