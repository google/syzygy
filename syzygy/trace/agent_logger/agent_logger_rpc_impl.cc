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

#include "syzygy/trace/agent_logger/agent_logger_rpc_impl.h"

#include <windows.h>
#include <winnt.h>

#include "base/process/process.h"
#include "base/win/scoped_handle.h"
#include "syzygy/common/com_utils.h"
#include "syzygy/common/rpc/helpers.h"
#include "syzygy/trace/agent_logger/agent_logger.h"
#include "syzygy/trace/rpc/logger_rpc.h"

namespace {

using base::ProcessId;
using base::win::ScopedHandle;
using trace::agent_logger::RpcLoggerInstanceManager;
using trace::agent_logger::AgentLogger;

bool GetClientInfo(handle_t binding,
                   base::ProcessId* pid,
                   base::win::ScopedHandle* handle) {
  DCHECK(pid);
  DCHECK(handle);

  base::ProcessId the_pid = ::common::rpc::GetClientProcessID(binding);
  if (!the_pid)
    return false;

  // Open and return the handle to the process.
  static const DWORD kFlags =
      PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;
  handle->Set(::OpenProcess(kFlags, FALSE, the_pid));
  if (!handle->IsValid()) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "Failed to open PID=" << the_pid << ": "
               << ::common::LogWe(error) << ".";
    return false;
  }

  // And we're done.
  *pid = the_pid;
  return true;
}

void InitContext(const ExecutionContext* ext_ctx, CONTEXT* ctx) {
  DCHECK(ext_ctx != NULL);
  DCHECK(ctx != NULL);

  ::memset(ctx, 0, sizeof(*ctx));
  ctx->ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;

  // TODO(loskutov): port to win64
#ifndef _WIN64
  // Populate the integer registers.
  ctx->Edi = ext_ctx->edi;
  ctx->Esi = ext_ctx->esi;
  ctx->Ebx = ext_ctx->ebx;
  ctx->Edx = ext_ctx->edx;
  ctx->Ecx = ext_ctx->ecx;
  ctx->Eax = ext_ctx->eax;

  // Populate the control registers.
  ctx->Ebp = ext_ctx->ebp;
  ctx->Eip = ext_ctx->eip;
  ctx->SegCs = ext_ctx->seg_cs;
  ctx->EFlags = ext_ctx->eflags;
  ctx->Esp = ext_ctx->esp;
  ctx->SegSs = ext_ctx->seg_ss;
#else
  ctx->Rdi = ext_ctx->rdi;
  ctx->Rsi = ext_ctx->rsi;
  ctx->Rbx = ext_ctx->rbx;
  ctx->Rdx = ext_ctx->rdx;
  ctx->Rcx = ext_ctx->rcx;
  ctx->Rax = ext_ctx->rax;

  // Populate the control registers.
  ctx->Rbp = ext_ctx->rbp;
  ctx->Rip = ext_ctx->rip;
  ctx->SegCs = ext_ctx->seg_cs;
  ctx->EFlags = ext_ctx->eflags;
  ctx->Rsp = ext_ctx->rsp;
  ctx->SegSs = ext_ctx->seg_ss;
#endif
}

}  // namespace

// The instance to which the RPC callbacks are bound.
AgentLogger* RpcLoggerInstanceManager::instance_ = NULL;

// RPC entrypoint for AgentLogger::Write().
boolean LoggerService_Write(
    /* [in] */ handle_t binding,
    /* [string][in] */ const unsigned char *text) {
  if (binding == NULL || text == NULL) {
    LOG(ERROR) << "Invalid input parameter(s).";
    return false;
  }

  // Get the logger instance.
  AgentLogger* instance = RpcLoggerInstanceManager::GetInstance();

  // Write the log message.
  std::string message(reinterpret_cast<const char*>(text));
  if (!instance->Write(message))
    return false;

  // And we're done.
  return true;
}

boolean LoggerService_WriteWithContext(
    /* [in] */ handle_t binding,
    /* [in, string] */ const unsigned char* text,
    /* [in */ const ExecutionContext* exc_context ) {
  if (binding == NULL || text == NULL || exc_context == NULL) {
    LOG(ERROR) << "Invalid input parameter(s).";
    return false;
  }

  // Get the caller's process info.
  ProcessId pid = 0;
  ScopedHandle handle;
  if (!GetClientInfo(binding, &pid, &handle))
    return false;

  // Get the logger instance.
  AgentLogger* instance = RpcLoggerInstanceManager::GetInstance();

  // Capture the stack trace for the caller's context.
  CONTEXT context = {};
  InitContext(exc_context, &context);
  std::vector<uintptr_t> trace_data;
  if (!instance->CaptureRemoteTrace(handle.Get(), &context, &trace_data)) {
    return false;
  }

  // Create the log message.
  std::string message(reinterpret_cast<const char*>(text));
  if (!instance->AppendTrace(handle.Get(), trace_data.data(), trace_data.size(),
                             &message)) {
    return false;
  }

  // Write the log message.
  if (!instance->Write(message))
    return false;

  // And we're done.
  return true;
}

boolean LoggerService_WriteWithTrace(
    /* [in] */ handle_t binding,
    /* [in, string] */ const unsigned char* text,
    /* [in, size_is(trace_length)] */ const uintptr_t* trace_data,
    /* [in] */ LONG trace_length) {
  if (binding == NULL || text == NULL || trace_data == NULL) {
    LOG(ERROR) << "Invalid input parameter(s).";
    return false;
  }

  // Get the caller's process info.
  ProcessId pid = 0;
  ScopedHandle handle;
  if (!GetClientInfo(binding, &pid, &handle))
    return false;

  // Get the logger instance.
  AgentLogger* instance = RpcLoggerInstanceManager::GetInstance();

  // Create the log message.
  std::string message(reinterpret_cast<const char*>(text));
  if (!instance->AppendTrace(handle.Get(), trace_data, trace_length, &message))
    return false;

  // Write the log message.
  if (!instance->Write(message))
    return false;

  // And we're done.
  return true;
}

// RPC entrypoint for AgentLogger::SaveMinidumpWithProtobufAndMemoryRanges().
boolean LoggerService_SaveMinidumpWithProtobufAndMemoryRanges(
    /* [in] */ handle_t binding,
    /* [in] */ unsigned long thread_id,
    /* [in] */ unsigned __int64 exception,
    /* [size_is][in] */ const byte protobuf[],
    /* [in] */ unsigned long protobuf_length,
    /* [size_is][in] */ const unsigned long memory_ranges_base_addresses[],
    /* [size_is][in] */ const unsigned long memory_ranges_lengths[],
    /* [in] */ unsigned long memory_ranges_count) {
  if (binding == NULL) {
    LOG(ERROR) << "Invalid input parameter(s).";
    return false;
  }

  // Get the caller's process info.
  ProcessId pid = 0;
  ScopedHandle handle;
  if (!GetClientInfo(binding, &pid, &handle))
    return false;

  std::string protobuf_data(reinterpret_cast<const char*>(protobuf));
  AgentLogger* instance = RpcLoggerInstanceManager::GetInstance();
  if (!instance->SaveMinidumpWithProtobufAndMemoryRanges(
          handle.Get(), pid, thread_id, exception, protobuf, protobuf_length,
          reinterpret_cast<const void* const*>(memory_ranges_base_addresses),
          reinterpret_cast<const size_t*>(memory_ranges_lengths),
          memory_ranges_count)) {
    return false;
  }

  return true;
}

// RPC endpoint.
unsigned long LoggerService_GetProcessId(/* [in] */ handle_t binding) {
  return ::GetCurrentProcessId();
}

// RPC entrypoint for AgentLogger::Stop().
boolean LoggerService_Stop(/* [in] */ handle_t binding) {
  if (binding == NULL) {
    LOG(ERROR) << "Invalid input parameter(s).";
    return false;
  }

  // Get the caller's process info.
  ProcessId pid = 0;
  ScopedHandle handle;
  if (!GetClientInfo(binding, &pid, &handle))
    return false;

  AgentLogger* instance = RpcLoggerInstanceManager::GetInstance();
  if (!instance->Stop())
    return false;

  return true;
}
