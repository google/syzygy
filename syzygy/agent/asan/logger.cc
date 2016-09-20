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

#include "syzygy/agent/asan/logger.h"

#include <memory>

#include "base/command_line.h"
#include "base/environment.h"
#include "base/logging.h"
#include "base/debug/stack_trace.h"
#include "base/process/launch.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_string_conversions.h"
#include "syzygy/common/rpc/helpers.h"
#include "syzygy/trace/rpc/logger_rpc.h"

namespace agent {
namespace asan {

namespace {

using ::common::rpc::GetInstanceString;

AsanLogger* logger_instance = NULL;

void InitExecutionContext(const CONTEXT& rtl_context,
                          ExecutionContext* exc_context) {
  DCHECK(exc_context != NULL);
  // TODO(loskutov): adapt for 64 bits
#ifndef _WIN64
  exc_context->edi = rtl_context.Edi;
  exc_context->esi = rtl_context.Esi;
  exc_context->ebx = rtl_context.Ebx;
  exc_context->edx = rtl_context.Edx;
  exc_context->ecx = rtl_context.Ecx;
  exc_context->eax = rtl_context.Eax;
  exc_context->ebp = rtl_context.Ebp;
  exc_context->eip = rtl_context.Eip;
  exc_context->esp = rtl_context.Esp;
#else
  exc_context->rdi = rtl_context.Rdi;
  exc_context->rsi = rtl_context.Rsi;
  exc_context->rbx = rtl_context.Rbx;
  exc_context->rdx = rtl_context.Rdx;
  exc_context->rcx = rtl_context.Rcx;
  exc_context->rax = rtl_context.Rax;
  exc_context->rbp = rtl_context.Rbp;
  exc_context->rip = rtl_context.Rip;
  exc_context->rsp = rtl_context.Rsp;
#endif
  exc_context->eflags = rtl_context.EFlags;
  exc_context->seg_cs = rtl_context.SegCs;
  exc_context->seg_ss = rtl_context.SegSs;
}

}  // namespace

AsanLogger::AsanLogger() : log_as_text_(true), minidump_on_failure_(false) {
}

void AsanLogger::Init() {
  bool success = rpc_binding_.Open(
      kLoggerRpcProtocol,
      GetInstanceString(kLoggerRpcEndpointRoot, instance_id_));

  // TODO(rogerm): Add a notion of a session to the logger interface. Opening
  //     a session (either here, or on first use) allows for better management
  //     of symbol context across trace log messages for a given process.
  if (success) {
    const base::CommandLine* command_line =
        base::CommandLine::ForCurrentProcess();
    std::string message = base::StringPrintf(
        "PID=%d; cmd-line='%ls'\n",
        ::GetCurrentProcessId(),
        command_line->GetCommandLineString().c_str());
    success = ::common::rpc::InvokeRpc(&LoggerClient_Write, rpc_binding_.Get(),
                                       reinterpret_cast<const unsigned char*>(
                                           message.c_str())).succeeded();
    if (!success)
      rpc_binding_.Close();
  }
}

void AsanLogger::Stop() {
  if (rpc_binding_.Get() != NULL) {
    ::common::rpc::InvokeRpc(&LoggerClient_Stop, rpc_binding_.Get());
  }
}

void AsanLogger::Write(const std::string& message) {
  // If we're bound to a logging endpoint, log the message there.
  if (rpc_binding_.Get() != NULL) {
    ::common::rpc::InvokeRpc(
        &LoggerClient_Write, rpc_binding_.Get(),
        reinterpret_cast<const unsigned char*>(message.c_str()));
  }
}

void AsanLogger::WriteWithContext(const std::string& message,
                                  const CONTEXT& context) {
  // If we're bound to a logging endpoint, log the message there.
  if (rpc_binding_.Get() != NULL) {
    ExecutionContext exec_context = {};
    InitExecutionContext(context, &exec_context);
    ::common::rpc::InvokeRpc(
        &LoggerClient_WriteWithContext, rpc_binding_.Get(),
        reinterpret_cast<const unsigned char*>(message.c_str()), &exec_context);
  }
}

void AsanLogger::WriteWithStackTrace(const std::string& message,
                                     const void * const * trace_data,
                                     uint32_t trace_length) {
  // If we're bound to a logging endpoint, log the message there.
  if (rpc_binding_.Get() != NULL) {
    ::common::rpc::InvokeRpc(
        &LoggerClient_WriteWithTrace, rpc_binding_.Get(),
        reinterpret_cast<const unsigned char*>(message.c_str()),
        reinterpret_cast<const uintptr_t*>(trace_data), trace_length);
  }
}

void AsanLogger::SaveMinidumpWithProtobufAndMemoryRanges(
    CONTEXT* context,
    AsanErrorInfo* error_info,
    const std::string& protobuf,
    const MemoryRanges& memory_ranges) {
  CHECK_NE(static_cast<CONTEXT*>(nullptr), context);
  CHECK_NE(static_cast<AsanErrorInfo*>(nullptr), error_info);

  if (rpc_binding_.Get() == NULL)
    return;

  // Convert the memory ranges to arrays.
  std::vector<const void*> base_addresses;
  std::vector<size_t> range_lengths;
  for (const auto& val : memory_ranges) {
    base_addresses.push_back(val.first);
    range_lengths.push_back(val.second);
  }

  EXCEPTION_RECORD exception = {};
  exception.ExceptionCode = EXCEPTION_ARRAY_BOUNDS_EXCEEDED;
  exception.ExceptionAddress = GetInstructionPointer(*context);
  exception.NumberParameters = 2;
  exception.ExceptionInformation[0] = reinterpret_cast<ULONG_PTR>(context);
  exception.ExceptionInformation[1] = reinterpret_cast<ULONG_PTR>(error_info);

  const EXCEPTION_POINTERS pointers = { &exception, context };
  ::common::rpc::InvokeRpc(
      &LoggerClient_SaveMinidumpWithProtobufAndMemoryRanges, rpc_binding_.Get(),
      ::GetCurrentThreadId(), reinterpret_cast<uintptr_t>(&pointers),
      reinterpret_cast<const byte*>(protobuf.data()),
      static_cast<unsigned long>(protobuf.size()),
      reinterpret_cast<const unsigned long*>(base_addresses.data()),
      reinterpret_cast<const unsigned long*>(range_lengths.data()),
      static_cast<uint32_t>(memory_ranges.size()));
}

}  // namespace asan
}  // namespace agent
