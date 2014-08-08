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

#include "syzygy/agent/asan/asan_logger.h"

#include "base/command_line.h"
#include "base/environment.h"
#include "base/logging.h"
#include "base/debug/stack_trace.h"
#include "base/memory/scoped_ptr.h"
#include "base/process/launch.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_string_conversions.h"
#include "syzygy/trace/rpc/logger_rpc.h"
#include "syzygy/trace/rpc/rpc_helpers.h"

namespace agent {
namespace asan {

namespace {

using trace::client::GetInstanceString;

AsanLogger* logger_instance = NULL;

void InitExecutionContext(const CONTEXT& rtl_context,
                          ExecutionContext* exc_context) {
  DCHECK(exc_context != NULL);

  exc_context->edi = rtl_context.Edi;
  exc_context->esi = rtl_context.Esi;
  exc_context->ebx = rtl_context.Ebx;
  exc_context->edx = rtl_context.Edx;
  exc_context->ecx = rtl_context.Ecx;
  exc_context->eax = rtl_context.Eax;
  exc_context->ebp = rtl_context.Ebp;
  exc_context->eip = rtl_context.Eip;
  exc_context->seg_cs = rtl_context.SegCs;
  exc_context->eflags = rtl_context.EFlags;
  exc_context->esp = rtl_context.Esp;
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
    const CommandLine* command_line = CommandLine::ForCurrentProcess();
    std::string message = base::StringPrintf(
        "PID=%d; cmd-line='%ls'\n",
        ::GetCurrentProcessId(),
        command_line->GetCommandLineString().c_str());
    success = trace::client::InvokeRpc(
        &LoggerClient_Write,
        rpc_binding_.Get(),
        reinterpret_cast<const unsigned char*>(message.c_str())).succeeded();
    if (!success)
      rpc_binding_.Close();
  }
}

void AsanLogger::Stop() {
  if (rpc_binding_.Get() != NULL) {
    trace::client::InvokeRpc(
        &LoggerClient_Stop,
        rpc_binding_.Get());
  }
}

void AsanLogger::Write(const std::string& message) {
  // If we're bound to a logging endpoint, log the message there.
  if (rpc_binding_.Get() != NULL) {
    trace::client::InvokeRpc(
        &LoggerClient_Write,
        rpc_binding_.Get(),
        reinterpret_cast<const unsigned char*>(message.c_str()));
  }
}

void AsanLogger::WriteWithContext(const std::string& message,
                                  const CONTEXT& context) {
  // If we're bound to a logging endpoint, log the message there.
  if (rpc_binding_.Get() != NULL) {
    ExecutionContext exec_context = {};
    InitExecutionContext(context, &exec_context);
    trace::client::InvokeRpc(
        &LoggerClient_WriteWithContext,
        rpc_binding_.Get(),
        reinterpret_cast<const unsigned char*>(message.c_str()),
        &exec_context);
  }
}

void AsanLogger::WriteWithStackTrace(const std::string& message,
                                     const void * const * trace_data,
                                     size_t trace_length) {
  // If we're bound to a logging endpoint, log the message there.
  if (rpc_binding_.Get() != NULL) {
    trace::client::InvokeRpc(
        &LoggerClient_WriteWithTrace,
        rpc_binding_.Get(),
        reinterpret_cast<const unsigned char*>(message.c_str()),
        reinterpret_cast<const DWORD*>(trace_data),
        trace_length);
  }
}

void AsanLogger::SaveMiniDump(CONTEXT* context, AsanErrorInfo* error_info) {
  DCHECK(context != NULL);
  DCHECK(error_info != NULL);

  if (rpc_binding_.Get() == NULL)
    return;

  EXCEPTION_RECORD exception = {};
  exception.ExceptionCode = EXCEPTION_ARRAY_BOUNDS_EXCEEDED;
  exception.ExceptionAddress = reinterpret_cast<PVOID>(context->Eip);
  exception.NumberParameters = 2;
  exception.ExceptionInformation[0] = reinterpret_cast<ULONG_PTR>(context);
  exception.ExceptionInformation[1] = reinterpret_cast<ULONG_PTR>(error_info);

  const EXCEPTION_POINTERS pointers = { &exception, context };
  trace::client::InvokeRpc(&LoggerClient_SaveMiniDump,
                           rpc_binding_.Get(),
                           ::GetCurrentThreadId(),
                           reinterpret_cast<unsigned long>(&pointers),
                           0);
}

}  // namespace asan
}  // namespace agent
