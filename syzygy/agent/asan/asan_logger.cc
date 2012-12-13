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
#include "base/process_util.h"
#include "base/stringprintf.h"
#include "base/utf_string_conversions.h"
#include "base/debug/stack_trace.h"
#include "base/memory/scoped_ptr.h"
#include "syzygy/trace/rpc/logger_rpc.h"
#include "syzygy/trace/rpc/rpc_helpers.h"

namespace agent {
namespace asan {

namespace {

using trace::client::GetInstanceString;

AsanLogger* logger_instance = NULL;

}

AsanLogger::AsanLogger() {
}

void AsanLogger::SetInstance(AsanLogger* instance) {
  logger_instance = instance;
}

AsanLogger* AsanLogger::Instance() {
  return logger_instance;
}

void AsanLogger::Init() {
  base::RouteStdioToConsole();
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

void AsanLogger::Write(const std::string& message) {
  // If we're bound to a logging endpoint, log the message there.
  if (rpc_binding_.Get() != NULL) {
    trace::client::InvokeRpc(
        &LoggerClient_Write,
        rpc_binding_.Get(),
        reinterpret_cast<const unsigned char*>(message.c_str()));
  } else {
    // Otherwise, log to stderr.
     ::fprintf(stderr, "%s", message.c_str());
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
  } else {
    // Otherwise, log to stderr.
    const char* format_str =  "%s%s";
    if (!message.empty() && message.back() != '\n')
      format_str = "%s\n%s";
    base::debug::StackTrace trace(trace_data, trace_length);
    ::fprintf(stderr, format_str, message.c_str(), trace.ToString().c_str());
  }
}

}  // namespace asan
}  // namespace agent
