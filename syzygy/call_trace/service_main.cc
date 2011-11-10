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

#include <iostream>

#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/file_path.h"
#include "base/logging.h"
#include "base/string_number_conversions.h"
#include "base/string_util.h"
#include "sawbuck/common/com_utils.h"
#include "syzygy/call_trace/rpc_helpers.h"
#include "syzygy/call_trace/service.h"

using call_trace::client::CreateRpcBinding;
using call_trace::client::InvokeRpc;
using call_trace::service::Service;

namespace {

// Minimum buffer size to allow (1 MB).
const int kMinBufferSize = 1024 * 1024;

// Minumum number of buffers to allocate.
const int kMinBuffers = 16;

// Handler function to be called on exit signals (Ctrl-C, TERM, etc...).
BOOL WINAPI OnConsoleCtrl(DWORD ctrl_type) {
  if (ctrl_type != CTRL_LOGOFF_EVENT) {
    Service::Instance().RequestShutdown();
    return TRUE;
  }
  return FALSE;
}

const char kUsage[] =
    "Usage: call_trace_service ACTION [OPTIONS]\n"
    "\n"
    "Actions:\n"
    "  start              Start the call trace service.\n"
    "  stop               Stop the call trace service.\n"
    "\n"
    "Options:\n"
    "  --help             Show this help message.\n"
    "  --trace-dir=PATH   The directory in which to write the trace files.\n"
    "  --buffer-size=NUM  The size (in bytes) of each buffer to allocate.\n"
    "  --num-incremental-buffers=NUM\n"
    "                     The number of buffers by which to grow the buffer\n"
    "                     pool each time the client exhausts its available\n"
    "                     buffer space.\n"
    "\n";

int Usage() {
  std::cout << kUsage;
  return 1;
}

bool RunService(const CommandLine* cmd_line) {
  DCHECK(cmd_line != NULL);
  Service& call_trace_service = Service::Instance();

  // Set up the trace directory.
  FilePath trace_directory(cmd_line->GetSwitchValuePath("trace-dir"));
  if (trace_directory.empty()) {
    trace_directory = FilePath(L".");
  }
  call_trace_service.set_trace_directory(trace_directory);

  // Setup the buffer size.
  std::wstring buffer_size_str(
      cmd_line->GetSwitchValueNative("buffer-size"));
  if (!buffer_size_str.empty()) {
    int num = 0;
    if (!base::StringToInt(buffer_size_str, &num) || num < kMinBufferSize) {
      LOG(ERROR) << "Buffer size is too small (<" << kMinBufferSize << ").";
      return false;
    }
    call_trace_service.set_buffer_size_in_bytes(num);
  }

  // Setup the number of incremental buffers
  std::wstring buffers_str(
      cmd_line->GetSwitchValueNative("num-incremental-buffers"));
  if (!buffers_str.empty()) {
    int num = 0;
    if (!base::StringToInt(buffers_str, &num) || num < kMinBuffers) {
      LOG(ERROR) << "Number of incremental buffers is too small (<"
                 << kMinBuffers << ").";
      return false;
    }
    call_trace_service.set_num_incremental_buffers(num);
  }

  // Setup the handler for exit signals.
  if (!SetConsoleCtrlHandler(&OnConsoleCtrl, TRUE)) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "Failed to register shutdown handler: "
               << com::LogWe(error) << ".";
    return false;
  }

  // Run the service until it is externally stopped.
  call_trace_service.Start(false);

  return true;
}

bool StopService() {
  LOG(INFO) << "Stopping call trace logging service.";
  handle_t binding = NULL;
  if (!CreateRpcBinding(Service::kRpcProtocol,
                        Service::kRpcEndpoint,
                        &binding)) {
    LOG(ERROR) << "Failed to connect to call trace logging service.";
    return false;
  }

  if (!InvokeRpc(CallTraceClient_Stop, binding).succeeded()) {
    LOG(ERROR) << "Failed to stop call trace logging service.";
    return false;
  }

  LOG(INFO) << "Call trace logging service has been stopped.";
  return true;
}

} // namespace

int main(int argc, char** argv) {
  base::AtExitManager at_exit_manager;
  CommandLine::Init(argc, argv);

  if (!logging::InitLogging(L"", logging::LOG_ONLY_TO_SYSTEM_DEBUG_LOG,
      logging::DONT_LOCK_LOG_FILE, logging::APPEND_TO_OLD_LOG_FILE,
      logging::ENABLE_DCHECK_FOR_NON_OFFICIAL_RELEASE_BUILDS)) {
    return 1;
  }

  CommandLine* cmd_line = CommandLine::ForCurrentProcess();
  DCHECK(cmd_line != NULL);

  if (cmd_line->HasSwitch("help") || cmd_line->args().size() < 1) {
    return Usage();
  }

  if (LowerCaseEqualsASCII(cmd_line->args()[0], "stop")) {
    return StopService() ? 0 : 1;
  }

  if (LowerCaseEqualsASCII(cmd_line->args()[0], "start")) {
    return RunService(cmd_line) ? 0 : 1;
  }

  return Usage();
}
