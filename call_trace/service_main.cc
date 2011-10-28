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

#include "syzygy/call_trace/service.h"

#include <iostream>

#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/file_path.h"
#include "base/logging.h"
#include "base/string_number_conversions.h"
#include "sawbuck/common/com_utils.h"

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
    "Usage: call_trace_service [options]\n"
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

  if (cmd_line->HasSwitch("help")) {
    return Usage();
  }

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
      return 1;
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
      return 1;
    }
    call_trace_service.set_num_incremental_buffers(num);
  }

  // Setup the handler for exit signals.
  if (!SetConsoleCtrlHandler(&OnConsoleCtrl, TRUE)) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "Failed to register shutdown handler: "
               << com::LogWe(error) << ".";
    return 1;
  }

  // Run the service until it is externally stopped.
  call_trace_service.Start(false);

  return 0;
}
