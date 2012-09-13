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

#include <iostream>

#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/file_path.h"
#include "base/logging.h"
#include "base/path_service.h"
#include "base/process_util.h"
#include "base/string_number_conversions.h"
#include "base/string_piece.h"
#include "base/string_util.h"
#include "base/utf_string_conversions.h"
#include "base/memory/scoped_ptr.h"
#include "base/threading/thread.h"
#include "sawbuck/common/com_utils.h"
#include "syzygy/trace/protocol/call_trace_defs.h"
#include "syzygy/trace/rpc/rpc_helpers.h"
#include "syzygy/trace/service/service.h"
#include "syzygy/trace/service/service_rpc_impl.h"
#include "syzygy/trace/service/trace_file_writer_factory.h"

namespace trace {
namespace service {
namespace {

using ::trace::client::CreateRpcBinding;
using ::trace::client::InvokeRpc;

// Minimum buffer size to allow (1 MB).
const int kMinBufferSize = 1024 * 1024;

// Minumum number of buffers to allocate.
const int kMinBuffers = 16;

// A static location to which the current instance id can be saved. We
// persist it here so that OnConsoleCtrl can have access to the instance
// id when it is invoked on the signal handler thread.
wchar_t saved_instance_id[16] = {0};

// Forward declaration.
bool StopService(const base::StringPiece16& instance_id);

// Handler function to be called on exit signals (Ctrl-C, TERM, etc...).
BOOL WINAPI OnConsoleCtrl(DWORD ctrl_type) {
  if (ctrl_type != CTRL_LOGOFF_EVENT) {
    StopService(saved_instance_id);
    return TRUE;
  }
  return FALSE;
}

const char* const kInstanceId = "instance-id";

const char kUsage[] =
    "Usage: call_trace_service ACTION [OPTIONS]\n"
    "\n"
    "Actions:\n"
    "  start              Start the call trace service. This causes an\n"
    "                     instance of the service to be launched as a\n"
    "                     foreground process.\n"
    "  spawn              Spawns an instance of the call trace service, waits\n"
    "                     for it to be ready, and returns. The call trace\n"
    "                     service continues running in the background.\n"
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
    "  --enable-exits     Enable exit tracing (off by default).\n"
    "  --verbose          Increase the logging verbosity to also include\n"
    "                     debug-level information.\n"
    "  --instance-id=ID   A unique identifier to use for the RPC endoint.\n"
    "                     This allows multiple instances of the service to\n"
    "                     run concurrently. By default this is empty.\n"
    "\n";

int Usage() {
  std::cout << kUsage;
  return 1;
}

bool GetInstanceId(const CommandLine* cmd_line, std::wstring* id) {
  DCHECK(cmd_line != NULL);
  DCHECK(id != NULL);

  // If not specified, this defaults to the empty string.
  *id = cmd_line->GetSwitchValueNative(kInstanceId);

  const size_t kMaxLength = arraysize(saved_instance_id) - 1;
  if (id->length() > kMaxLength) {
    LOG(ERROR) << "The instance id '" << *id << "' is too long. "
               << "The max length is " << kMaxLength << " characters.";
    return false;
  }

  return true;
}

bool RunService(const CommandLine* cmd_line) {
  DCHECK(cmd_line != NULL);

  base::Thread writer_thread("trace-file-writer");
  if (!writer_thread.StartWithOptions(
          base::Thread::Options(MessageLoop::TYPE_IO, 0))) {
    LOG(ERROR) << "Failed to start call trace service writer thread.";
    return 1;
  }

  MessageLoop* message_loop = writer_thread.message_loop();
  TraceFileWriterFactory trace_file_writer_factory(message_loop);
  Service call_trace_service(&trace_file_writer_factory);
  RpcServiceInstanceManager rpc_instance(&call_trace_service);

  // Get/set the instance id.
  std::wstring instance_id;
  if (!GetInstanceId(cmd_line, &instance_id))
    return false;

  call_trace_service.set_instance_id(instance_id);
  base::wcslcpy(saved_instance_id,
                instance_id.c_str(),
                arraysize(saved_instance_id));

  // Set up the trace directory.
  FilePath trace_directory(cmd_line->GetSwitchValuePath("trace-dir"));
  if (trace_directory.empty())
    trace_directory = FilePath(L".");
  if (!trace_file_writer_factory.SetTraceFileDirectory(trace_directory))
    return false;

  // Setup the buffer size.
  std::wstring buffer_size_str(cmd_line->GetSwitchValueNative("buffer-size"));
  if (!buffer_size_str.empty()) {
    int num = 0;
    if (!base::StringToInt(buffer_size_str, &num) || num < kMinBufferSize) {
      LOG(ERROR) << "Buffer size is too small (<" << kMinBufferSize << ").";
      return false;
    }
    call_trace_service.set_buffer_size_in_bytes(num);
  }

  if (cmd_line->HasSwitch("enable-exits")) {
    call_trace_service.set_flags(TRACE_FLAG_ENTER | TRACE_FLAG_EXIT);
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

  // Run the service in blocking mode. This will not return until the service
  // has been externally stopped.
  call_trace_service.Start(false);

  // We no longer need to look out for exit signals.
  SetConsoleCtrlHandler(&OnConsoleCtrl, FALSE);

  // The call trace service will be stopped on destruction.
  return true;
}

bool SpawnService(const CommandLine* cmd_line) {
  // Get the path to ourselves.
  FilePath self_path;
  PathService::Get(base::FILE_EXE, &self_path);

  // Build a command line for starting a new instance of the service.
  CommandLine service_cmd(self_path);
  service_cmd.AppendArg("start");

  // Copy over any other switches.
  CommandLine::SwitchMap::const_iterator it =
      cmd_line->GetSwitches().begin();
  for (; it != cmd_line->GetSwitches().end(); ++it)
    service_cmd.AppendSwitchNative(it->first, it->second);

  // Get the instance id.
  std::wstring instance_id;
  if (!GetInstanceId(cmd_line, &instance_id))
    return false;

  // Launch a new process in the background.
  LOG(INFO) << "Launching background call trace service with instance ID \""
            << instance_id << "\".";
  base::ProcessHandle service_process;
  base::LaunchOptions options;
  options.start_hidden = true;
  if (!base::LaunchProcess(service_cmd, options, &service_process)) {
    LOG(ERROR) << "Failed to launch process.";
    return false;
  }
  DCHECK_NE(base::kNullProcessHandle, service_process);

  // Get the name of the event that will be signalled when the service is up
  // and running.
  std::wstring event_name;
  ::GetSyzygyCallTraceRpcEventName(instance_id, &event_name);
  base::win::ScopedHandle rpc_event(
      ::CreateEvent(NULL, TRUE, FALSE, event_name.c_str()));
  if (!rpc_event.IsValid()) {
    LOG(ERROR) << "Unable to create RPC event for instance id \""
               << instance_id << "\".";
    return false;
  }

  // We wait on both the RPC event and the process, as if the process fails for
  // any reason, it'll exit and its handle will become signalled.
  HANDLE handles[] = { rpc_event.Get(), service_process };
  if (::WaitForMultipleObjects(arraysize(handles),
                               handles,
                               FALSE,
                               INFINITE) != WAIT_OBJECT_0) {
    LOG(ERROR) << "The spawned call trace service exited in error.";
    return false;
  }

  LOG(INFO) << "Background call trace service with instance ID \""
            << instance_id << "\" is ready.";

  return true;
}

bool StopService(const base::StringPiece16& instance_id) {
  std::wstring protocol;
  std::wstring endpoint;

  ::GetSyzygyCallTraceRpcProtocol(&protocol);
  ::GetSyzygyCallTraceRpcEndpoint(instance_id, &endpoint);

  LOG(INFO) << "Stopping call trace logging service instance at '"
            << endpoint << "' via " << protocol << '.';

  handle_t binding = NULL;
  if (!CreateRpcBinding(protocol, endpoint, &binding)) {
    LOG(ERROR) << "Failed to connect to call trace logging service.";
    return false;
  }

  if (!InvokeRpc(CallTraceClient_Stop, binding).succeeded()) {
    LOG(ERROR) << "Failed to stop call trace logging service.";
    return false;
  }

  // TODO(rogerm): It would be nice to make this blocking until the
  //    service actually shuts down. Perhaps with retries on the stop
  //    request.
  LOG(INFO) << "Call trace service shutdown has been requested.";
  return true;
}

extern "C" int main(int argc, char** argv) {
  base::AtExitManager at_exit_manager;
  CommandLine::Init(argc, argv);
  const int kVlogLevelVerbose = -2;
  if (!logging::InitLogging(
          L"",
          logging::LOG_ONLY_TO_SYSTEM_DEBUG_LOG,
          logging::DONT_LOCK_LOG_FILE,
          logging::APPEND_TO_OLD_LOG_FILE,
          logging::ENABLE_DCHECK_FOR_NON_OFFICIAL_RELEASE_BUILDS)) {
    return 1;
  }

  // TODO(rogerm): Turn on ETW logging as well.

  CommandLine* cmd_line = CommandLine::ForCurrentProcess();
  DCHECK(cmd_line != NULL);

  if (cmd_line->HasSwitch("verbose")) {
    logging::SetMinLogLevel(kVlogLevelVerbose);
  }

  if (cmd_line->HasSwitch("help") || cmd_line->GetArgs().size() < 1) {
    return Usage();
  }

  if (LowerCaseEqualsASCII(cmd_line->GetArgs()[0], "stop")) {
    std::wstring id;
    return (GetInstanceId(cmd_line, &id) && StopService(id)) ? 0 : 1;
  }

  if (LowerCaseEqualsASCII(cmd_line->GetArgs()[0], "start")) {
    return RunService(cmd_line) ? 0 : 1;
  }

  if (LowerCaseEqualsASCII(cmd_line->GetArgs()[0], "spawn")) {
    return SpawnService(cmd_line) ? 0 : 1;
  }

  return Usage();
}

}  // namespace
}  // namespace service
}  // namespace trace
