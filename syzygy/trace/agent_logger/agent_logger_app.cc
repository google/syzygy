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
// This file defines the trace::agent_logger::LoggerApp class which implements
// the LoggerApp RPC interface.

#include "syzygy/trace/agent_logger/agent_logger_app.h"

#include "base/bind.h"
#include "base/environment.h"
#include "base/file_util.h"
#include "base/path_service.h"
#include "base/process.h"
#include "base/process_util.h"
#include "base/rand_util.h"
#include "base/string_util.h"
#include "base/stringprintf.h"
#include "base/utf_string_conversions.h"
#include "base/win/scoped_handle.h"
#include "syzygy/trace/agent_logger/agent_logger.h"
#include "syzygy/trace/agent_logger/agent_logger_rpc_impl.h"
#include "syzygy/trace/common/service_util.h"
#include "syzygy/trace/protocol/call_trace_defs.h"
#include "syzygy/trace/rpc/logger_rpc.h"
#include "syzygy/trace/rpc/rpc_helpers.h"

namespace trace {
namespace agent_logger {

namespace {

using trace::client::GetInstanceString;

// The usage string for the logger app.
const char kUsageFormatStr[] =
    "Usage: %ls [options] ACTION [-- command]\n"
    "  Supported actions:\n"
    "    start  Run a new logger instance in the foreground (blocking). You\n"
    "           may optionally specify an external command which will be\n"
    "           run behind the logger. The logger will return once the\n"
    "           external command has terminated or the logger is externally\n"
    "           stopped. If no command is specified, Ctrl-C or an invocation\n"
    "           of the stop action will stop the logger.\n"
    "    spawn  Run a new logger instance in the background (non-blocking).\n"
    "    stop   Stop a separately running logger instance.\n"
    "\n"
    "  Options:\n"
    "    --append             Append to (instead of truncating) the output\n"
    "                         file. This option is valid for the start and\n"
    "                         spawn actions.\n"
    "    --instance-id=ID     A unique (up to 16 character) ID to identify\n"
    "                         the logger instance.\n"
    "    --minidump-dir=PATH  The directory path in which minidumps, if any,\n"
    "                         should be generated.\n"
    "    --output-file=PATH   The file path to which logs should be written.\n"
    "                         This may be stdout (the default), stderr or a\n"
    "                         file path. This option is valid for the start\n"
    "                         and spawn actions.\n"
    "    --unique-instance-id Automatically generate a unique ID for the\n"
    "                         logger instance.\n";

// Names for kernel objects used to synchronize with a logger singleton.
const wchar_t kLoggerMutexRoot[] = L"syzygy-logger-mutex";
const wchar_t kLoggerStartEventRoot[] = L"syzygy-logger-started";
const wchar_t kLoggerStopEventRoot[] = L"syzygy-logger-stopped";

// A static location to which the current instance id can be saved. We
// persist it here so that OnConsoleCtrl can have access to the instance
// id when it is invoked on the signal handler thread.
wchar_t saved_instance_id[LoggerApp::kMaxInstanceIdLength + 1] = { 0 };

// Send a stop request via RPC to the logger instance given by @p instance_id.
bool SendStopRequest(const base::StringPiece16& instance_id) {
  std::wstring protocol(kLoggerRpcProtocol);
  std::wstring endpoint(GetInstanceString(kLoggerRpcEndpointRoot, instance_id));

  LOG(INFO) << "Stopping logging service instance at '"
            << endpoint << "' via " << protocol << '.';

  handle_t binding = NULL;
  if (!trace::client::CreateRpcBinding(protocol, endpoint, &binding)) {
    LOG(ERROR) << "Failed to connect to logging service.";
    return false;
  }

  if (!trace::client::InvokeRpc(LoggerClient_Stop, binding).succeeded()) {
    LOG(ERROR) << "Failed to stop logging service.";
    return false;
  }

  LOG(INFO) << "Logging service shutdown has been requested.";

  return true;
}

// Handler function to be called on exit signals (Ctrl-C, TERM, etc...).
BOOL WINAPI OnConsoleCtrl(DWORD ctrl_type) {
  if (ctrl_type != CTRL_LOGOFF_EVENT) {
    SendStopRequest(saved_instance_id);
    return TRUE;
  }
  return FALSE;
}

// A helper function to signal an event. This is passable as a callback to
// a Logger instance to be called on logger start/stop.
bool SignalEvent(HANDLE event_handle, trace::common::Service* /* logger */) {
  DCHECK_NE(INVALID_HANDLE_VALUE, event_handle);
  if (!::SetEvent(event_handle))
    return false;
  return true;
}

// A helper function which sets the Syzygy RPC instance id environment variable
// then runs a given command line to completion.
bool RunApp(const CommandLine& command_line,
            const std::wstring& instance_id,
            HANDLE interruption_event,
            int* exit_code) {
  DCHECK(exit_code != NULL);
  scoped_ptr<base::Environment> env(base::Environment::Create());
  CHECK(env != NULL);
  env->SetVar(kSyzygyRpcInstanceIdEnvVar, WideToUTF8(instance_id));

  LOG(INFO) << "Launching '" << command_line.GetProgram().value() << "'.";
  VLOG(1) << "Command Line: " << command_line.GetCommandLineString();

  *exit_code = 0;

  // Launch a new process in the background.
  base::ProcessHandle process_handle;
  base::LaunchOptions options;
  options.start_hidden = false;
  if (!base::LaunchProcess(command_line, options, &process_handle)) {
    LOG(ERROR)
        << "Failed to launch '" << command_line.GetProgram().value() << "'.";
    return false;
  }

  HANDLE objects[] = { process_handle, interruption_event };
  DWORD num_objects = arraysize(objects);
  switch (::WaitForMultipleObjects(num_objects, objects, FALSE, INFINITE)) {
    case WAIT_OBJECT_0 + 0: {
      // The client process has finished.
      DWORD temp_exit_code;
      ::GetExitCodeProcess(process_handle, &temp_exit_code);
      *exit_code = temp_exit_code;
      base::CloseProcessHandle(process_handle);
      return true;
    }

    case WAIT_OBJECT_0 + 1: {
      // The logger has been shutdown. Kill the client process.
      base::KillProcess(process_handle, 1, true);
      base::CloseProcessHandle(process_handle);
      *exit_code = 1;
      return true;
    }
  }

  // If we get here then an error has occurred (since the timeout is infinite).
  DWORD error = ::GetLastError();
  LOG(ERROR) << "Error waiting for shutdown event " << ::common::LogWe(error)
             << ".";
  return false;
}

}  // namespace

// Keywords appearing on the command-line
const wchar_t LoggerApp::kSpawn[] = L"spawn";
const wchar_t LoggerApp::kStart[] = L"start";
const wchar_t LoggerApp::kStatus[] = L"status";
const wchar_t LoggerApp::kStop[] = L"stop";
const char LoggerApp::kInstanceId[] = "instance-id";
const char LoggerApp::kUniqueInstanceId[] = "unique-instance-id";
const char LoggerApp::kOutputFile[] = "output-file";
const char LoggerApp::kMiniDumpDir[] = "minidump-dir";
const char LoggerApp::kAppend[] = "append";
const wchar_t LoggerApp::kStdOut[] = L"stdout";
const wchar_t LoggerApp::kStdErr[] = L"stderr";

// A table mapping action keywords to their handler implementations.
const LoggerApp::ActionTableEntry LoggerApp::kActionTable[] = {
    { LoggerApp::kSpawn, &LoggerApp::Spawn },
    { LoggerApp::kStart, &LoggerApp::Start },
    { LoggerApp::kStatus, &LoggerApp::Status },
    { LoggerApp::kStop, &LoggerApp::Stop },
};

LoggerApp::LoggerApp()
    : ::common::AppImplBase("AgentLogger"),
      logger_command_line_(CommandLine::NO_PROGRAM),
      action_handler_(NULL),
      append_(false) {
}

LoggerApp::~LoggerApp() {
}

bool LoggerApp::ParseCommandLine(const CommandLine* command_line) {
  DCHECK(command_line != NULL);

  if (!trace::common::SplitCommandLine(
          command_line,
          &logger_command_line_,
          &app_command_line_)) {
    LOG(ERROR) << "Failed to split command_line into logger and app parts.";
    return false;
  }

  // Save the command-line in case we need to spawn.
  command_line = &logger_command_line_;

  if (command_line->HasSwitch(kInstanceId) &&
      command_line->HasSwitch(kUniqueInstanceId)) {
    return Usage(command_line,
                 base::StringPrintf("--%s and --%s are mutually exclusive.",
                                    kInstanceId,
                                    kUniqueInstanceId));
  }

  // Parse the instance id.
  instance_id_ = command_line->GetSwitchValueNative(kInstanceId);
  if (instance_id_.length() > kMaxInstanceIdLength) {
    return Usage(command_line,
                 base::StringPrintf("The instance id '%ls' is too long. "
                                    "The max length is %d characters.",
                                    instance_id_.c_str(),
                                    kMaxInstanceIdLength));
  }

  // Save the output file parameter.
  output_file_path_ = command_line->GetSwitchValuePath(kOutputFile);

  // Save the minidump-dir parameter.
  mini_dump_dir_ = command_line->GetSwitchValuePath(kMiniDumpDir);
  if (mini_dump_dir_.empty()) {
    CHECK(PathService::Get(base::DIR_CURRENT, &mini_dump_dir_));
  } else {
    mini_dump_dir_ = base::MakeAbsoluteFilePath(mini_dump_dir_);
    if (mini_dump_dir_.empty())
      return Usage(command_line, "The minidump-dir parameter is invalid.");

    if (!file_util::DirectoryExists(mini_dump_dir_) &&
        !file_util::CreateDirectory(mini_dump_dir_)) {
      LOG(ERROR) << "Failed to create minidump-dir "
                 << mini_dump_dir_.value();
    }
  }

  // Make sure there's exactly one action.
  if (command_line->GetArgs().size() != 1) {
    return Usage(command_line,
                 "Exactly 1 action is expected on the command line.");
  }

  // Check for the append flag.
  append_ = command_line->HasSwitch(kAppend);

  // Parse the action.
  action_ = command_line->GetArgs()[0];
  const ActionTableEntry* entry = FindActionHandler(action_);
  if (entry == NULL) {
    return Usage(
        command_line,
        base::StringPrintf("Unrecognized action: %s.", action_.c_str()));
  }

  if (command_line->HasSwitch(kUniqueInstanceId)) {
    DWORD process_id = ::GetCurrentProcessId();
    DWORD timestamp = ::GetTickCount();
    base::SStringPrintf(&instance_id_, L"%08x%08x", process_id, timestamp);
    DCHECK_EQ(kMaxInstanceIdLength, instance_id_.length());
  }

  LOG(INFO) << "Using logger instance ID: '" << instance_id_ << "'.";
  LOG(INFO) << "Writing minidumps to: " << mini_dump_dir_.value();

  // Setup the action handler.
  DCHECK(entry->handler != NULL);
  action_handler_ = entry->handler;

  return true;
}

int LoggerApp::Run() {
  DCHECK(action_handler_ != NULL);
  if (!(this->*action_handler_)())
    return 1;
  return 0;
}

// A helper function to find the handler method for a given action.
const LoggerApp::ActionTableEntry* LoggerApp::FindActionHandler(
    const base::StringPiece16& action) {
  for (size_t i = 0; i < arraysize(kActionTable); ++i) {
    if (::_wcsicmp(kActionTable[i].action, action.data()) == 0)
      return &kActionTable[i];
  }
  return NULL;
}

bool LoggerApp::Start() {
  std::wstring logger_name(
      GetInstanceString(kLoggerRpcEndpointRoot, instance_id_));

  // Acquire the logger mutex.
  base::win::ScopedHandle mutex;
  std::wstring mutex_name(GetInstanceString(kLoggerMutexRoot, instance_id_));
  if (!trace::common::AcquireMutex(mutex_name, &mutex))
    return false;

  // Setup the start event.
  base::win::ScopedHandle start_event;
  std::wstring start_event_name(
      GetInstanceString(kLoggerStartEventRoot, instance_id_));
  if (!trace::common::InitEvent(start_event_name, &start_event)) {
    LOG(ERROR) << "Unable to init start event for '" << logger_name << "'.";
    return false;
  }

  // Setup the stop event.
  base::win::ScopedHandle stop_event;
  std::wstring stop_event_name(
      GetInstanceString(kLoggerStopEventRoot, instance_id_));
  if (!trace::common::InitEvent(stop_event_name, &stop_event)) {
    LOG(ERROR) << "Unable to init stop event for '" << logger_name << "'.";
    return false;
  }

  // Setup an anonymous event to notify us if the logger has been
  // asynchronously asked to shutdown.
  base::win::ScopedHandle interrupt_event;
  if (!trace::common::InitEvent(L"", &interrupt_event)) {
    LOG(ERROR) << "Unable to init interrupt event for '" << logger_name << "'.";
    return false;
  }

  // Get the log file output_file.
  FILE* output_file = NULL;
  bool must_close_output_file = false;
  file_util::ScopedFILE auto_close;
  if (!OpenOutputFile(&output_file, &must_close_output_file)) {
    LOG(ERROR) << "Unable to open '" << output_file_path_.value() << "'.";
    return false;
  }

  // Setup auto_close as appropriate.
  if (must_close_output_file)
    auto_close.reset(output_file);

  // Initialize the logger instance.
  AgentLogger logger;
  logger.set_destination(output_file);
  logger.set_minidump_dir(mini_dump_dir_);
  logger.set_instance_id(instance_id_);
  logger.set_started_callback(
      base::Bind(&SignalEvent, start_event.Get()));
  logger.set_stopped_callback(
      base::Bind(&SignalEvent, stop_event.Get()));
  logger.set_interrupted_callback(
      base::Bind(&SignalEvent, interrupt_event.Get()));

  // Save the instance_id for the Ctrl-C handler.
  ::wcsncpy_s(saved_instance_id,
              arraysize(saved_instance_id),
              instance_id_.c_str(),
              _TRUNCATE);

  // Register the handler for Ctrl-C.
  if (!SetConsoleCtrlHandler(&OnConsoleCtrl, TRUE)) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "Failed to register shutdown handler: "
               << ::common::LogWe(error) << ".";
    return false;
  }

  // Start the logger.
  RpcLoggerInstanceManager instance_manager(&logger);
  if (!logger.Start()) {
    LOG(ERROR) << "Failed to start '" << logger_name << "'.";
    return false;
  }

  bool error = false;

  // Run the logger, either standalone or as the parent of some application.
  trace::common::ScopedConsoleCtrlHandler ctrl_handler;
  if (app_command_line_.get() != NULL) {
    // We have a command to run, so launch that command and when it finishes
    // stop the logger.
    int exit_code = 0;
    if (!RunApp(*app_command_line_, instance_id_, interrupt_event,
                &exit_code) ||
        exit_code != 0) {
      error = true;
    }
    ignore_result(logger.Stop());
  } else {
    // There is no command to wait for, so just register the control handler
    // (we stop the logger if this fails) and then let the logger run until
    // the control handler stops it or someone externally stops it using the
    // stop command.
    if (!ctrl_handler.Init(&OnConsoleCtrl)) {
      ignore_result(logger.Stop());
      error = true;
    }
  }

  // Run the logger to completion.
  if (!logger.Join()) {
    LOG(ERROR) << "Failed running to completion '" << logger_name << "'.";
    error = true;
  }

  // And we're done.
  return !error;
}

bool LoggerApp::Status() {
  // TODO(rogerm): Implement me.
  return false;
}

bool LoggerApp::Spawn() {
  std::wstring logger_name(
      GetInstanceString(kLoggerRpcEndpointRoot, instance_id_));

  LOG(INFO) << "Launching background logging service '" << logger_name << "'.";

  // Get the path to ourselves.
  base::FilePath self_path;
  PathService::Get(base::FILE_EXE, &self_path);

  // Build a command line for starting a new instance of the logger.
  CommandLine new_command_line(self_path);
  new_command_line.AppendArg("start");

  // Copy over any other switches.
  CommandLine::SwitchMap::const_iterator it =
      logger_command_line_.GetSwitches().begin();
  for (; it != logger_command_line_.GetSwitches().end(); ++it)
    new_command_line.AppendSwitchNative(it->first, it->second);

  // Launch a new process in the background.
  base::ProcessHandle service_process;
  base::LaunchOptions options;
  options.start_hidden = true;
  if (!base::LaunchProcess(new_command_line, options, &service_process)) {
    LOG(ERROR) << "Failed to launch process.";
    return false;
  }
  DCHECK_NE(base::kNullProcessHandle, service_process);

  // Setup the start event.
  base::win::ScopedHandle start_event;
  std::wstring start_event_name(
      GetInstanceString(kLoggerStartEventRoot, instance_id_));
  if (!trace::common::InitEvent(start_event_name, &start_event)) {
    LOG(ERROR) << "Unable to init start event for '" << logger_name << "'.";
    return false;
  }

  // We wait on both the start event and the process, as if the process fails
  // for any reason, it'll exit and its handle will become signaled.
  HANDLE handles[] = { start_event, service_process };
  if (::WaitForMultipleObjects(arraysize(handles),
                               handles,
                               FALSE,
                               INFINITE) != WAIT_OBJECT_0) {
    LOG(ERROR) << "The logger '" << logger_name << "' exited in error.";
    return false;
  }

  LOG(INFO) << "Background logger '" << logger_name << "' is running.";

  return true;
}

bool LoggerApp::Stop() {
  std::wstring logger_name(
      GetInstanceString(kLoggerRpcEndpointRoot, instance_id_));

  // Setup the stop event.
  base::win::ScopedHandle stop_event;
  std::wstring stop_event_name(
      GetInstanceString(kLoggerStopEventRoot, instance_id_));
  if (!trace::common::InitEvent(stop_event_name, &stop_event)) {
    LOG(ERROR) << "Unable to init stop event for '" << logger_name << "'.";
    return false;
  }

  // Send the stop request.
  if (!SendStopRequest(instance_id_))
    return false;

  // We wait on both the RPC event and the process, as if the process fails for
  // any reason, it'll exit and its handle will become signaled.
  if (::WaitForSingleObject(stop_event, INFINITE) != WAIT_OBJECT_0) {
    LOG(ERROR) << "Timed out waiting for '" << logger_name << "' to stop.";
    return false;
  }

  LOG(INFO) << "The logger instance has stopped.";

  return true;
}

// Helper to resolve @p path to an open file. This will set @p must_close
// to true if @path denotes a newly opened file, and false if it denotes
// stderr or stdout.
bool LoggerApp::OpenOutputFile(FILE** output_file, bool* must_close) {
  DCHECK(output_file != NULL);
  DCHECK(must_close != NULL);

  *output_file = NULL;
  *must_close = false;

  // Check for stdout.
  if (output_file_path_.empty() ||
      ::_wcsnicmp(output_file_path_.value().c_str(),
                  kStdOut,
                  arraysize(kStdOut)) == 0) {
    *output_file = stdout;
    return true;
  }

  // Check for stderr.
  if (::_wcsnicmp(output_file_path_.value().c_str(),
                  kStdErr,
                  arraysize(kStdErr)) == 0) {
    *output_file = stderr;
    return true;
  }

  // Setup the write mode.
  const char* mode = "wb";
  if (append_)
    mode = "ab";

  // Create a new file, which the caller is responsible for closing.
  *output_file = file_util::OpenFile(output_file_path_, mode);
  if (*output_file == NULL)
    return false;

  *must_close = true;
  return true;
}

// Print the usage/help text, plus an optional @p message.
bool LoggerApp::Usage(const CommandLine* command_line,
                      const base::StringPiece& message) const {
  if (!message.empty()) {
    ::fwrite(message.data(), 1, message.length(), err());
    ::fprintf(err(), "\n\n");
  }

  ::fprintf(err(),
            kUsageFormatStr,
            command_line->GetProgram().BaseName().value().c_str());

  return false;
}

}  // namespace agent_logger
}  // namespace trace
