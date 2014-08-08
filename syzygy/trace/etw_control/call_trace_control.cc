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

#include <windows.h>  // NOLINT

#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/logging.h"
#include "base/debug/trace_event_win.h"
#include "base/files/file_path.h"
#include "base/strings/string_number_conversions.h"
#include "base/win/event_trace_controller.h"
#include "syzygy/common/com_utils.h"
#include "syzygy/trace/protocol/call_trace_defs.h"

using base::win::EtwTraceController;
using base::win::EtwTraceProperties;

namespace {

static const wchar_t kCallTraceSessionName[] = L"Call Trace Logger";
static const wchar_t kChromeSessionName[] = L"Chrome Event Logger";
static const wchar_t kDefaultCallTraceFile[] = L"call_trace.etl";
static const wchar_t kDefaultKernelFile[] = L"kernel.etl";

enum FileMode {
  kFileOverwrite,
  kFileAppend
};

struct CallTraceOptions {
  base::FilePath call_trace_file;
  base::FilePath kernel_file;
  base::FilePath chrome_file;
  FileMode file_mode;
  int flags;
  int min_buffers;
};

// Initializes the command-line and logging for functions called via rundll32.
static void Init() {
  CommandLine::Init(0, NULL);

  logging::LoggingSettings settings;
  settings.logging_dest = logging::LOG_TO_SYSTEM_DEBUG_LOG;
  settings.lock_log = logging::DONT_LOCK_LOG_FILE;
  settings.delete_old = logging::APPEND_TO_OLD_LOG_FILE;
  logging::InitLogging(settings);
}

// Parses command-line options for StartCallTrace.
static bool ParseOptions(CallTraceOptions* options) {
  DCHECK(options != NULL);

  CommandLine* cmd_line = CommandLine::ForCurrentProcess();

  options->call_trace_file = cmd_line->GetSwitchValuePath("call-trace-file");
  if (options->call_trace_file.empty())
    options->call_trace_file = base::FilePath(kDefaultCallTraceFile);

  options->kernel_file = cmd_line->GetSwitchValuePath("kernel-file");
  if (options->kernel_file.empty())
    options->kernel_file = base::FilePath(kDefaultKernelFile);

  // This is an optional argument. If specified, it must be different from
  // call-trace-file and kernel-file.
  options->chrome_file = cmd_line->GetSwitchValuePath("chrome-file");
  if (!options->chrome_file.empty()) {
    if (options->chrome_file == options->call_trace_file ||
        options->chrome_file == options->kernel_file) {
      LOG(ERROR) << "chrome-file must be different from call-trace-file "
          "and kernel-file.";
      return false;
    }
  }

  if (options->call_trace_file == options->kernel_file) {
    LOG(ERROR) << "call-trace-file and kernel-file must be different.";
    return false;
  }

  if (!base::StringToInt(cmd_line->GetSwitchValueASCII("kernel-flags"),
                                                       &options->flags)) {
    options->flags = kDefaultEtwKernelFlags;
  }

  if (!base::StringToInt(cmd_line->GetSwitchValueASCII("min-buffers"),
                                                       &options->min_buffers)) {
    options->min_buffers = 0;
  }

  if (cmd_line->HasSwitch("append"))
    options->file_mode = kFileAppend;
  else
    options->file_mode = kFileOverwrite;

  return true;
}

enum EtwTraceType {
  kKernelType,
  kCallTraceType,
  kChromeType,
};

// Sets up basic ETW trace properties.
static void SetupEtwProperties(EtwTraceType trace_type,
                               const CallTraceOptions& options,
                               EtwTraceProperties* properties) {
  EVENT_TRACE_PROPERTIES* p = properties->get();

  SYSTEM_INFO sysinfo = { 0 };
  GetSystemInfo(&sysinfo);

  // Use the CPU cycle counter.
  p->Wnode.ClientContext = 3;
  // The buffer size caps out at 1 MB, so we set it to the maximum. The value
  // here is in KB.
  p->BufferSize = 1024;

  // We'll manually flush things in EndCallTrace.
  p->FlushTimer = 0;

  switch (trace_type) {
    case kKernelType: {
      properties->SetLoggerFileName(options.kernel_file.value().c_str());

      p->Wnode.Guid = kSystemTraceControlGuid;
      p->EnableFlags = options.flags;

      // Kernel traces need two buffers per CPU: one flushing to disk, the other
      // being used for live events. This has been sufficient in all situations
      // we've seen thus far.
      p->MinimumBuffers = 2 * sysinfo.dwNumberOfProcessors;
      p->MaximumBuffers = 4 * sysinfo.dwNumberOfProcessors;
      break;
    }

    case kCallTraceType: {
      properties->SetLoggerFileName(options.call_trace_file.value().c_str());

      p->EnableFlags = 0;

      // The call_trace library seems to settle out anywhere from 7 to 12
      // buffers per CPU under heavy usage. We provide roughly half that to
      // start, with a hefty margin.
      p->MinimumBuffers =
          kMinEtwBuffersPerProcessor * sysinfo.dwNumberOfProcessors;
      if (p->MinimumBuffers < kMinEtwBuffers)
        p->MinimumBuffers = kMinEtwBuffers;
      if (options.min_buffers > signed(p->MinimumBuffers))
        p->MinimumBuffers = options.min_buffers;
      p->MaximumBuffers = kEtwBufferMultiplier * p->MinimumBuffers;

      break;
    }

    case kChromeType: {
      // This should never be called with an empty file name.
      DCHECK(!options.chrome_file.empty());

      properties->SetLoggerFileName(options.chrome_file.value().c_str());

      // Chrome is quite low volume.
      p->EnableFlags = 0;
      p->MinimumBuffers = 1;
      p->MaximumBuffers = 5;

      break;
    }

    default: {
      NOTREACHED() << "Invalid EtwTraceType.";
    }
  }

  // Set the logging mode.
  switch (options.file_mode) {
    case kFileAppend: {
      p->LogFileMode = EVENT_TRACE_FILE_MODE_APPEND;
      break;
    }

    case kFileOverwrite: {
      p->LogFileMode = EVENT_TRACE_FILE_MODE_NONE;
      break;
    }

    default: {
      NOTREACHED() << "Invalid FileMode.";
    }
  }
}

enum StartSessionResult {
  kStarted,
  kAlreadyStarted,
  kError
};

// Logs some summary information about a trace given its properties.
static void DumpEtwTraceProperties(const wchar_t* session_name,
                                   EtwTraceProperties& props) {
  LOG(INFO) << "Session '" << session_name << "' is logging to '"
      << props.GetLoggerFileName() << "'.";
  LOG(INFO) << "  BufferSize = " << props.get()->BufferSize << " Kb";
  LOG(INFO) << "  BuffersWritten = " << props.get()->BuffersWritten;
  LOG(INFO) << "  EventsLost = " << props.get()->EventsLost;
  LOG(INFO) << "  NumberOfBuffers = " << props.get()->NumberOfBuffers;
}

// Attempts to start an ETW trace with the given properties, returning a
// handle to it via @p session_handle.
static StartSessionResult StartSession(const wchar_t* session_name,
                                       EtwTraceProperties* props,
                                       TRACEHANDLE* session_handle) {
  DCHECK(session_name != NULL);
  DCHECK(props != NULL);
  DCHECK(session_handle != NULL);

  *session_handle = NULL;

  LOG(INFO) << "Starting '" << session_name
      << "' session with output '" << props->GetLoggerFileName() << "'.";
  HRESULT hr = EtwTraceController::Start(session_name,
                                         props,
                                         session_handle);
  if (HRESULT_CODE(hr) == ERROR_ALREADY_EXISTS) {
    LOG(WARNING) << "Session '" << session_name << "' already exists.";
    return kAlreadyStarted;
  }
  if (FAILED(hr)) {
    LOG(ERROR) << "Failed to start call trace session: "
        << ::common::LogHr(hr) << ".";
    return kError;
  }

  DumpEtwTraceProperties(session_name, *props);

  return kStarted;
}

// Logs information about a running ETW trace given its session name.
static bool DumpSessionStatus(const wchar_t* session_name) {
  EtwTraceProperties props;
  LOG(INFO) << "Querying session '" << session_name << "'.";
  HRESULT hr = EtwTraceController::Query(session_name, &props);
  if (HRESULT_CODE(hr) == ERROR_WMI_INSTANCE_NOT_FOUND) {
    LOG(ERROR) << "Session '" << session_name << "' does not exist.";
    return true;
  }
  if (FAILED(hr)) {
    LOG(ERROR) << "Failed to query '" << session_name << "' session: "
        << ::common::LogHr(hr) << ".";
    return false;
  }

  DumpEtwTraceProperties(session_name, props);

  return true;
}

// Stops the given ETW logging session given its name and properties.
// Returns true on success, false otherwise.
static bool StopSession(const wchar_t* session_name,
                        EtwTraceProperties* props) {
  LOG(INFO) << "Stopping session '" << session_name << "'.";
  HRESULT hr = EtwTraceController::Stop(session_name, props);
  if (FAILED(hr)) {
    LOG(ERROR) << "Failed to stop '" << session_name << "' session: "
        << ::common::LogHr(hr) << ".";
    return false;
  }

  return true;
}

// Flushes and closes the trace with the given session name, returning
// its file name via @p file_name. Returns true on success, false otherwise.
static bool FlushAndStopSession(const wchar_t* session_name,
                                std::wstring* file_name) {
  DCHECK(file_name != NULL);

  EtwTraceProperties props;
  LOG(INFO) << "Querying session '" << session_name << "'.";
  HRESULT hr = EtwTraceController::Query(session_name, &props);
  if (FAILED(hr)) {
    LOG(ERROR) << "Failed to query '" << session_name << "' session: "
        << ::common::LogHr(hr) << ".";
    return false;
  }

  *file_name = props.GetLoggerFileName();

  LOG(INFO) << "Flushing session '" << session_name << "'.";
  hr = EtwTraceController::Flush(session_name, &props);
  if (FAILED(hr)) {
    LOG(ERROR) << "Failed to flush '" << session_name << "' session: "
        << ::common::LogHr(hr) << ".";
    return false;
  }

  if (!StopSession(session_name, &props))
    return false;

  // Log some information about the trace.
  DumpEtwTraceProperties(session_name, props);

  return true;
}

class ScopedSession {
 public:
  ScopedSession(const wchar_t* session_name,
                EtwTraceProperties* properties)
      : name_(session_name), props_(properties) {
    DCHECK(session_name != NULL);
    DCHECK(properties != NULL);
  }

  ~ScopedSession() {
    DCHECK((name_ == NULL) == (props_ == NULL));
    if (name_) {
      StopSession(name_, props_);
    }
  }

  void Release() {
    name_ = NULL;
    props_ = NULL;
  }

 private:
  const wchar_t* name_;
  EtwTraceProperties* props_;
};

}  // namespace

bool StartCallTraceImpl() {
  CallTraceOptions options;
  if (!ParseOptions(&options))
    return false;

  // Start the call-trace ETW session.
  EtwTraceProperties call_trace_props;
  SetupEtwProperties(kCallTraceType, options, &call_trace_props);
  TRACEHANDLE session_handle = NULL;
  StartSessionResult result = StartSession(kCallTraceSessionName,
                                           &call_trace_props,
                                           &session_handle);
  if (result == kError)
    return false;

  // Automatically clean up this session if we exit early.
  ScopedSession call_trace_session(kCallTraceSessionName, &call_trace_props);

  // If we started the session (it wasn't already running), enable batch
  // entry logging. If we received kAlreadyStarted, session_handle is invalid
  // so we're can't call EnableTrace.
  if (result == kStarted) {
    // Enable batch entry logging.
    ULONG err = ::EnableTrace(TRUE,
                              TRACE_FLAG_BATCH_ENTER,
                              CALL_TRACE_LEVEL,
                              &kCallTraceProvider,
                              session_handle);
    if (err != ERROR_SUCCESS) {
      LOG(ERROR) << "Failed to enable call trace batch logging: "
          << ::common::LogWe(err) << ".";
      return false;
    }
  }

  // Start the kernel ETW session.
  EtwTraceProperties kernel_props;
  SetupEtwProperties(kKernelType, options, &kernel_props);
  result = StartSession(KERNEL_LOGGER_NAMEW, &kernel_props, &session_handle);
  if (result == kError) {
    LOG(INFO) << "Failed to start '" << KERNEL_LOGGER_NAMEW << "' session, "
        << "shutting down '" << kCallTraceSessionName << "' sesion.";
    return false;
  }

  // Automatically clean up this session if we exit early.
  ScopedSession kernel_session(KERNEL_LOGGER_NAMEW, &kernel_props);

  // If a chrome file name has been provided, enable it as well.
  if (!options.chrome_file.empty()) {
    EtwTraceProperties chrome_props;
    SetupEtwProperties(kChromeType, options, &chrome_props);
    result = StartSession(kChromeSessionName, &chrome_props, &session_handle);
    if (result == kError) {
      LOG(INFO) << "Failed to start '" << kChromeSessionName << "' session, "
          << "shutting down other session.";
      return false;
    }

    // Automatically clean up this session if we exit early.
    ScopedSession chrome_session(kChromeSessionName, &chrome_props);

    if (result == kStarted) {
      // Enable Chrome trace events.
      ULONG err = ::EnableTrace(TRUE,
                                0,
                                TRACE_LEVEL_INFORMATION,
                                &base::debug::kChromeTraceProviderName,
                                session_handle);
      if (err != ERROR_SUCCESS) {
        LOG(ERROR) << "Failed to enable Chrome logging: "
                   << ::common::LogWe(err) << ".";
        return false;
      }
    }

    // Release the ScopedSession so it doesn't get torn down.
    chrome_session.Release();
  }

  // Release the ScopedSessions so that they don't get torn down as we're
  // exiting successfully.
  kernel_session.Release();
  call_trace_session.Release();

  // Sleep a bit to allow the call-trace session to settle down. When the
  // kernel trace is started, all running processes and modules in memory are
  // enumerated.
  // TODO(chrisha): Be a little smarter here, and continuously monitor the
  //     event rate for each session, and wait until the initial spurt of
  //     activity is finished.
  ::Sleep(2500);

  return true;
}

bool QueryCallTraceImpl() {
  bool success = true;

  if (!DumpSessionStatus(kCallTraceSessionName))
    success = false;

  if (!DumpSessionStatus(KERNEL_LOGGER_NAMEW))
    success = false;

  if (!DumpSessionStatus(kChromeSessionName))
    success = false;

  return success;
}

bool StopCallTraceImpl() {
  // Always try stopping both traces before exiting on error. It may be that
  // one of them was already stopped manually and FlushAndStopSession will
  // return failure.
  std::wstring call_trace_file;
  std::wstring kernel_file;
  std::wstring chrome_file;
  bool success = true;
  if (!FlushAndStopSession(kCallTraceSessionName, &call_trace_file))
    success = false;
  if (!FlushAndStopSession(KERNEL_LOGGER_NAMEW, &kernel_file))
    success = false;

  EtwTraceProperties props;
  HRESULT hr = EtwTraceController::Query(kChromeSessionName, &props);
  if (SUCCEEDED(hr)) {
    LOG(INFO) << "Detected optional session: '" << kChromeSessionName << "'.";
    if (!FlushAndStopSession(kChromeSessionName, &chrome_file))
      success = false;
  }

  // TODO(chrisha): Add ETL file merging support here.
  return success;
}

void CALLBACK StartCallTrace(HWND unused_window,
                             HINSTANCE unused_instance,
                             LPSTR unused_cmd_line,
                             int unused_show) {
  Init();
  StartCallTraceImpl();
}

void CALLBACK StopCallTrace(HWND unused_window,
                           HINSTANCE unused_instance,
                           LPSTR unused_cmd_line,
                           int unused_show) {
  Init();
  StopCallTraceImpl();
}
