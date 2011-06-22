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
#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/file_path.h"
#include "base/logging.h"
#include "base/string_number_conversions.h"
#include "base/win/event_trace_controller.h"
#include "sawbuck/common/com_utils.h"
#include "syzygy/call_trace/call_trace_defs.h"

using base::win::EtwTraceController;
using base::win::EtwTraceProperties;

namespace {

// {3D7926F7-6F59-4635-AAFD-0E95710FF60D}
const GUID kSystemTraceControlGuid =
    { 0x9e814aad, 0x3204, 0x11d2,
        { 0x9a, 0x82, 0x00, 0x60, 0x08, 0xa8, 0x69, 0x39 } };

const int kDefaultKernelFlags = EVENT_TRACE_FLAG_PROCESS |
                                EVENT_TRACE_FLAG_THREAD |
                                EVENT_TRACE_FLAG_IMAGE_LOAD |
                                EVENT_TRACE_FLAG_DISK_IO |
                                EVENT_TRACE_FLAG_DISK_FILE_IO |
                                EVENT_TRACE_FLAG_MEMORY_PAGE_FAULTS |
                                EVENT_TRACE_FLAG_MEMORY_HARD_FAULTS |
                                EVENT_TRACE_FLAG_FILE_IO;

static const wchar_t kCallTraceSessionName[] = L"Call Trace Logger";
static const wchar_t kDefaultCallTraceFile[] = L"call_trace.etl";
static const wchar_t kDefaultKernelFile[] = L"kernel.etl";

enum FileMode {
  kFileOverwrite,
  kFileAppend
};

struct CallTraceOptions {
  FilePath call_trace_file;
  FilePath kernel_file;
  FileMode file_mode;
  int flags;
};

// Initializes the command-line and logging for functions called via rundll32.
static void Init() {
  CommandLine::Init(0, NULL);
  logging::InitLogging(L"",
      logging::LOG_ONLY_TO_SYSTEM_DEBUG_LOG,
      logging::DONT_LOCK_LOG_FILE,
      logging::APPEND_TO_OLD_LOG_FILE,
      logging::ENABLE_DCHECK_FOR_NON_OFFICIAL_RELEASE_BUILDS);
}

// Parses command-line options for StartCallTrace.
static bool ParseOptions(CallTraceOptions* options) {
  DCHECK(options != NULL);

  CommandLine* cmd_line = CommandLine::ForCurrentProcess();

  options->call_trace_file = cmd_line->GetSwitchValuePath("call-trace-file");
  if (options->call_trace_file.empty())
    options->call_trace_file = FilePath(kDefaultCallTraceFile);

  options->kernel_file = cmd_line->GetSwitchValuePath("kernel-file");
  if (options->kernel_file.empty())
    options->kernel_file = FilePath(kDefaultKernelFile);

  if (options->call_trace_file == options->kernel_file) {
    LOG(ERROR) << "call-trace-file and kernel-file must be different.";
    return false;
  }

  if (!base::StringToInt(cmd_line->GetSwitchValueASCII("kernel-flags"),
                                                       &options->flags)) {
    options->flags = kDefaultKernelFlags;
  }

  if (cmd_line->HasSwitch("append"))
    options->file_mode = kFileAppend;
  else
    options->file_mode = kFileOverwrite;

  return true;
}

// Sets up basic ETW trace properties that are common to both call_trace
// and kernel.
static void SetupEtwProperties(const CallTraceOptions& options,
                               EtwTraceProperties* properties) {
  EVENT_TRACE_PROPERTIES* p = properties->get();

  SYSTEM_INFO sysinfo = { 0 };
  GetSystemInfo(&sysinfo);

  // Use the CPU cycle counter.
  p->Wnode.ClientContext = 3;
  // The buffer size caps out at 1 MB, so we set it to the maximum. The value
  // here is in KB.
  p->BufferSize = 1024;
  // We want at least two buffers per CPU. One active, the other being flushed.
  // The call_trace lib seems to settle out at around 7 buffers per processor
  // under heavy usage, so we provide a little breathing room in the maximum.
  p->MinimumBuffers = 2 * sysinfo.dwNumberOfProcessors;
  p->MaximumBuffers = 10 * sysinfo.dwNumberOfProcessors;

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

  // We'll manually flush things in EndCallTrace.
  p->FlushTimer = 0;
  p->EnableFlags = 0;
}

enum StartSessionResult {
  kStarted,
  kAlreadyStarted,
  kError
};

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
        << com::LogHr(hr) << ".";
    return kError;
  }

  return kStarted;
}

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
        << com::LogHr(hr) << ".";
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
        << com::LogHr(hr) << ".";
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
        << com::LogHr(hr) << ".";
    return false;
  }

  *file_name = props.GetLoggerFileName();

  LOG(INFO) << "Flushing session '" << session_name << "'.";
  hr = EtwTraceController::Flush(session_name, &props);
  if (FAILED(hr)) {
    LOG(ERROR) << "Failed to flush '" << session_name << "' session: "
        << com::LogHr(hr) << ".";
    return false;
  }

  if (!StopSession(session_name, &props))
    return false;

  // Log some information about the trace.
  DumpEtwTraceProperties(session_name, props);

  return true;
}

}  // namespace

bool StartCallTraceImpl() {
  CallTraceOptions options;
  if (!ParseOptions(&options))
    return false;

  // Start the call-trace ETW session.
  EtwTraceProperties call_trace_props;
  SetupEtwProperties(options, &call_trace_props);
  call_trace_props.SetLoggerFileName(options.call_trace_file.value().c_str());
  TRACEHANDLE session_handle = NULL;
  StartSessionResult result = StartSession(kCallTraceSessionName,
                                           &call_trace_props,
                                           &session_handle);
  if (result == kError)
    return false;
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
      LOG(ERROR) << "Failed to enable call trace: " << com::LogWe(err) << ".";
      return false;
    }
  }

  // Start the kernel ETW session.
  EtwTraceProperties kernel_props;
  SetupEtwProperties(options, &kernel_props);
  kernel_props.get()->Wnode.Guid = kSystemTraceControlGuid;
  kernel_props.get()->EnableFlags = options.flags;
  kernel_props.SetLoggerFileName(options.kernel_file.value().c_str());
  result = StartSession(KERNEL_LOGGER_NAMEW, &kernel_props, &session_handle);
  if (result == kError) {
    LOG(INFO) << "Failed to start '" << KERNEL_LOGGER_NAMEW << "' session, "
        << "shutting down '" << kCallTraceSessionName << "' sesion.";
    StopSession(kCallTraceSessionName, &call_trace_props);
    return false;
  }

  return true;
}

bool QueryCallTraceImpl() {
  if (!DumpSessionStatus(kCallTraceSessionName))
    return false;

  if (!DumpSessionStatus(KERNEL_LOGGER_NAMEW))
    return false;

  return true;
}

bool StopCallTraceImpl() {
  // Always try stopping both traces before exiting on error. It may be that
  // one of them was already stopped manually and FlushAndStopSession will
  // return failure.
  std::wstring call_trace_file;
  std::wstring kernel_file;
  bool success = true;
  if (!FlushAndStopSession(kCallTraceSessionName, &call_trace_file))
    success = false;
  if (!FlushAndStopSession(KERNEL_LOGGER_NAMEW, &kernel_file))
    success = false;

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
