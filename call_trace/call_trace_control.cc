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
#include "syzygy/call_trace/call_trace_defs.h"

using base::win::EtwTraceController;
using base::win::EtwTraceProperties;

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


static void GetFlags(FilePath* kernel_file,
                     FilePath* call_trace_file,
                     std::wstring* call_trace_session,
                     int* flags) {
  CommandLine* cmd_line = CommandLine::ForCurrentProcess();

  *kernel_file = cmd_line->GetSwitchValuePath("kernel-file");
  *call_trace_file = cmd_line->GetSwitchValuePath("call-trace-file");
  *call_trace_session = cmd_line->GetSwitchValueNative("call-trace-session");
  if (!base::StringToInt(cmd_line->GetSwitchValueASCII("kernel-flags"),
                                                       flags)) {
    *flags = kDefaultKernelFlags;
  }

  if (kernel_file->empty())
    *kernel_file = FilePath(L"kernel.etl");

  if (call_trace_file->empty())
    *call_trace_file = FilePath(L"call_trace.etl");

  if (call_trace_session->empty())
    *call_trace_session = L"call_trace";
}

void CALLBACK BeginCallTrace(HWND unused_window,
                             HINSTANCE unused_instance,
                             LPSTR unused_cmd_line,
                             int unused_show) {
  CommandLine::Init(0, NULL);

  FilePath kernel_file;
  FilePath call_trace_file;
  std::wstring call_trace_session;
  int flags = 0;
  GetFlags(&kernel_file, &call_trace_file, &call_trace_session, &flags);

  EtwTraceProperties props;
  EVENT_TRACE_PROPERTIES* p = props.get();

  // Use the CPU cycle counter.
  p->Wnode.ClientContext = 3;

  p->BufferSize = 10 * 1024;  // 10 Mb buffer size
  p->MinimumBuffers = 25;
  p->MaximumBuffers = 50;
  p->LogFileMode = EVENT_TRACE_FILE_MODE_NONE;
  // TODO(chrisha): Replace stop_call_trace.bat with an EndCallTrace
  //     function, and have it manually flush the buffers. Then we can put
  //     this flush timer back to 0.
  p->FlushTimer = 30;
  p->EnableFlags = 0;

  props.SetLoggerFileName(call_trace_file.value().c_str());

  // Create the call trace session.
  TRACEHANDLE session_handle = NULL;
  HRESULT hr = EtwTraceController::Start(call_trace_session.c_str(),
                                         &props,
                                         &session_handle);
  if (FAILED(hr)) {
    LOG(ERROR) << "Failed to start call trace session" << hr;
    return;
  }

  // And enable batch enter logging.
  ULONG err = ::EnableTrace(TRUE,
                            TRACE_FLAG_BATCH_ENTER,
                            CALL_TRACE_LEVEL,
                            &kCallTraceProvider,
                            session_handle);
  if (err != ERROR_SUCCESS) {
    LOG(ERROR) << "Failed to enable call trace " << err;
    return;
  }

  // Now start the kernel session.
  p->Wnode.Guid = kSystemTraceControlGuid;
  p->EnableFlags = flags;
  props.SetLoggerFileName(kernel_file.value().c_str());

  hr = EtwTraceController::Start(KERNEL_LOGGER_NAMEW,
                                 &props,
                                 &session_handle);
  if (FAILED(hr)) {
    LOG(ERROR) << "Failed to start kernel trace session" << hr;
    return;
  }
}
