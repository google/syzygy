// Copyright 2010 Google Inc.
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
// Implementation of the LogTimer class.

// Turns the DEFINE_GUID for EventTraceGuid into a const.
#define INITGUID

#include "sawbuck/log_timer/log_timer.h"

#include <iostream>
#include "base/logging.h"
#include "base/stringprintf.h"
#include "base/string_util.h"
#include "sawbuck/log_lib/buffer_parser.h"

LogTimer* LogTimer::instance_ = NULL;

LogTimer::LogTimer() {
  instance_ = this;
}

LogTimer::~LogTimer() {
  instance_ = NULL;
}

void LogTimer::AddEvent(LogTimer::Event event) {
  events_.push_back(event);
}

void LogTimer::ProcessLog(const std::wstring& logfile_path) {
  event_index_ = 0;

  // Create a trace log file.
  EVENT_TRACE_LOGFILE trace_logfile = {};
  trace_logfile.LogFileName = const_cast<LPWSTR>(logfile_path.c_str());
  trace_logfile.EventRecordCallback = LogTimer::OnEventRecord;
  trace_logfile.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD;

  // Open the trace.
  TRACEHANDLE trace = OpenTrace(&trace_logfile);
  if (trace == INVALID_PROCESSTRACE_HANDLE) {
    LOG(ERROR) << "OpenTrace failed with " << GetLastError() << "\n";
    return;
  }

  // Process the trace.
  ULONG status = ProcessTrace(&trace, 1, 0, 0);
  if (status != ERROR_SUCCESS && status != ERROR_CANCELLED) {
    LOG(ERROR) << "ProcessTrace failed with " << status << "\n";
  }

  // Clean up.
  if (trace != INVALID_PROCESSTRACE_HANDLE) {
    status = CloseTrace(trace);
  }
}

void WINAPI LogTimer::OnEventRecord(EVENT_RECORD* event_record) {
  instance_->ProcessEvent(event_record);
}

void LogTimer::ProcessEvent(EVENT_RECORD* event_record) {
  // Skips the event if it is the event trace header. Log files contain this
  // event but real-time sessions do not. The event contains the same
  // information as the EVENT_TRACE_LOGFILE.LogfileHeader member that you can
  // access when you open the trace.
  if (IsEqualGUID(event_record->EventHeader.ProviderId, EventTraceGuid) &&
      event_record->EventHeader.EventDescriptor.Opcode ==
          EVENT_TRACE_TYPE_INFO) {
    // Skip this event.
  } else {
    // Get the event information and compare it to the event we're looking for.
    scoped_ptr<TRACE_EVENT_INFO> event_info;
    DWORD event_info_len;
    DWORD status = GetEventRecordInfo(event_record, &event_info,
                                      &event_info_len);

    if (status == ERROR_SUCCESS) {
      // Note that we don't handle DecodingSourceWbem nor DecodingSourceWPP.
      if (event_info->DecodingSource == DecodingSourceXMLFile) {
        // Get the expected event.
        Event& event = events_[event_index_];

        // Transform the event info into a log event so we can compare to
        // our expected event.
        Event log_event;
        GetEventFromInfo(event_info.get(), event_info_len, &log_event);

        // If the expected event contains a GUID, try to get a GUID from the
        // event record's user data. This is a hack as we should consult the
        // schema, but it appears to contain the GUID of the plugin for which
        // the event was fired.
        if (event.guid != GUID_NULL &&
            event_record->UserDataLength == sizeof(GUID))
          log_event.guid = *static_cast<GUID*>(event_record->UserData);

        // Does the log event match the expected event?
        if (log_event == event) {
          event.time = base::Time::FromFileTime(
              reinterpret_cast<FILETIME&>(event_record->EventHeader.TimeStamp));
          if (event_index_ == 0) {
            start_time_ = event.time;
          }

          base::TimeDelta delta = event.time - start_time_;
          int64 minutes = delta.InMinutes() % 60;
          int64 seconds = delta.InSeconds() % 60;
          int64 milliseconds = delta.InMilliseconds() % 1000;
          std::wstring time_str = StringPrintf(L"%02lld:%02lld.%03lld",
                                               minutes, seconds, milliseconds);
          std::wcout << event.provider << "/" << event.task << "/" <<
              event.opcode << " - " << time_str << "\n";

          // Did we make it through the whole expected sequence?
          if (++event_index_ == events_.size()) {
            std::wcout << "Total: " << time_str << "\n";

            event_index_ = 0;
          }
        }
      }
    }
  }
}

DWORD LogTimer::GetEventRecordInfo(EVENT_RECORD* event_record,
                                   scoped_ptr<TRACE_EVENT_INFO>* event_info,
                                   DWORD* event_info_len) {
  *event_info_len = 0;
  DWORD status = ::TdhGetEventInformation(event_record, 0, NULL,
                                          event_info->get(), event_info_len);

  if (status == ERROR_INSUFFICIENT_BUFFER) {
    event_info->reset(
        reinterpret_cast<TRACE_EVENT_INFO*>(new char[*event_info_len]));
    if (*event_info == NULL) {
      LOG(ERROR) << "Failed to allocate memory for event info (size=" <<
          *event_info_len << ")\n";
      return ERROR_OUTOFMEMORY;
    }

    status = ::TdhGetEventInformation(event_record, 0, NULL, event_info->get(),
                                      event_info_len);
  }

  if (status != ERROR_SUCCESS) {
    LOG(ERROR) << "TdhGetEventInformation failed with " << status << "\n";
  }

  return status;
}

void LogTimer::GetEventFromInfo(const TRACE_EVENT_INFO* event_info,
                                DWORD event_info_len, Event* event) {
  BinaryBufferParser reader(event_info, event_info_len);
  size_t len;

  const wchar_t* provider = L"";
  reader.GetStringAt(event_info->ProviderNameOffset, &provider, &len);

  const wchar_t* task = L"";
  reader.GetStringAt(event_info->TaskNameOffset, &task, &len);

  const wchar_t* opcode = L"";
  reader.GetStringAt(event_info->OpcodeNameOffset, &opcode, &len);

  TrimWhitespace(provider, TRIM_ALL, &event->provider);
  TrimWhitespace(task, TRIM_ALL, &event->task);
  TrimWhitespace(opcode, TRIM_ALL, &event->opcode);
}
