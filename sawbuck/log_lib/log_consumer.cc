// Copyright 2009 Google Inc.
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
// Log consumer implementation.
#include "sawbuck/log_lib/log_consumer.h"

#include "base/debug/trace_event_win.h"
#include "base/logging.h"
#include "base/logging_win.h"
#include "sawbuck/common/buffer_parser.h"
#include <initguid.h>  // NOLINT - must be last include.

LogParser::LogParser() : log_event_sink_(NULL), trace_event_sink_(NULL) {
}

LogParser::~LogParser() {
}

bool LogParser::ProcessOneEvent(EVENT_TRACE* event) {
  DCHECK(event != NULL);

  // Is it a log message?
  if (event->Header.Guid == logging::kLogEventId) {
    return ParseLogEvent(event);
  } else if (event->Header.Guid == base::debug::kTraceEventClass32) {
    return ParseTraceEvent(event);
  }

  return false;
}

bool LogParser::ParseLogEvent(EVENT_TRACE* event) {
  DCHECK(event != NULL);

  // Don't perform any work unless there's a listener.
  if (log_event_sink_ == NULL)
    return false;

  BinaryBufferReader reader(event->MofData, event->MofLength);
  LogEvents::LogMessage msg;

  msg.time = base::Time::FromFileTime(
      reinterpret_cast<FILETIME&>(event->Header.TimeStamp));
  msg.level = event->Header.Class.Level;
  msg.process_id = event->Header.ProcessId;
  msg.thread_id = event->Header.ThreadId;

  if (event->Header.Class.Type == logging::LOG_MESSAGE &&
      event->Header.Class.Version == 0) {
    if (reader.ReadString(&msg.message, &msg.message_len)) {
      log_event_sink_->OnLogMessage(msg);
    } else {
      DLOG(ERROR) << "Failed to read message from event";
    }
    // We processed the event.
    return true;
  } else if (event->Header.Class.Type ==
      logging::LOG_MESSAGE_WITH_STACKTRACE &&
      event->Header.Class.Version == 0) {
    // The format of the binary log message is:
    // 1. A DWORD containing the stack trace depth.
    // 2. The trace, "depth" in number.
    // 3. The log message as a zero-terminated string.
    const DWORD* depth = NULL;
    if (reader.Read(&depth) &&
        reader.Read(*depth * sizeof(void*), &msg.traces) &&
        reader.ReadString(&msg.message, &msg.message_len)) {
      msg.trace_depth = *depth;
      log_event_sink_->OnLogMessage(msg);
    } else {
      DLOG(ERROR) << "Failed to read stack trace or message from event";
    }

    // We processed the event.
    return true;
  } else if (event->Header.Class.Type == logging::LOG_MESSAGE_FULL &&
             event->Header.Class.Version == 0) {
    // The format of the binary log message is:
    // 1. A DWORD containing the stack trace depth.
    // 2. The trace, "depth" in number.
    // 3. The line as a 4 byte integer value.
    // 4. The file as a zero-terminated string.
    // 5. The log message as a zero-terminated string.
    const DWORD* depth = NULL;
    const DWORD* line = NULL;
    if (reader.Read(&depth) &&
        reader.Read(*depth * sizeof(void*), &msg.traces) &&
        reader.Read(&line) &&
        reader.ReadString(&msg.file, &msg.file_len) &&
        reader.ReadString(&msg.message, &msg.message_len)) {
      msg.trace_depth = *depth;
      msg.line = *line;

      log_event_sink_->OnLogMessage(msg);

      // Event is handled.
      return true;
    } else {
      DLOG(ERROR) << "Failed to read event";
    }
  }

  return false;
}

bool LogParser::ParseTraceEvent(EVENT_TRACE* event) {
  DCHECK(event != NULL);

  // Don't perform any work unless there's a listener.
  if (trace_event_sink_ == NULL)
    return false;

  switch (event->Header.Class.Type) {
    case base::debug::kTraceEventTypeBegin:
    case base::debug::kTraceEventTypeEnd:
    case base::debug::kTraceEventTypeInstant:
      // It's a known type, parse it.
      break;

    default:
      LOG(ERROR) << "Unknown event type " << event->Header.Class.Type;
      return false;
  }

  if (event->Header.Class.Version != 0) {
    LOG(ERROR) << "Unknown event version " << event->Header.Class.Version;
    return false;
  }

  TraceEvents::TraceMessage trace;

  trace.time = base::Time::FromFileTime(
      reinterpret_cast<FILETIME&>(event->Header.TimeStamp));
  trace.level = event->Header.Class.Level;
  trace.process_id = event->Header.ProcessId;
  trace.thread_id = event->Header.ThreadId;
  BinaryBufferReader reader(event->MofData, event->MofLength);

  void* const* id = NULL;
  if (reader.ReadString(&trace.name, &trace.name_len) &&
      reader.Read(&id),
      reader.ReadString(&trace.extra, &trace.extra_len)) {
    DCHECK(id != NULL);
    trace.id = *id;

    switch (event->Header.Class.Type) {
      case base::debug::kTraceEventTypeBegin:
        trace_event_sink_->OnTraceEventBegin(trace);
        break;
      case base::debug::kTraceEventTypeEnd:
        trace_event_sink_->OnTraceEventEnd(trace);
        break;
      case base::debug::kTraceEventTypeInstant:
        trace_event_sink_->OnTraceEventInstant(trace);
        break;
      default:
        NOTREACHED();
        break;
    }

    return true;
  }

  return false;
}

LogConsumer* LogConsumer::current_ = NULL;

LogConsumer::LogConsumer() {
  DCHECK(current_ == NULL);

  current_ = this;
}

LogConsumer::~LogConsumer() {
  DCHECK(current_ == this);
  current_ = NULL;
}

void LogConsumer::ProcessEvent(PEVENT_TRACE event) {
  DCHECK(current_ != NULL);
  current_->ProcessOneEvent(event);
}

DWORD WINAPI LogConsumer::ThreadProc(LPVOID param) {
  LogConsumer* consumer = reinterpret_cast<LogConsumer*>(param);

  return consumer->Consume();
}
