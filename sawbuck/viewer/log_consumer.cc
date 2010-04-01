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
#include "sawbuck/viewer/log_consumer.h"

#include "base/logging.h"
#include "base/logging_win.h"
#include <initguid.h>  // NOLINT - must be last include.

LogParser::LogParser() : log_event_sink_(NULL) {
}

LogParser::~LogParser() {
}

bool LogParser::ProcessOneEvent(PEVENT_TRACE event) {
  // Is it a log message?
  if (event->Header.Guid == logging::kLogEventId) {
    if (event->Header.Class.Type == logging::LOG_MESSAGE &&
        event->Header.Class.Version == 0) {
      log_event_sink_->OnLogMessage(
          event->Header.Class.Level, event->Header.ProcessId,
          event->Header.ThreadId, event->Header.TimeStamp,
          0, NULL, event->MofLength,
          reinterpret_cast<const char*>(event->MofData));

      // We processed the event.
      return true;
    } else if (event->Header.Class.Type ==
        logging::LOG_MESSAGE_WITH_STACKTRACE &&
        event->Header.Class.Version == 0) {
      // The format of the binary log message is:
      // 1. A DWORD containing the stack trace depth.
      DWORD* depth = reinterpret_cast<DWORD*>(event->MofData);
      // 2. The stack trace as an array of "depth" void pointers.
      void** backtrace = reinterpret_cast<void**>(depth + 1);
      // 3. Followed lastly by the ascii string message, which should
      //    be zero-terminated, though we don't rely on that.
      const char* msg = reinterpret_cast<const char*>(&backtrace[*depth]);
      size_t trace_len = sizeof(depth) + sizeof(backtrace[0]) * *depth;
      log_event_sink_->OnLogMessage(
          event->Header.Class.Level, event->Header.ProcessId,
          event->Header.ThreadId, event->Header.TimeStamp,
          *depth, backtrace, event->MofLength - trace_len, msg);

      // We processed the event.
      return true;
    }
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
