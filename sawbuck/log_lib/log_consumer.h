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
// Log consumer declaration.
#ifndef SAWBUCK_LOG_LIB_LOG_CONSUMER_H_
#define SAWBUCK_LOG_LIB_LOG_CONSUMER_H_

#include "base/time/time.h"
#include "base/win/event_trace_consumer.h"

struct LogMessageBase {
  LogMessageBase() : level(0), process_id(0), thread_id(0), trace_depth(0),
      traces(NULL) {
  }

  base::Time time;
  UCHAR level;
  DWORD process_id;
  DWORD thread_id;

  size_t trace_depth;
  void* const* traces;
};

// Implemented by clients of LogParser to receive log message notifications.
class LogEvents {
 public:
  struct LogMessage : public LogMessageBase {
    LogMessage() : message_len(0), message(NULL), file_len(0), file(NULL),
        line(0) {
    }

    size_t message_len;
    const char* message;

    // File/line information, if available.
    size_t file_len;
    const char* file;
    int line;
  };

  // Issued for log messages.
  // Note: log_message is not valid beyond the call, any strings
  //    you need to hold on to must be copied.
  virtual void OnLogMessage(const LogMessage& log_message) = 0;
};

// Implemented by clients of LogParser to receive trace message notifications.
class TraceEvents {
 public:
  struct TraceMessage : public LogMessageBase {
    TraceMessage() : name_len(0), name(NULL), id(0), extra(0), extra_len(0) {
    }

    size_t name_len;
    const char* name;
    void* id;
    size_t extra_len;
    const char* extra;
  };

  // Issued for trace events.
  // Note: trace_message is not valid beyond the call, any strings
  //    you need to hold on to must be copied.
  virtual void OnTraceEventBegin(const TraceMessage& trace_message) = 0;
  virtual void OnTraceEventEnd(const TraceMessage& trace_message) = 0;
  virtual void OnTraceEventInstant(const TraceMessage& trace_message) = 0;
};

class LogParser {
 public:
  LogParser();
  ~LogParser();

  void set_event_sink(LogEvents* log_event_sink){
    log_event_sink_ = log_event_sink;
  }
  void set_trace_sink(TraceEvents* trace_event_sink){
    trace_event_sink_ = trace_event_sink;
  }

  bool ProcessOneEvent(EVENT_TRACE* event);

 private:
  bool ParseLogEvent(EVENT_TRACE* event);
  bool ParseTraceEvent(EVENT_TRACE* event);

  // Our log event sink.
  LogEvents* log_event_sink_;

  // Our trace event sink.
  TraceEvents* trace_event_sink_;
};

class LogConsumer
    : public base::win::EtwTraceConsumerBase<LogConsumer>,
      public LogParser {
 public:
  LogConsumer();
  ~LogConsumer();

  static DWORD WINAPI ThreadProc(LPVOID param);
  static void ProcessEvent(EVENT_TRACE* event);
 private:
  static LogConsumer* current_;
};

#endif  // SAWBUCK_LOG_LIB_LOG_CONSUMER_H_
