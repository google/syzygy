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
#ifndef SAWBUCK_VIEWER_LOG_CONSUMER_H_
#define SAWBUCK_VIEWER_LOG_CONSUMER_H_

#include "base/basictypes.h"
#include "base/event_trace_consumer_win.h"
#include "base/time.h"
#include "sawbuck/sym_util/types.h"
#include <string>

// Implemented by clients of EventTraceConsumer to get module load
// event notifications.
class LogEvents {
 public:
  virtual void OnLogMessage(UCHAR level,
                            DWORD process_id,
                            DWORD thread_id,
                            LARGE_INTEGER time_stamp,
                            size_t num_traces,
                            void** stack_trace,
                            size_t length,
                            const char* message) = 0;
};

class LogParser {
 public:
  LogParser();
  ~LogParser();

  void set_event_sink(LogEvents* log_event_sink){
    log_event_sink_ = log_event_sink;
  }

  bool ProcessOneEvent(EVENT_TRACE* event);

 private:
  // Our log event sink.
  LogEvents* log_event_sink_;
};

class LogConsumer
    : public EtwTraceConsumerBase<LogConsumer>,
      public LogParser {
 public:
  LogConsumer();
  ~LogConsumer();

  static DWORD WINAPI ThreadProc(LPVOID param);
  static void ProcessEvent(EVENT_TRACE* event);
 private:
  static LogConsumer* current_;
};

#endif  // SAWBUCK_VIEWER_LOG_CONSUMER_H_
