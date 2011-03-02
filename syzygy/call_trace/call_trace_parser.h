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
// Call trace event parsing classes.

#ifndef SYZYGY_CALL_TRACE_CALL_TRACE_PARSER_H_
#define SYZYGY_CALL_TRACE_CALL_TRACE_PARSER_H_

#include "base/time.h"
#include "syzygy/call_trace/call_trace_defs.h"

// Implemented by clients of CallTraceParser to
// receive trace event notifications.
class CallTraceEvents {
 public:
  // Issued for entry traces.
  virtual void OnTraceEntry(base::Time time,
                            DWORD process_id,
                            DWORD thread_id,
                            const TraceEnterExitEventData* data) = 0;

  // Issued for exit traces.
  virtual void OnTraceExit(base::Time time,
                          DWORD process_id,
                          DWORD thread_id,
                          const TraceEnterExitEventData* data) = 0;

  // Issued for batch entry traces.
  virtual void OnTraceBatchEnter(base::Time time,
                                 DWORD process_id,
                                 DWORD thread_id,
                                 const TraceBatchEnterData* data) = 0;
};

class CallTraceParser {
 public:
  CallTraceParser();
  ~CallTraceParser();

  void set_call_trace_event_sink(CallTraceEvents* call_trace_events) {
    call_trace_events_ = call_trace_events;
  }

  // Process an event, issue callbacks to event sinks as appropriate.
  // @param event the event to process.
  // @returns true iff the event resulted in a notification, false otherwise.
  bool ProcessOneEvent(EVENT_TRACE* event);

 private:
  bool ProcessEntryExitEvent(EVENT_TRACE* event, TraceEventType type);
  bool ProcessBatchEnterEvent(EVENT_TRACE* event);

  CallTraceEvents* call_trace_events_;
};

#endif  // SYZYGY_CALL_TRACE_CALL_TRACE_PARSER_H_
