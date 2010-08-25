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
// A class used to process ETW logs and track event timings.

#ifndef SAWBUCK_LOG_TIMER_LOG_TIMER_H_
#define SAWBUCK_LOG_TIMER_LOG_TIMER_H_

#include <windows.h>
#include <wmistr.h>
#include <evntrace.h>
#include <tdh.h>
#include <cguid.h>

#include <string>
#include <vector>
#include "base/scoped_ptr.h"
#include "base/time.h"

class LogTimer {
 public:
  struct Event {
    std::wstring provider;
    std::wstring task;
    std::wstring opcode;
    GUID guid;
    base::Time time;

    bool operator==(const Event& e) {
      // Note that we purposely don't compare time.
      return provider.compare(e.provider) == 0 &&
          task.compare(e.task) == 0 &&
          opcode.compare(e.opcode) == 0 &&
          guid == e.guid;
    }
  };

  LogTimer();
  ~LogTimer();

  void AddEvent(Event event);
  void ProcessLog(const std::wstring& logfile_path);

 private:
  static void WINAPI OnEventRecord(EVENT_RECORD* event_record);
  void ProcessEvent(EVENT_RECORD* event_record);
  DWORD GetEventRecordInfo(EVENT_RECORD* event_record,
                           scoped_ptr<TRACE_EVENT_INFO>* event_info,
                           DWORD* event_info_len);
  void GetEventFromInfo(const TRACE_EVENT_INFO* event_info,
                        DWORD event_info_len, Event* event);

  // Our instance so that we can route the static call back to the class.
  static LogTimer* instance_;

  // The sequence of events to search for in the log file.
  std::vector<Event> events_;

  // Helper variables used while processing events.
  int event_index_;
  base::Time start_time_;
};

#endif  // SAWBUCK_LOG_TIMER_LOG_TIMER_H_
