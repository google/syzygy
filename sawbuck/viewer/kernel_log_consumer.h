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
// Kernel log consumer declaration.
#ifndef SAWBUCK_VIEWER_KERNEL_LOG_CONSUMER_H_
#define SAWBUCK_VIEWER_KERNEL_LOG_CONSUMER_H_

#include "base/basictypes.h"
#include "base/event_trace_consumer_win.h"
#include "base/time.h"
#include "sawbuck/sym_util/types.h"
#include <string>
#include <windows.h>

// Implemented by clients of EventTraceConsumer to get module load
// event notifications.
class KernelModuleEvents {
 public:
  typedef sym_util::ModuleInformation ModuleInformation;

  virtual void OnModuleIsLoaded(DWORD process_id,
                                const base::Time& time,
                                const ModuleInformation& module_info) = 0;
  virtual void OnModuleUnload(DWORD process_id,
                              const base::Time& time,
                              const ModuleInformation& module_info) = 0;
  virtual void OnModuleLoad(DWORD process_id,
                            const base::Time& time,
                            const ModuleInformation& module_info) = 0;
};

class KernelLogParser {
 public:
  KernelLogParser();
  ~KernelLogParser();

  void set_is_64_bit_log(bool is_64_bit_log) {
    is_64_bit_log_ = is_64_bit_log;
  }

  void set_module_event_sink(KernelModuleEvents* module_event_sink) {
    module_event_sink_ = module_event_sink;
  }

  // Process an event, issue callbacks to event sinks as appropriate.
  // @param event the event to process.
  // @returns true iff the event resulted in a notification, false otherwise.
  bool ProcessOneEvent(EVENT_TRACE* event);

 private:
  // Our module event sink.
  KernelModuleEvents* module_event_sink_;

  // True iff we've evidence that the log we're consuming
  // originates from a 64 bit machine.
  bool is_64_bit_log_;
};

class KernelLogConsumer
    : public EtwTraceConsumerBase<KernelLogConsumer>,
      public KernelLogParser {
 public:
  KernelLogConsumer();
  ~KernelLogConsumer();

  static DWORD WINAPI ThreadProc(void* param);
  static void ProcessEvent(EVENT_TRACE* event);

 private:
  static KernelLogConsumer* current_;
};

#endif  // SAWBUCK_VIEWER_KERNEL_LOG_CONSUMER_H_
