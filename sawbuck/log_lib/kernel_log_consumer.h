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
#ifndef SAWBUCK_LOG_LIB_KERNEL_LOG_CONSUMER_H_
#define SAWBUCK_LOG_LIB_KERNEL_LOG_CONSUMER_H_

#include <string>
#include "base/time/time.h"
#include "base/win/event_trace_consumer.h"
#include "sawbuck/sym_util/types.h"

// Implemented by clients of EventTraceConsumer to get module load
// event notifications.
class KernelModuleEvents {
 public:
  typedef sym_util::ModuleInformation ModuleInformation;

  // Issued for all modules loaded before the trace session started.
  virtual void OnModuleIsLoaded(DWORD process_id,
                                const base::Time& time,
                                const ModuleInformation& module_info) = 0;
  // Issued for module unloads.
  virtual void OnModuleUnload(DWORD process_id,
                              const base::Time& time,
                              const ModuleInformation& module_info) = 0;
  // Issued for modules loaded after the trace session started.
  virtual void OnModuleLoad(DWORD process_id,
                            const base::Time& time,
                            const ModuleInformation& module_info) = 0;
};

class KernelPageFaultEvents {
 public:
  virtual void OnTransitionFault(DWORD process_id,
                                 DWORD thread_id,
                                 const base::Time& time,
                                 sym_util::Address address,
                                 sym_util::Address program_counter) = 0;
  virtual void OnDemandZeroFault(DWORD process_id,
                                 DWORD thread_id,
                                 const base::Time& time,
                                 sym_util::Address address,
                                 sym_util::Address program_counter) = 0;
  virtual void OnCopyOnWriteFault(DWORD process_id,
                                 DWORD thread_id,
                                 const base::Time& time,
                                 sym_util::Address address,
                                 sym_util::Address program_counter) = 0;
  virtual void OnGuardPageFault(DWORD process_id,
                                DWORD thread_id,
                                const base::Time& time,
                                sym_util::Address address,
                                sym_util::Address program_counter) = 0;
  virtual void OnHardFault(DWORD process_id,
                           DWORD thread_id,
                           const base::Time& time,
                           sym_util::Address address,
                           sym_util::Address program_counter) = 0;
  virtual void OnAccessViolationFault(DWORD process_id,
                                      DWORD thread_id,
                                      const base::Time& time,
                                      sym_util::Address address,
                                      sym_util::Address program_counter) = 0;

  // This event seems to be generated on the trailing edge of the
  // page fault handler. The process id and thread id in the event
  // header are bogus, and only the thread id in the event body allows
  // associating with the faulting process.
  virtual void OnHardPageFault(DWORD thread_id,
                               const base::Time& time,
                               const base::Time& initial_time,
                               sym_util::Offset offset,
                               sym_util::Address address,
                               sym_util::Address file_object,
                               sym_util::ByteCount byte_count) = 0;
};

class KernelProcessEvents {
 public:
  struct ProcessInfo {
    ULONG process_id;
    ULONG parent_id;
    ULONG session_id;
    struct {
      SID user_sid;
      DWORD sub_auths[SECURITY_MAX_SID_SIZE - 1];
    };
    std::string image_name;
    std::wstring command_line;

    bool operator == (const ProcessInfo& other) const;
  };
  // Issued for processes running before the trace session started.
  virtual void OnProcessIsRunning(const base::Time& time,
                                  const ProcessInfo& process_info) = 0;
  // Issued for process starting after the trace session started.
  virtual void OnProcessStarted(const base::Time& time,
                                const ProcessInfo& process_info) = 0;
  // Issued for processes ending.
  virtual void OnProcessEnded(const base::Time& time,
                              const ProcessInfo& process_info,
                              ULONG exit_status) = 0;
  // TODO(siggi): Data collection end event?
};

class KernelLogParser {
 public:
  KernelLogParser();
  ~KernelLogParser();

  bool infer_bitness_from_log() const { return infer_bitness_from_log_; }
  void set_infer_bitness_from_log(bool infer_bitness_from_log) {
    infer_bitness_from_log_ = infer_bitness_from_log;
  }

  bool is_64_bit_log() const { return is_64_bit_log_; }
  void set_is_64_bit_log(bool is_64_bit_log) {
    is_64_bit_log_ = is_64_bit_log;
  }

  void set_module_event_sink(KernelModuleEvents* module_event_sink) {
    module_event_sink_ = module_event_sink;
  }
  void set_page_fault_event_sink(KernelPageFaultEvents* page_fault_event_sink) {
    page_fault_event_sink_ = page_fault_event_sink;
  }
  void set_process_event_sink(KernelProcessEvents* process_event_sink) {
    process_event_sink_ = process_event_sink;
  }

  // Process an event, issue callbacks to event sinks as appropriate.
  // @param event the event to process.
  // @returns true iff the event resulted in a notification, false otherwise.
  bool ProcessOneEvent(EVENT_TRACE* event);

 private:
  bool ProcessImageLoadEvent(EVENT_TRACE* event);
  bool ProcessPageFaultEvent(EVENT_TRACE* event);
  bool ProcessProcessEvent(EVENT_TRACE* event);

  // Our module event sink.
  KernelModuleEvents* module_event_sink_;
  // Our page fault event sink.
  KernelPageFaultEvents* page_fault_event_sink_;
  // Our process event sink.
  KernelProcessEvents* process_event_sink_;

  // If true, we should infer the log bitness from the event stream,
  // e.g. from the pointer size field of the log file header event.
  bool infer_bitness_from_log_;

  // True iff (infer_bitness_from_log_ == true), and we've evidence that
  // the log we're consuming originates from a 64 bit machine.
  bool is_64_bit_log_;
};

class KernelLogConsumer
    : public base::win::EtwTraceConsumerBase<KernelLogConsumer>,
      public KernelLogParser {
 public:
  KernelLogConsumer();
  ~KernelLogConsumer();

  static DWORD WINAPI ThreadProc(void* param);
  static void ProcessEvent(EVENT_TRACE* event);

 private:
  static KernelLogConsumer* current_;
};

#endif  // SAWBUCK_LOG_LIB_KERNEL_LOG_CONSUMER_H_
