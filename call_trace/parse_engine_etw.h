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
//
// Call trace event parsing classes.

#ifndef SYZYGY_CALL_TRACE_PARSE_ENGINE_ETW_H_
#define SYZYGY_CALL_TRACE_PARSE_ENGINE_ETW_H_

#include "base/time.h"
#include "base/file_path.h"
#include "base/win/event_trace_consumer.h"
#include "sawbuck/log_lib/kernel_log_consumer.h"
#include "syzygy/call_trace/call_trace_defs.h"
#include "syzygy/call_trace/parse_engine.h"

namespace call_trace {
namespace parser {

// This class implements a call-trace Parser for ETW-based call-trace
// log files.
//
// @note No more than one instance of this class may exist at any given
//     time (i.e., it must be a singleton)due to the way the Windows ETW
//     API is structured. This is enforced in debug builds.
class ParseEngineEtw
    : public ParseEngine,
      public base::win::EtwTraceConsumerBase<ParseEngineEtw>,
      public KernelModuleEvents,
      public KernelProcessEvents {
 public:
  typedef base::win::EtwTraceConsumerBase<ParseEngineEtw> EtwConsumerBase;

  ParseEngineEtw();
  ~ParseEngineEtw();

  // Returns true if the file given by @p trace_file_path is parseable by this
  // parse engine.
  virtual bool IsRecognizedTraceFile(const FilePath& trace_file_path) OVERRIDE;

  // Opens the trace log given by @p trace_file_path and prepares it for
  // consumption. It is an error to call this method given a file that
  // will not be recognized by the parse engine.
  virtual bool OpenTraceFile(const FilePath& trace_file_path) OVERRIDE;

  // Consume all events across all currently open trace files and for each
  // event call the dispatcher to notify the event handler.
  virtual bool ConsumeAllEvents() OVERRIDE;

  // Close all currently open trace files.
  virtual bool CloseAllTraceFiles() OVERRIDE;

 protected:
  // @name KernelModuleEvents implementation.
  // @{
  virtual void OnModuleIsLoaded(DWORD process_id,
                                const base::Time& time,
                                const ModuleInformation& module_info) OVERRIDE;
  virtual void OnModuleUnload(DWORD process_id,
                              const base::Time& time,
                              const ModuleInformation& module_info) OVERRIDE;
  virtual void OnModuleLoad(DWORD process_id,
                            const base::Time& time,
                            const ModuleInformation& module_info) OVERRIDE;
  // @}

  // @name KernelProcessEvents implementation.
  // @{
  virtual void OnProcessIsRunning(const base::Time& time,
                                  const ProcessInfo& process_info) OVERRIDE;
  virtual void OnProcessStarted(const base::Time& time,
                                const ProcessInfo& process_info) OVERRIDE;
  virtual void OnProcessEnded(const base::Time& time,
                              const ProcessInfo& process_info,
                              ULONG exit_status) OVERRIDE;
  // @}

  // @name Static hooks called from EtwTraceConsumerBase.
  // @{
  friend class EtwConsumerBase;
  static void ProcessEvent(PEVENT_TRACE event);
  static bool ProcessBuffer(PEVENT_TRACE_LOGFILE buffer);

  // A static pointer to the current ETW parse engine instance. The static hooks
  // will be directed to this instance.
  static ParseEngineEtw* parse_engine_etw_;
  // @}

  // Parser to grok and dispatch kernel notifications back into this ETW parser
  // so that they can be translated into the corresonding call trace events, as
  // appropriate.
  KernelLogParser kernel_log_parser_;

  // The time of the last processed event.
  base::Time last_event_time_;

 private:
  DISALLOW_COPY_AND_ASSIGN(ParseEngineEtw);
};

}  // namespace call_trace::parser
}  // namespace call_trace

#endif  // SYZYGY_CALL_TRACE_PARSE_ENGINE_ETW_H_
