// Copyright 2012 Google Inc. All Rights Reserved.
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

#ifndef SYZYGY_TRACE_PARSE_PARSE_ENGINE_H_
#define SYZYGY_TRACE_PARSE_PARSE_ENGINE_H_

#include <map>
#include <set>
#include <string>

#include "syzygy/pe/pe_file.h"
#include "syzygy/trace/parse/parser.h"

namespace trace {
namespace parser {

// This base class defines and implements the common event dispatching and
// module tracking for all supported parse engines. It also declares the
// abstract interface a parse engine exposes to its clients.
class ParseEngine {
 public:
  virtual ~ParseEngine();

  // Returns a short human readable name by which this parse engine can be
  // recognized.
  const char* name() const;

  // Returns true if an error occurred while parsing the trace files.
  bool error_occurred() const;

  // Set or reset the error flag.
  void set_error_occurred(bool value);

  // Registers an event handler with this trace-file parse engine.
  void set_event_handler(ParseEventHandler* event_handler);

  // Returns true if the file given by @p trace_file_path is parseable by this
  // parse engine.
  virtual bool IsRecognizedTraceFile(const base::FilePath& trace_file_path) = 0;

  // Opens the trace log given by @p trace_file_path and prepares it for
  // consumption. It is an error to call this method given a file that
  // will not be recognized by the parse engine.
  //
  // @returns true on success.
  virtual bool OpenTraceFile(const base::FilePath& trace_file_path) = 0;

  // Consume all events across all currently open trace files and for each
  // event call the dispatcher to notify the event handler.
  //
  // @returns true on success.
  virtual bool ConsumeAllEvents() = 0;

  // Close all currently open trace files.
  //
  // @returns true on success.
  virtual bool CloseAllTraceFiles() = 0;

  // Given an address and a process id, returns the module in memory at that
  // address.
  //
  // @param process_id The id of the process to look up.
  // @param addr An address in the memory space of the process.
  //
  // @returns NULL if no such module exists; otherwise, a pointer to the module.
  const ModuleInformation* GetModuleInformation(uint32 process_id,
                                                AbsoluteAddress64 addr) const;

 protected:
  // Used to store module information about each observed process.
  typedef std::map<uint32, ModuleSpace> ProcessMap;

  // Initialize the base ParseEngine.
  //
  // @param name The name of this parse engine. This will be logged.
  // @param fail_on_module_conflict A flag denoting whether to abort on
  //     conflicting module information. In ETW traces, for example, we
  //     sometimes get conflicting module information if background
  //     processes are actively coming and going. In RPC traces, we should
  //     never get conflicting module information.
  ParseEngine(const char* const name, bool fail_on_module_conflict);

  // Registers a module in the address space of the process denoted by
  // @p process_id.
  //
  // @param process_id The process in which the module has been loaded.
  // @param module_info The meta-data describing the loaded module.
  //
  // @returns true on success.
  bool AddModuleInformation(DWORD process_id,
                            const ModuleInformation& module_info);

  // Unregisters a module from the address space of the process denoted by
  // @p process_id.
  //
  // @param process_id The process in which the module has been unloaded.
  // @param module_info The meta-data describing the loaded module.
  //
  // @returns true on success.
  bool RemoveModuleInformation(DWORD process_id,
                               const ModuleInformation& module_info);

  // Unregisters a process (and all of the modules it contains) from the
  // process map.
  //
  // @param process_id The process which has been unloaded.
  // @returns true on success.
  bool RemoveProcessInformation(DWORD process_id);

  // The main entry point by which trace events are dispatched to the
  // event handler.
  //
  // @param event The event to dispatch.
  //
  // @returns true if the event was recognized and handled in some way; false
  //     if the event must be handled elsewhere. If an error occurs during
  //     the handling of the event, the error_occurred_ flag will be set to
  //     true.
  bool DispatchEvent(EVENT_TRACE* event);

  // Parses and dispatches function entry and exit events. Called from
  // DispatchEvent().
  //
  // @param event The event to dispatch.
  // @param type TRACE_ENTER_EVENT or TRACE_EXIT_EVENT
  //
  // @returns true if the event was successfully dispatched, false otherwise.
  //     If an error occurred, the error_occurred_ flag will be set to
  //     true.
  bool DispatchEntryExitEvent(EVENT_TRACE* event, TraceEventType type);

  // Parses and dispatches batch function entry events. Called from
  // DispatchEvent().
  //
  // @param event The event to dispatch.
  //
  // @returns true if the event was successfully dispatched, false otherwise.
  //     If an error occurred, the error_occurred_ flag will be set to
  //     true.
  bool DispatchBatchEnterEvent(EVENT_TRACE* event);

  // Parses and dispatches a process ended event. Called from DispatchEvent().
  //
  // @param event The event to dispatch.
  //
  // @returns true if the event was successfully dispatched, false otherwise.
  //     If an error occurred the error_occurred_ flag will be set to true.
  bool DispatchProcessEndedEvent(EVENT_TRACE* event);

  // Parses and dispatches invocation batch function events. Called from
  // DispatchEvent().
  //
  // @param event The event to dispatch.
  //
  // @returns true if the event was successfully dispatched, false otherwise.
  //     If an error occurred, the error_occurred_ flag will be set to
  //     true.
  bool DispatchBatchInvocationEvent(EVENT_TRACE* event);

  // Parses and dispatches dynamic library events (i.e., process and thread
  // attach/detach events). Called from DispatchEvent().
  //
  // @param event The event to dispatch.
  // @param type One of TRACE_PROCESS_ATTACH_EVENT, TRACE_PROCESS_DETACH_EVENT,
  //     TRACE_THREAD_ATTACH_EVENT, or TRACE_THREAD_DETACH_EVENT.
  //
  // @returns true if the event was successfully dispatched, false otherwise.
  //     If an error occurred, the error_occurred_ flag will be set to
  //     true.
  bool DispatchModuleEvent(EVENT_TRACE* event, TraceEventType type);

  // Parses and dispatches thread name events. Called from DispatchEvent().
  //
  // @param event The event to dispatch.
  //
  // @returns true if the event was successfully dispatched, false otherwise.
  //     If an error occurred, the error_occurred_ flag will be set to
  //     true.
  bool DispatchThreadNameEvent(EVENT_TRACE* event);

  // Parses and dispatches indexed frequency events.
  //
  // @param event the event to dispatch.
  //
  // @returns true if the event was successfully dispatched, false otherwise.
  //     Does not explicitly set error occurred.
  bool DispatchIndexedFrequencyEvent(EVENT_TRACE* event);

  // Parses and dispatches dynamic module events.
  //
  // @param event the event to dispatch.
  //
  // @returns true if the event was successfully dispatched, false otherwise.
  //     Does not explicitly set error occurred.
  bool DispatchDynamicSymbolEvent(EVENT_TRACE* event);

  // Parses and dispatches sampling profiler data.
  //
  // @param event the event to dispatch.
  //
  // @returns true if the event was successfully dispatched, false otherwise.
  //     Does not explicitly set error occurred.
  bool DispatchSampleDataEvent(EVENT_TRACE* event);

  // The name by which this parse engine is known.
  std::string name_;

  // The event handler to be notified on trace events.
  ParseEventHandler* event_handler_;

  // For each process, we store its point of view of the world.
  ProcessMap processes_;

  // Flag indicating whether or not an error has occurred in parsing the trace
  // event stream.
  bool error_occurred_;

  // A flag denoting whether to abort on conflicting module information. In
  // ETW traces, we sometimes get conflicting module information if background
  // processes are actively coming a going. In RPC traces, we should never get
  // conflicting module information.
  bool fail_on_module_conflict_;

 private:
  DISALLOW_COPY_AND_ASSIGN(ParseEngine);
};

}  // namespace parser
}  // namespace trace

#endif  // SYZYGY_TRACE_PARSE_PARSE_ENGINE_H_
