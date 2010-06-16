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
#ifndef SAWBUCK_CALL_TRACE_CALL_TRACE_DEFS_H_
#define SAWBUCK_CALL_TRACE_CALL_TRACE_DEFS_H_

#include <windows.h>
#include <wmistr.h>
#include <evntrace.h>  // NOLINT - wmistr must precede envtrace.h

// ID for the call trace provider.
extern const GUID kCallTraceProvider;

// Class of trace provider events.
extern const GUID kCallTraceEventClass;

enum TraceEventType {
  TRACE_ENTER_EVENT = 10,
  TRACE_EXIT_EVENT,
  TRACE_PROCESS_ATTACH_EVENT,
  TRACE_PROCESS_DETACH_EVENT,
  TRACE_THREAD_ATTACH_EVENT,
  TRACE_THREAD_DETACH_EVENT,
  TRACE_MODULE_EVENT,
  TRACE_BATCH_ENTER,
};

// All traces are emitted at this trace level.
const UCHAR CALL_TRACE_LEVEL = TRACE_LEVEL_INFORMATION;

enum TraceEventFlags {
  // Trace function entry.
  TRACE_FLAG_ENTER          = 0x0001,
  // Trace function exit.
  TRACE_FLAG_EXIT           = 0x0002,
  // Captur stack traces on entry and exit.
  TRACE_FLAG_STACK_TRACES   = 0x0002,
  // Trace DLL load/unload events.
  TRACE_FLAG_LOAD_EVENTS    = 0x0008,
  // Trace DLL thread events.
  TRACE_FLAG_THREAD_EVENTS  = 0x0010,
  // Batch entry traces.
  TRACE_FLAG_BATCH_ENTER    = 0x0020,
};

// Max depth of stack trace captured on entry/exit.
const size_t kMaxTraceDepth = 32;

typedef const void *RetAddr;
typedef const void *FuncAddr;
typedef const void *ModuleAddr;
typedef DWORD ArgumentWord;
typedef DWORD RetValueWord;

// The structure traced on function entry or exit.
struct TraceEnterExitEventData {
  size_t depth;
  FuncAddr function;
  union {
    ArgumentWord args[4];
    RetValueWord retval;
  };
  size_t num_traces;
  RetAddr traces[kMaxTraceDepth];
};

// The structure traced for each loaded module
// when tracing is turned on.
struct TraceModuleData {
  ModuleAddr module_base_addr;
  size_t module_base_size;
  wchar_t module_name[256];
  wchar_t module_exe[MAX_PATH];
};

// The structure traced for batch entry traces.
struct TraceBatchEnterData {
  // The thread ID from which these traces originate. This can differ
  // from the logging thread ID when a process exits, and the exiting
  // thread flushes the trace buffers from its expired brethren.
  DWORD thread_id;

  // Number of function entries.
  size_t num_functions;

  // Back-to-back function addresses, one for each entry.
  FuncAddr functions[1];
};

#endif  // SAWBUCK_CALL_TRACE_CALL_TRACE_DEFS_H_
