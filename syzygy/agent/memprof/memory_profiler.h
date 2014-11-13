// Copyright 2014 Google Inc. All Rights Reserved.
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
// Declares the memory profiler class, which is responsible for gathering
// memory statistics by hooking the Heap API. This class isn't much more than
// a thin wrapper for the FunctionCallLogger right now, but will likely grow
// to maintain and log other state.

#ifndef SYZYGY_AGENT_MEMPROF_MEMORY_PROFILER_H_
#define SYZYGY_AGENT_MEMPROF_MEMORY_PROFILER_H_

#include "syzygy/agent/common/agent.h"
#include "syzygy/agent/common/dll_notifications.h"
#include "syzygy/agent/memprof/function_call_logger.h"
#include "syzygy/agent/memprof/parameters.h"
#include "syzygy/common/logging.h"
#include "syzygy/trace/client/rpc_session.h"

namespace agent {
namespace memprof {

class MemoryProfiler {
 public:
  MemoryProfiler();

  // Initializes this memory profiler.
  // @returns true for success, false otherwise.
  bool Init();

  // @returns the active function call logger.
  FunctionCallLogger& function_call_logger() {
    return function_call_logger_;
  }

 protected:
  // Propagates configured parameters to sub-components.
  void PropagateParameters();

  // Flushes the active segment and gets a new one. Returns true if all
  // went well, false otherwise.
  bool FlushSegment();

  // Logs @p module and all other modules in the process, then flushes
  // the current trace buffer.
  void LogAllModules(HMODULE module);

  // Logs @p module.
  void LogModule(HMODULE module);

  // Sink for DLL load/unload event notifications.
  void OnDllEvent(agent::common::DllNotificationWatcher::EventType type,
                  HMODULE module,
                  size_t module_size,
                  const base::StringPiece16& dll_path,
                  const base::StringPiece16& dll_base_name);

  // Synchronizes access to various global state.
  base::Lock lock_;

  // The RPC session we're logging to/through.
  trace::client::RpcSession session_;

  // The active trace file segment where events are written. This object
  // guarantees its own thread safety.
  // TODO(chrisha): Make this live in thread-local state, so each thread has
  //     its own segment. Right now they all contend for one.
  trace::client::TraceFileSegment segment_;

  // The function call logger that we use for detailed function call
  // events.
  FunctionCallLogger function_call_logger_;

  // The parameters that we use. These are parsed from the environment.
  Parameters parameters_;

  // To keep track of modules added after initialization.
  agent::common::DllNotificationWatcher dll_watcher_;

  // Contains the set of modules we've seen and logged.
  typedef base::hash_set<HMODULE> ModuleSet;
  ModuleSet logged_modules_;  // Under lock_.

 private:
  DISALLOW_COPY_AND_ASSIGN(MemoryProfiler);
};

}  // namespace memprof
}  // namespace agent

#endif  // SYZYGY_AGENT_MEMPROF_MEMORY_PROFILER_H_
