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

#include "base/threading/thread_local.h"
#include "syzygy/agent/common/agent.h"
#include "syzygy/agent/common/dll_notifications.h"
#include "syzygy/agent/common/thread_state.h"
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

  // Forward declaration.
  class ThreadState;

  // @returns the thread state for the current thread, with an initialized
  //     call trace segment. Allocates thread state if this is not already
  //     done.
  ThreadState* GetOrAllocateThreadState();

  // @returns the thread state, returning nullptr if none has yet been
  //     allocated.
  ThreadState* GetThreadState();

  // @returns the current parameters.
  const Parameters& parameters() const { return parameters_; }

 protected:
  friend class ThreadState;

  // Propagates configured parameters to sub-components.
  void PropagateParameters();

  // Returns the thread state for the current thread, but doesn't initialize
  // a call trace segment.
  ThreadState* GetOrAllocateThreadStateImpl();

  // Logs all modules in the process, then flushes the current trace segment.
  // Logs using the current thread's segment.
  void LogAllModules();

  // Logs @p module, using the current thread's segment.
  void LogModule(HMODULE module);

  // Sink for DLL load/unload event notifications.
  void OnDllEvent(agent::common::DllNotificationWatcher::EventType type,
                  HMODULE module,
                  size_t module_size,
                  const base::StringPiece16& dll_path,
                  const base::StringPiece16& dll_base_name);

  // Helper class for managing ThreadState lifetimes.
  agent::common::ThreadStateManager thread_state_manager_;

  // Synchronizes access to various global state.
  base::Lock lock_;

  // The RPC session we're logging to/through.
  trace::client::RpcSession session_;

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

  // This points to our per-thread state.
  mutable base::ThreadLocalPointer<ThreadState> tls_;

 private:
  DISALLOW_COPY_AND_ASSIGN(MemoryProfiler);
};

// Maintains thread specific memory profiler state, and provides convenient
// logging methods.
class MemoryProfiler::ThreadState : public agent::common::ThreadStateBase {
 public:
  // Initializes this thread state.
  // @param parent The memory profiler owning this thread state.
  explicit ThreadState(MemoryProfiler* parent);

  // Flushes the active segment and gets a new one.
  // @returns true if all went well, false otherwise.
  bool FlushSegment();

  // @returns the active trace file segment.
  trace::client::TraceFileSegment* segment() {
    return &segment_;
  }

 protected:
  friend class MemoryProfiler;

  // Our parent memory profiler.
  MemoryProfiler* parent_;

  // The active trace file segment where events are written.
  trace::client::TraceFileSegment segment_;

 private:
  DISALLOW_COPY_AND_ASSIGN(ThreadState);
};

}  // namespace memprof
}  // namespace agent

#endif  // SYZYGY_AGENT_MEMPROF_MEMORY_PROFILER_H_
