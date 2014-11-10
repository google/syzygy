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
#include "syzygy/agent/memprof/function_call_logger.h"
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
  // The RPC session we're logging to/through.
  trace::client::RpcSession session_;

  // The active trace file segment where events are written. This object
  // guarantees its own thread safety.
  trace::client::TraceFileSegment segment_;

  // The function call logger that we use for detailed function call
  // events.
  FunctionCallLogger function_call_logger_;

 private:
  DISALLOW_COPY_AND_ASSIGN(MemoryProfiler);
};

}  // namespace memprof
}  // namespace agent

#endif  // SYZYGY_AGENT_MEMPROF_MEMORY_PROFILER_H_
