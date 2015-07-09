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

#include "syzygy/agent/memprof/memory_profiler.h"

#include "base/bind.h"
#include "syzygy/agent/common/process_utils.h"
#include "syzygy/common/process_utils.h"

namespace agent {
namespace memprof {

MemoryProfiler::MemoryProfiler()
    : function_call_logger_(&session_) {
  SetDefaultParameters(&parameters_);
}

bool MemoryProfiler::Init() {
  // We don't care if parameter parsing fails at runtime; such parameters will
  // simply be ignored.
  ParseParametersFromEnv(&parameters_);
  PropagateParameters();
  ThreadState* state = GetOrAllocateThreadState();
  if (!trace::client::InitializeRpcSession(
          &session_, state->segment())) {
    return false;
  }

  // Setup the DLL watcher. This will be notified of module load and unload
  // events as they occur.
  dll_watcher_.Init(base::Bind(&MemoryProfiler::OnDllEvent,
                               base::Unretained(this)));

  // Log all modules that are already loaded when we are. Further modules
  // will be logged as they load and unload via the DllNotification
  // mechanism.
  LogAllModules();

  return true;
}

MemoryProfiler::ThreadState* MemoryProfiler::GetOrAllocateThreadState() {
  ThreadState* data = GetOrAllocateThreadStateImpl();
  if (!data->segment()->write_ptr && session_.IsTracing())
    session_.AllocateBuffer(data->segment());

  return data;
}

MemoryProfiler::ThreadState* MemoryProfiler::GetThreadState() {
  return tls_.Get();
}

void MemoryProfiler::PropagateParameters() {
  function_call_logger_.set_stack_trace_tracking(
      parameters_.stack_trace_tracking);
  function_call_logger_.set_serialize_timestamps(
      parameters_.serialize_timestamps);
}

MemoryProfiler::ThreadState* MemoryProfiler::GetOrAllocateThreadStateImpl() {
  ThreadState *data = tls_.Get();
  if (data != NULL)
    return data;

  data = new ThreadState(this);
  if (data == NULL) {
    LOG(ERROR) << "Unable to allocate per-thread data";
    return NULL;
  }

  thread_state_manager_.Register(data);
  tls_.Set(data);

  return data;
}

void MemoryProfiler::LogAllModules() {
  ::common::ModuleVector modules;
  ::common::GetCurrentProcessModules(&modules);

  for (size_t i = 0; i < modules.size(); ++i) {
    DCHECK(modules[i] != NULL);
    LogModule(modules[i]);
  }

  // We need to flush module events right away, so that the module is
  // defined in the trace file before events using that module start to
  // occur.
  GetOrAllocateThreadState()->FlushSegment();
}

void MemoryProfiler::LogModule(HMODULE module) {
  {
    base::AutoLock lock(lock_);
    bool inserted = logged_modules_.insert(module).second;
    if (!inserted)
      return;
  }

  ThreadState* state = GetOrAllocateThreadState();
  agent::common::LogModule(module, &session_, state->segment());
}

void MemoryProfiler::OnDllEvent(
    agent::common::DllNotificationWatcher::EventType type,
    HMODULE module,
    size_t module_size,
    const base::StringPiece16& dll_path,
    const base::StringPiece16& dll_base_name) {
  switch (type) {
    case agent::common::DllNotificationWatcher::kDllLoaded: {
      LogModule(module);
      break;
    }

    case agent::common::DllNotificationWatcher::kDllUnloaded: {
      base::AutoLock lock(lock_);
      logged_modules_.erase(module);
      break;
    }
  }

  return;
}

MemoryProfiler::ThreadState::ThreadState(MemoryProfiler* parent)
    : parent_(parent) {
  DCHECK_NE(static_cast<MemoryProfiler*>(nullptr), parent);
}

bool MemoryProfiler::ThreadState::FlushSegment() {
  if (!parent_->session_.ExchangeBuffer(&segment_))
    return false;
  return true;
}

}  // namespace memprof
}  // namespace agent
