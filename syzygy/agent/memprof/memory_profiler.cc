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

// Gives us a pointer to the load address of our image.
extern "C" IMAGE_DOS_HEADER __ImageBase;

namespace agent {
namespace memprof {

MemoryProfiler::MemoryProfiler()
    : function_call_logger_(&session_, &segment_) {
  SetDefaultParameters(&parameters_);
}

bool MemoryProfiler::Init() {
  if (!ParseParametersFromEnv(&parameters_))
    return false;
  PropagateParameters();
  if (!trace::client::InitializeRpcSession(&session_, &segment_))
    return false;

  // Setup the DLL watcher. This will be notified of module load and unload
  // events as they occur.
  dll_watcher_.Init(base::Bind(&MemoryProfiler::OnDllEvent,
                               base::Unretained(this)));

  // Log all modules that are already loaded when we are. Further modules
  // will be logged as they load and unload via the DllNotification
  // mechanism.
  HMODULE module = reinterpret_cast<HMODULE>(&__ImageBase);
  LogAllModules(module);

  return true;
}

void MemoryProfiler::PropagateParameters() {
  function_call_logger_.set_stack_trace_tracking(
      parameters_.stack_trace_tracking);
}

bool MemoryProfiler::FlushSegment() {
  return session_.ExchangeBuffer(&segment_);
}

void MemoryProfiler::LogAllModules(HMODULE module) {
  agent::common::ModuleVector modules;
  agent::common::GetProcessModules(&modules);

  // Our module should be in the process modules.
  DCHECK(std::find(modules.begin(), modules.end(), module) != modules.end());

  for (size_t i = 0; i < modules.size(); ++i) {
    DCHECK(modules[i] != NULL);
    LogModule(modules[i]);
  }

  // We need to flush module events right away, so that the module is
  // defined in the trace file before events using that module start to
  // occur.
  FlushSegment();
}

void MemoryProfiler::LogModule(HMODULE module) {
  {
    base::AutoLock lock(lock_);
    bool inserted = logged_modules_.insert(module).second;
    if (!inserted)
      return;
  }

  agent::common::LogModule(module, &session_, &segment_);
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

}  // namespace memprof
}  // namespace agent
