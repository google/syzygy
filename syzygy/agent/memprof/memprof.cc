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

#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/logging.h"
#include "syzygy/agent/memprof/memory_profiler.h"

namespace {

// Our AtExit manager required by base.
base::AtExitManager* at_exit = nullptr;

void SetUpAtExitManager() {
  DCHECK(at_exit == nullptr);
  at_exit = new base::AtExitManager();
  CHECK(at_exit != nullptr);
}

}  // namespace

namespace agent {
namespace memprof {

std::unique_ptr<MemoryProfiler> memory_profiler;

}  // namespace memprof
}  // namespace agent

extern "C" {

BOOL WINAPI DllMain(HMODULE instance, DWORD reason, LPVOID reserved) {
  agent::common::InitializeCrt();

  switch (reason) {
    case DLL_PROCESS_ATTACH:
      // Create the At-Exit manager.
      SetUpAtExitManager();

      // Disable logging. In the case of Chrome this is running in a sandboxed
      // process where logging to file doesn't help us any. In other cases the
      // log output will still go to console.
      base::CommandLine::Init(0, NULL);
      common::InitLoggingForDll(L"memprof");

      agent::memprof::memory_profiler.reset(
          new agent::memprof::MemoryProfiler());
      agent::memprof::memory_profiler->Init();
      break;

    case DLL_THREAD_ATTACH:
      // Nothing to do here.
      break;

    case DLL_THREAD_DETACH:
      // Nothing to do here.
      break;

    case DLL_PROCESS_DETACH:
      base::CommandLine::Reset();
      agent::memprof::memory_profiler.reset(nullptr);
      break;

    default:
      NOTREACHED();
      break;
  }

  return TRUE;
}

}  // extern "C"
