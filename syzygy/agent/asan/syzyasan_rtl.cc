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

#include <windows.h>

#include "base/at_exit.h"
#include "base/atomicops.h"
#include "base/command_line.h"
#include "base/logging.h"
#include "syzygy/agent/asan/rtl_impl.h"
#include "syzygy/agent/asan/runtime.h"
#include "syzygy/agent/asan/runtime_util.h"
#include "syzygy/agent/common/agent.h"
#include "syzygy/common/logging.h"

namespace {

// Our AtExit manager required by base.
base::AtExitManager* at_exit = nullptr;

// The asan runtime manager.
agent::asan::AsanRuntime* asan_runtime = nullptr;

void SetUpAtExitManager() {
  DCHECK_EQ(static_cast<base::AtExitManager*>(nullptr), at_exit);
  at_exit = new base::AtExitManager();
  CHECK_NE(static_cast<base::AtExitManager*>(nullptr), at_exit);
}

void TearDownAtExitManager() {
  DCHECK_NE(static_cast<base::AtExitManager*>(nullptr), at_exit);
  delete at_exit;
  at_exit = nullptr;
}

}  // namespace

extern "C" {

BOOL WINAPI DllMain(HMODULE instance, DWORD reason, LPVOID reserved) {
  agent::common::InitializeCrt();

  switch (reason) {
    case DLL_PROCESS_ATTACH: {
      // Create the At-Exit manager.
      SetUpAtExitManager();

      // Disable logging. In the case of Chrome this is running in a sandboxed
      // process where logging to file doesn't help us any. In other cases the
      // log output will still go to console.
      base::CommandLine::Init(0, NULL);
      common::InitLoggingForDll(L"asan");

      // This runtime has no ability to disable instrumentation so can't
      // tolerate an initialization failure.
      CHECK(SetUpAsanRuntime(&asan_runtime));
      break;
    }

    case DLL_THREAD_ATTACH: {
      agent::asan::AsanRuntime* runtime = agent::asan::AsanRuntime::runtime();
      DCHECK_NE(static_cast<agent::asan::AsanRuntime*>(nullptr), runtime);
      runtime->AddThreadId(::GetCurrentThreadId());
      break;
    }

    case DLL_THREAD_DETACH:
      // Nothing to do here.
      break;

    case DLL_PROCESS_DETACH: {
      base::CommandLine::Reset();
      // This should be the last thing called in the agent DLL before it
      // gets unloaded. Everything should otherwise have been initialized
      // and we're now just cleaning it up again.
      TearDownAsanRuntime(&asan_runtime);
      TearDownAtExitManager();
      break;
    }

    default:
      NOTREACHED();
      break;
  }

  return TRUE;
}

}  // extern "C"
