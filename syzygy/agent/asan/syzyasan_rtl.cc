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

#include <windows.h>  // NOLINT

#include "base/at_exit.h"
#include "base/atomicops.h"
#include "base/command_line.h"
#include "base/logging.h"
#include "syzygy/agent/asan/asan_rtl_impl.h"
#include "syzygy/agent/asan/asan_runtime.h"
#include "syzygy/common/logging.h"

namespace {

using agent::asan::AsanRuntime;

// Our AtExit manager required by base.
base::AtExitManager* at_exit = NULL;

// The asan runtime manager.
AsanRuntime* asan_runtime = NULL;

void SetUpAtExitManager() {
  DCHECK(at_exit == NULL);
  at_exit = new base::AtExitManager();
  CHECK(at_exit != NULL);
}

void TearDownAtExitManager() {
  DCHECK(at_exit != NULL);
  delete at_exit;
  at_exit = NULL;
}

void SetUpAsanRuntime() {
  DCHECK(asan_runtime == NULL);
  asan_runtime = new AsanRuntime();
  CHECK(asan_runtime != NULL);
  std::wstring asan_flags_str;
  if (!AsanRuntime::GetAsanFlagsEnvVar(&asan_flags_str)) {
    LOG(ERROR) << "Error while trying to read Asan command line.";
  }
  asan_runtime->SetUp(asan_flags_str);

  agent::asan::SetUpRtl(asan_runtime);
}

void TearDownAsanRuntime() {
  DCHECK(asan_runtime != NULL);
  asan_runtime->TearDown();
  delete asan_runtime;
  asan_runtime = NULL;
}

}  // namespace

extern "C" {

BOOL WINAPI DllMain(HMODULE instance, DWORD reason, LPVOID reserved) {
  switch (reason) {
    case DLL_PROCESS_ATTACH:
      // Create the At-Exit manager.
      SetUpAtExitManager();

      // Disable logging. In the case of Chrome this is running in a sandboxed
      // process where logging to file doesn't help us any. In other cases the
      // log output will still go to console.
      CommandLine::Init(0, NULL);
      common::InitLoggingForDll(L"asan");

      SetUpAsanRuntime();

      break;

    case DLL_THREAD_ATTACH:
      // Nothing to do here.
      break;

    case DLL_THREAD_DETACH:
      // Nothing to do here.
      break;

    case DLL_PROCESS_DETACH:
      CommandLine::Reset();
      // This should be the last thing called in the agent DLL before it
      // gets unloaded. Everything should otherwise have been initialized
      // and we're now just cleaning it up again.
      agent::asan::TearDownRtl();
      TearDownAsanRuntime();
      break;

    default:
      NOTREACHED();
      break;
  }

  return TRUE;
}

}  // extern "C"
