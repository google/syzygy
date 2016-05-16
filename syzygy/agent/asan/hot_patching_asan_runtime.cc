// Copyright 2015 Google Inc. All Rights Reserved.
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

#include "syzygy/agent/asan/hot_patching_asan_runtime.h"

#include "base/command_line.h"
#include "base/environment.h"
#include "base/strings/utf_string_conversions.h"
#include "syzygy/agent/asan/logger.h"
#include "syzygy/trace/client/client_utils.h"
#include "syzygy/trace/protocol/call_trace_defs.h"

namespace agent {
namespace asan {

HotPatchingAsanRuntime::HotPatchingAsanRuntime() { }

HotPatchingAsanRuntime::~HotPatchingAsanRuntime() { }

bool HotPatchingAsanRuntime::HotPatch(HINSTANCE instance) {
  logger_->Write("HPSyzyAsan: Started hot patching. Module: " +
      std::to_string(reinterpret_cast<int>(instance)) +
      " PID: " +
      std::to_string(GetCurrentProcessId()));

  if (hot_patched_modules_.count(instance)) {
    logger_->Write("HPSyzyAsan - Already tried to hot patch, exiting.");
    return true;
  }
  hot_patched_modules_.insert(instance);

  // TODO(cseri): Do the hot patching.
  logger_->Write("HPSyzyAsan: Hot patching not yet implemented.");

  return true;
}

void HotPatchingAsanRuntime::SetUp() {
  SetUpLogger();

  logger_->Write("HPSyzyAsan: Runtime loaded.");
}

void HotPatchingAsanRuntime::SetUpLogger() {
  // Setup variables we're going to use.
  std::unique_ptr<base::Environment> env(base::Environment::Create());
  std::unique_ptr<AsanLogger> client(new AsanLogger);
  CHECK(env.get() != NULL);
  CHECK(client.get() != NULL);

  // Initialize the client.
  client->set_instance_id(
      base::UTF8ToWide(trace::client::GetInstanceIdForThisModule()));
  client->Init();

  // Register the client singleton instance.
  logger_.reset(client.release());
}

void WINAPI HotPatchingAsanRuntime::DllMainEntryHook(
    agent::EntryFrame* entry_frame,
    FuncAddr function) {
  HINSTANCE instance = reinterpret_cast<HINSTANCE>(entry_frame->args[0]);
  DWORD reason = entry_frame->args[1];

  switch (reason) {
    case DLL_PROCESS_ATTACH: {
      HotPatchingAsanRuntime::GetInstance()->HotPatch(instance);
      break;
    }

    case DLL_THREAD_ATTACH:
      // Nothing to do here.
      break;

    case DLL_THREAD_DETACH:
      // Nothing to do here.
      break;

    case DLL_PROCESS_DETACH:
      // Nothing to do here.
      break;

    default:
      NOTREACHED();
      break;
  }
}

}  // namespace asan
}  // namespace agent

extern "C" {

agent::asan::HotPatchingAsanRuntime* hp_asan_GetActiveHotPatchingAsanRuntime() {
  return agent::asan::HotPatchingAsanRuntime::GetInstance();
}

}
