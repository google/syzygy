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
#include "base/bind.h"
#include "base/command_line.h"
#include "base/logging.h"
#include "base/synchronization/lock.h"
#include "syzygy/agent/asan/iat_patcher.h"
#include "syzygy/agent/asan/memory_interceptors.h"
#include "syzygy/agent/asan/rtl_impl.h"
#include "syzygy/agent/asan/runtime.h"
#include "syzygy/agent/asan/runtime_util.h"
#include "syzygy/agent/common/agent.h"
#include "syzygy/common/logging.h"

namespace agent {
namespace asan {
namespace {

struct AsanFeatureName {
  AsanFeature flag;
  const char* name;
};

static const AsanFeatureName kAsanFeatureNames[] = {
    {ASAN_FEATURE_ENABLE_PAGE_PROTECTIONS, "SyzyASANPageProtections"},
    {DEPRECATED_ASAN_FEATURE_ENABLE_CTMALLOC, nullptr},
    {ASAN_FEATURE_ENABLE_LARGE_BLOCK_HEAP, "SyzyASANLargeBlockHeap"},
    {DEPRECATED_ASAN_FEATURE_ENABLE_KASKO, nullptr},
    {DEPRECATED_ASAN_FEATURE_ENABLE_CRASHPAD, nullptr},
};

// This lock guards against IAT patching on multiple threads concurrently.
base::Lock patch_lock;

// The maximum number of patch attemps to tolerate.
const size_t kPatchAttempsMax = 10;
// Counts the number of patch attempts that have occurred. Under patch_lock.
size_t patch_attempts = 0;
// Set to true when patching has been successfully accomplished.
bool patch_complete = false;

// Our AtExit manager required by base.
base::AtExitManager* at_exit = nullptr;

// The asan runtime manager.
AsanRuntime* asan_runtime = nullptr;

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

MemoryAccessorMode SelectMemoryAccessorMode() {
  static uint64_t kOneGB = 1ull << 30;

  // If there is no runtime then use the noop probes.
  if (asan_runtime == nullptr)
    return MEMORY_ACCESSOR_MODE_NOOP;

  // Determine the amount of shadow memory allocated.
  uint64_t gb = asan_runtime->shadow()->length();
  gb <<= kShadowRatioLog;
  gb /= kOneGB;

  switch (gb) {
#ifndef _WIN64
    case 2:
      return MEMORY_ACCESSOR_MODE_2G;
    case 4:
      return MEMORY_ACCESSOR_MODE_4G;
#else
    case 0x2000:
      return MEMORY_ACCESSOR_MODE_8TB;
    case 0x20000:
      return MEMORY_ACCESSOR_MODE_128TB;
#endif
    // 1GB should never happen, and 3GB simply isn't properly supported.
    default:
      return MEMORY_ACCESSOR_MODE_NOOP;
  }
}

MemoryAccessorMode OnRedirectStubEntry(const void* caller_address) {
  // This grabs the loader's lock, which could be a problem. If there are
  // multiple instrumented DLLs, or a single one executing on multiple threads,
  // there could be lock inversion here. The possibility seems remote, though.
  // Maybe locating the module associated with the caller_address can be done
  // with a VirtualQuery, with a fallback to the loader for an additional pair
  // of belt-and-suspenders...
  const DWORD kFlags = GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                       GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT;
  HMODULE calling_module = nullptr;
  BOOL success = ::GetModuleHandleEx(
      kFlags, reinterpret_cast<LPCWSTR>(caller_address), &calling_module);
  CHECK_EQ(TRUE, success);

  // TODO(chrisha): Implement logic for selecting the noop mode if the system
  // isn't up to par, if so configured by Finch, if the shadow memory
  // allocation failed, etc.
  MemoryAccessorMode mode = SelectMemoryAccessorMode();

  // If a runtime has been successfully allocated but for whatever reason the
  // noop instrumentation has been selected, then cleanup the runtime
  // allocation.
  if (mode == MEMORY_ACCESSOR_MODE_NOOP && asan_runtime != nullptr)
    TearDownAsanRuntime(&asan_runtime);

  // Build the IAT patch map.
  IATPatchMap patch_map;
#ifndef _WIN64
  for (size_t i = 0; i < kNumMemoryAccessorVariants; ++i) {
    patch_map.insert(
        std::make_pair(kMemoryAccessorVariants[i].name,
                       kMemoryAccessorVariants[i].accessors[mode]));
  }
#endif
  for (size_t i = 0; i < kNumClangMemoryAccessorVariants; ++i) {
    patch_map.insert(
        std::make_pair(kClangMemoryAccessorVariants[i].name,
                       reinterpret_cast<FunctionPointer>(
                           kClangMemoryAccessorVariants[i].accessors[mode])));
  }

  // Grab the patching lock only while patching the caller's IAT. Assuming no
  // other parties are patching this IAT, this is sufficient to prevent
  // double-patching due to multiple threads invoking on instrumentation
  // concurrently idempotent.
  base::AutoLock lock(patch_lock);
  if (!patch_complete) {
    ++patch_attempts;
    auto result = PatchIATForModule(calling_module, patch_map);
    // If somebody is racing with us to patch our IAT we want to know about it.
    CHECK_EQ(0u, result & PATCH_FAILED_RACY_WRITE);

    // Increment the counter on failure and potentially try again.
    if (result != PATCH_SUCCEEDED) {
      CHECK_LE(patch_attempts, kPatchAttempsMax);
    } else {
      patch_complete = true;
    }
  }

  return mode;
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
      ::common::InitLoggingForDll(L"asan");

      // Setup the ASAN runtime. If this fails then |asan_runtime| will remain
      // nullptr, and the stub redirection will enable the noop probes.
      SetUpAsanRuntime(&asan_runtime);

      // Hookup IAT patching on redirector stub entry.
      agent::asan::SetRedirectEntryCallback(base::Bind(OnRedirectStubEntry));
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

// Enables the deferred free mechanism. This can be called only once per
// execution.
VOID WINAPI asan_EnableDeferredFreeThread() {
  asan_runtime->EnableDeferredFreeThread();
}

// Disables the deferred free mechanism. This must be called before shutdown if
// the thread was started.
VOID WINAPI asan_DisableDeferredFreeThread() {
  asan_runtime->DisableDeferredFreeThread();
}

void WINAPI asan_EnumExperiments(AsanExperimentCallback callback) {
  DCHECK(callback != nullptr);

  // Under the current implementation, each randomized feature is considered an
  // individual experiment, with two groups "Enabled" and "Disabled"
  AsanFeatureSet enabled_features = asan_runtime->GetEnabledFeatureSet();
  for (const auto& feature : kAsanFeatureNames) {
    if (feature.name) {
      const char* state = "Disabled";
      if ((enabled_features & feature.flag) != 0)
        state = "Enabled";
      callback(feature.name, state);
    } else {
      // Deprecated features should never be enabled.
      DCHECK_EQ(0U, enabled_features & feature.flag);
    }

    // Mask out this feature.
    enabled_features &= ~feature.flag;
  }

  // Check that we had names for all the features.
  DCHECK_EQ(0U, enabled_features);
}

}  // extern "C"

}  // namespace asan
}  // namespace agent
