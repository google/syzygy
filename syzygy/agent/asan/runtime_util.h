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
//
// This file contains helper functions for setting up and tearing down the
// SyzyAsan runtime.

#ifndef SYZYGY_AGENT_ASAN_RUNTIME_UTIL_H_
#define SYZYGY_AGENT_ASAN_RUNTIME_UTIL_H_

#include "syzygy/agent/asan/runtime.h"

namespace agent {
namespace asan {

// Loads parameters from the module and the environment, then sets up the Asan
// runtime library.
// @param asan_runtime pointer that will receive the created Asan runtime
//     object.
// @pre |*asan_runtime| must be nullptr.
// @returns true on success, false otherwise.
bool SetUpAsanRuntime(AsanRuntime** asan_runtime);

// Calls the |TearDown| function of the runtime and deletes the runtime object.
// @param asan_runtime pointer to the Asan runtime object to destruct. This
//     pointer will be nullptr after the call.
void TearDownAsanRuntime(AsanRuntime** asan_runtime);

}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_RUNTIME_UTIL_H_
