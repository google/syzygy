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

#ifndef SYZYGY_AGENT_ASAN_IAT_PATCHER_H_
#define SYZYGY_AGENT_ASAN_IAT_PATCHER_H_

#include <windows.h>

#include <map>
#include "base/strings/string_piece.h"

namespace agent {
namespace asan {

typedef void (*FunctionPointer)();
// Note this map doesn't copy the strings supplied, it's the caller's
// responsibility to ensure their lifetime.
using IATPatchMap = std::map<base::StringPiece, FunctionPointer>;

// Modifies the IAT of @p module such that each function named in @p patch_map
// points to the associated function.
// @param module the module to patch up.
// @param patch_map a map from name to the desired function.
// @note this function is BYOL - bring your own locking.
// @note IAT patching is inherently racy. It's wise to call this function from
//     under a lock that prevents concurrent patching on the same module, and
//     the caller must guarantee that the module is not unloaded during
//     patching.
// TODO(siggi): Should this be scoped to module name also?
bool PatchIATForModule(HMODULE module, const IATPatchMap& patch_map);

}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_IAT_PATCHER_H_
