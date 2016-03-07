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

#include <stdint.h>
#include <windows.h>

#include <map>
#include "base/strings/string_piece.h"
#include "syzygy/agent/asan/scoped_page_protections.h"

namespace agent {
namespace asan {

// Possible outcomes of patching. This is a bitmask as multiple reasons
// may be encountered at once.
enum PatchResults : uint32_t {
  // The patch succeeded.
  PATCH_SUCCEEDED = 0x00000000,
  // The patch failed because the given module does not appear to be a
  // valid image.
  PATCH_FAILED_INVALID_IMAGE = 0x00000001,
  // The patch failed because VirtualProtect failed to unprotect the page
  // for us.
  PATCH_FAILED_UNPROTECT_FAILED = 0x00000002,
  // The patch failed because of an access violation when writing to the
  // IAT. This can occur if another thread changes the page protections
  // from underneath us.
  PATCH_FAILED_ACCESS_VIOLATION = 0x00000004,
  // The patch failed because somebody else was racing us to write to the
  // same IAT entry.
  PATCH_FAILED_RACY_WRITE = 0x00000008,
  // The patch failed because VirtualProtect failed to unprotect the page
  // for us.
  PATCH_FAILED_REPROTECT_FAILED = 0x00000010,
};
using PatchResult = uint32_t;

typedef void (*FunctionPointer)();
// Note this map doesn't copy the strings supplied, it's the caller's
// responsibility to ensure their lifetime.
using IATPatchMap = std::map<base::StringPiece, FunctionPointer>;

// Testing callback.

// Modifies the IAT of @p module such that each function named in @p patch_map
// points to the associated function.
// @param module the module to patch up.
// @param patch_map a map from name to the desired function.
// @param on_unprotect Callback function that is invoked as page protections
//     are modified. Intended as a testing seam. See scoped_page_protections.h
//     for details.
// @note this function is BYOL - bring your own locking.
// @note IAT patching is inherently racy. It's wise to call this function from
//     under a lock that prevents concurrent patching on the same module, and
//     the caller must guarantee that the module is not unloaded during
//     patching.
// TODO(siggi): Should this be scoped to module name also?
PatchResult PatchIATForModule(HMODULE module, const IATPatchMap& patch_map);
PatchResult PatchIATForModule(HMODULE module, const IATPatchMap& patch_map,
    ScopedPageProtections::OnUnprotectCallback on_unprotect);

}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_IAT_PATCHER_H_
