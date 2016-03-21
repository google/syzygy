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
// Defines the Asan Hot Patching CRT interceptors.
//
// Hot Patching Asan transformed links modules against these functions
// instead of the CRT ones. When hot patching is inactive, these functions
// call the respective system functions.
// TODO(cseri): When hot patching Asan mode is activated, the import entries
// of these functions must be overwritten to call the respective functions
// from the SyzyAsan runtime library.
#ifndef SYZYGY_AGENT_ASAN_HP_CRT_INTERCEPTORS_H_
#define SYZYGY_AGENT_ASAN_HP_CRT_INTERCEPTORS_H_

#include "syzygy/agent/asan/crt_interceptors_macros.h"

// Exposes the CRT interceptors.
extern "C" {

// See crt_interceptors_macros.h for details.
ASAN_CRT_INTERCEPTORS(ASAN_CRT_INTERCEPTORS_DECL, hp_asan_);

}  // extern "C"

#endif  // SYZYGY_AGENT_ASAN_HP_CRT_INTERCEPTORS_H_
