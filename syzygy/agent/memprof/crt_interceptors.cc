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
//
// Dummy CRT interceptors for the memory profiler. This is simply for
// maintaining ABI compatibility.

#include <cstring>

#include "syzygy/agent/asan/crt_interceptors_macros.h"

extern "C" {

// See crt_interceptors_macros.h for details.
ASAN_CRT_INTERCEPTORS(ASAN_CRT_INTERCEPTORS_DEFN, asan_);

}  // extern "C"
