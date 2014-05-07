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

#include "syzygy/agent/asan/asan_system_interceptors.h"

#include <algorithm>

#include "base/logging.h"
#include "syzygy/agent/asan/asan_rtl_utils.h"

namespace {

using agent::asan::HeapProxy;
using agent::asan::Shadow;
using agent::asan::TestMemoryRange;
using agent::asan::TestStructure;

// A callback that will be used in the functions interceptors once the call
// to the intercepted function has been done. This is for testing purposes
// only.
InterceptorTailCallback interceptor_tail_callback = NULL;

}  // namespace

extern "C" {

void asan_SetInterceptorCallback(InterceptorTailCallback callback) {
  interceptor_tail_callback = callback;
}

// Bring in the implementation of the system interceptors that have been
// automatically generated.
#include "syzygy/agent/asan/asan_system_interceptors_impl.gen"

}  // extern "C"
