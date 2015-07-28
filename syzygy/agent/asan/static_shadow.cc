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
// Provides an actual static shadow memory. This is intended for use with
// runtimes that can't patch the memory interceptor probes and thus need a
// hardcoded address for the shadow memory array.
//
// Intended for use in syzyasan_rtl.dll.

#include "syzygy/agent/asan/shadow.h"

namespace {

// One shadow byte per group of kShadowRatio bytes in a 2G address space.
// NOTE: This is dependent on the process NOT being large address aware.
static const size_t kShadowSize = 1 << (31 - agent::asan::kShadowRatioLog);

}  // namespace

extern "C" {
size_t asan_memory_interceptors_shadow_memory_size = kShadowSize;
uint8_t asan_memory_interceptors_shadow_memory[kShadowSize] = {};
}
