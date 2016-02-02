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
// Provides a dummy static shadow memory array. This is simply to be used as
// a pointer for the probes to be anchored to. If any of the probes referring
// to this dummy shadow memory are run they will behave badly until they have
// been patched using 'PatchMemoryInterceptorShadowReferences'.
//
// Intended for use in syzyasan_rtl.dll.

#include <cstdint>

namespace {

static const size_t kShadowSize = 1;

}  // namespace

extern "C" {
size_t asan_memory_interceptors_shadow_memory_size = kShadowSize;
uint8_t asan_memory_interceptors_shadow_memory[kShadowSize] = {};
}
