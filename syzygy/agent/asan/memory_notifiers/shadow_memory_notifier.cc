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

#include "syzygy/agent/asan/memory_notifiers/shadow_memory_notifier.h"

#include "syzygy/agent/asan/shadow.h"
#include "syzygy/common/align.h"

namespace agent {
namespace asan {
namespace memory_notifiers {

namespace {

void AlignRange(const void** address, size_t* size) {
  DCHECK_NE(reinterpret_cast<void**>(nullptr), address);
  DCHECK_NE(reinterpret_cast<size_t*>(nullptr), size);
  const uint8_t* start = reinterpret_cast<const uint8_t*>(*address);
  const uint8_t* end = start + *size;
  start = ::common::AlignDown(start, kShadowRatio);
  end = ::common::AlignUp(end, kShadowRatio);
  *address = start;
  *size = end - start;
}

}  // namespace

void ShadowMemoryNotifier::NotifyInternalUse(
    const void* address, size_t size) {
  DCHECK_NE(static_cast<void*>(nullptr), address);
  AlignRange(&address, &size);
  shadow_->Poison(address, size, kAsanMemoryMarker);
}

void ShadowMemoryNotifier::NotifyFutureHeapUse(
    const void* address, size_t size) {
  DCHECK_NE(static_cast<void*>(nullptr), address);
  AlignRange(&address, &size);
  shadow_->Poison(address, size, kAsanReservedMarker);
}

void ShadowMemoryNotifier::NotifyReturnedToOS(
    const void* address, size_t size) {
  DCHECK_NE(static_cast<void*>(nullptr), address);
  AlignRange(&address, &size);
  shadow_->Unpoison(address, size);
}

}  // namespace memory_notifiers
}  // namespace asan
}  // namespace agent
