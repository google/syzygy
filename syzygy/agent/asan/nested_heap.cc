// Copyright 2013 Google Inc. All Rights Reserved.
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
#include "syzygy/agent/asan/nested_heap.h"

#include "base/bits.h"
#include "syzygy/agent/asan/asan_heap.h"
#include "syzygy/agent/asan/asan_shadow.h"
#include "syzygy/agent/asan/stack_capture.h"
#include "syzygy/common/align.h"

namespace {

using agent::asan::HeapProxy;
using agent::asan::Shadow;
using agent::asan::StackCapture;

}  // namespace

void asan_PoisonMemoryRange(const void* address, size_t size) {
  DCHECK(address != NULL);
  DCHECK(common::IsAligned(reinterpret_cast<uint8>(address) + size,
                           Shadow::kShadowGranularity));

  Shadow::Poison(address, size, Shadow::kUserRedzone);
}

void asan_UnpoisonMemoryRange(const void* address, size_t size) {
  DCHECK(address != NULL);
  DCHECK(common::IsAligned(reinterpret_cast<uint8>(address),
                           Shadow::kShadowGranularity));
  DCHECK(common::IsAligned(size, Shadow::kShadowGranularity));

  Shadow::Unpoison(address, size);
}

size_t asan_GetAsanObjectSize(size_t user_object_size,
                                     size_t alignment) {
  return HeapProxy::GetAllocSize(user_object_size, alignment);
}

void asan_GetUserExtent(const void* asan_pointer,
                        void** user_pointer,
                        size_t* size) {
  DCHECK(asan_pointer != NULL);
  DCHECK(user_pointer != NULL);
  DCHECK(size != NULL);

  return HeapProxy::GetUserExtent(asan_pointer, user_pointer, size);
}

void asan_GetAsanExtent(const void* user_pointer,
                               void** asan_pointer,
                               size_t* size) {
  DCHECK(user_pointer != NULL);
  DCHECK(asan_pointer != NULL);
  DCHECK(size != NULL);

  HeapProxy::GetAsanExtent(user_pointer, asan_pointer, size);
}

void asan_InitializeObject(void* asan_pointer,
                                  size_t user_object_size,
                                  size_t alignment) {
  DCHECK(asan_pointer != NULL);

  uint8 alignment_log = base::bits::Log2Floor(alignment);

  StackCapture stack;
  stack.InitFromStack();

  HeapProxy::InitializeAsanBlock(reinterpret_cast<uint8*>(asan_pointer),
                                 user_object_size,
                                 HeapProxy::GetAllocSize(user_object_size,
                                                         alignment),
                                 alignment_log,
                                 stack);
}

void asan_QuarantineObject(void* asan_pointer) {
  DCHECK(asan_pointer != NULL);

  StackCapture stack;
  stack.InitFromStack();

  HeapProxy::MarkBlockAsQuarantined(asan_pointer, stack);
}

void asan_DestroyObject(void* asan_pointer) {
  DCHECK(asan_pointer != NULL);

  HeapProxy::DestroyAsanBlock(asan_pointer);
}

void asan_CloneObject(const void* src_asan_pointer,
                             const void* dst_asan_pointer) {
  // TODO(sebmarchand): Implement this function.
  NOTREACHED();
}
