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

#include "syzygy/agent/asan/stack_capture.h"

#include "base/logging.h"

namespace agent {
namespace asan {

uint32 ComputeStackTraceHash(void** stack_trace, uint8 stack_depth) {
  uint32 hash_value = 0;
  for (uint8 i = 0; i < stack_depth; ++i) {
    hash_value += reinterpret_cast<uint32>(stack_trace[i]);
  }
  return hash_value;
}

// The biggest gain observed on stack cache compression is when we skip the 5
// bottom frames of the stack traces. To measure this gain we've run an
// instrumented version of base_unittests and observed the cache compression.
// With a value between 0 and 4 the compression ratio was around 28.9%, and with
// a value of 5 it was 92.19%.
// NOTE: This is mostly for Chrome's unittests, the side effect is that the
//     bottom frames of the allocation and free stack traces of any instrumented
//     image will be elided, but from what we've seen they're rarely precise and
//     useful (they refer to the entry point of the image).
size_t StackCapture::bottom_frames_to_skip_ = 5;

size_t StackCapture::GetSize(size_t max_num_frames) {
  DCHECK_LT(0u, max_num_frames);
  max_num_frames = std::min(max_num_frames, kMaxNumFrames);
  return offsetof(StackCapture, frames_) + max_num_frames * sizeof(void*);
}

void StackCapture::InitFromBuffer(StackId stack_id,
                                  const void* const* frames,
                                  size_t num_frames) {
  DCHECK(frames != NULL);
  DCHECK_LT(0U, num_frames);
  stack_id_ = stack_id;
  num_frames_ = std::min<uint8>(num_frames, max_num_frames_);
  ::memcpy(frames_, frames, num_frames_ * sizeof(void*));
}

size_t StackCapture::HashCompare::operator()(
    const StackCapture* stack_capture) const {
  DCHECK(stack_capture != NULL);
  // We're assuming that the StackId and size_t have the same size, so let's
  // make sure that's the case.
  COMPILE_ASSERT(sizeof(StackId) == sizeof(size_t),
                 stack_id_and_size_t_not_same_size);
  return stack_capture->stack_id_;
}

bool StackCapture::HashCompare::operator()(
    const StackCapture* stack_capture1,
    const StackCapture* stack_capture2) const {
  DCHECK(stack_capture1 != NULL);
  DCHECK(stack_capture2 != NULL);
  return stack_capture1->stack_id_ < stack_capture2->stack_id_;
}

}  // namespace asan
}  // namespace agent
