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

#include <algorithm>

#include "base/logging.h"
#include "base/process_util.h"

// http://blogs.msdn.com/oldnewthing/archive/2004/10/25/247180.aspx
extern "C" IMAGE_DOS_HEADER __ImageBase;

namespace agent {
namespace asan {

uint32 ComputeStackTraceHash(void** stack_trace, uint8 stack_depth) {
  uint32 hash_value = 0;
  for (uint8 i = 0; i < stack_depth; ++i) {
    hash_value += reinterpret_cast<uint32>(stack_trace[i]);
  }
  return hash_value;
}

// The number of bottom frames to skip per stack trace.
size_t StackCapture::bottom_frames_to_skip_ = kDefaultBottomFramesToSkip_;

size_t StackCapture::GetSize(size_t max_num_frames) {
  DCHECK_LT(0u, max_num_frames);
  max_num_frames = std::min(max_num_frames, kMaxNumFrames);
  return offsetof(StackCapture, frames_) + max_num_frames * sizeof(void*);
}

size_t StackCapture::GetMaxNumFrames(size_t bytes) {
  if (bytes < offsetof(StackCapture, frames_))
    return 0;
  bytes -= offsetof(StackCapture, frames_);
  bytes /= sizeof(void*);
  return bytes;
}

void StackCapture::AddRef() {
  if (RefCountIsSaturated())
    return;
  DCHECK_GT(kMaxRefCount, ref_count_);
  ++ref_count_;
}

void StackCapture::RemoveRef() {
  DCHECK_LT(0u, ref_count_);
  if (RefCountIsSaturated())
    return;
  --ref_count_;
}

void StackCapture::Init() {
  bottom_frames_to_skip_ = kDefaultBottomFramesToSkip_;
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

StackCapture::StackId StackCapture::ComputeRelativeStackId() {
  // We want to ignore the frames relative to our module to be able to get the
  // same trace id even if we update our runtime.
  HANDLE asan_handle = reinterpret_cast<HANDLE>(&__ImageBase);
  DCHECK(asan_handle != NULL);

  StackId stack_id = 0;
  for (size_t i = 0; i < num_frames_; ++i) {
    HMODULE module = base::GetModuleFromAddress(frames_[i]);
    if (module == NULL || module == asan_handle)
      continue;
    stack_id += reinterpret_cast<size_t>(frames_[i]) -
      reinterpret_cast<size_t>(module);
  }

  return stack_id;
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
