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

#include "syzygy/agent/common/stack_capture.h"

#include <algorithm>

#include "base/logging.h"
#include "base/process/memory.h"

// http://blogs.msdn.com/oldnewthing/archive/2004/10/25/247180.aspx
extern "C" IMAGE_DOS_HEADER __ImageBase;

namespace agent {
namespace common {

namespace {

// Uses a simple hash with reasonable properties. This is effectively the same
// as base::SuperFastHash, but we can't use it as there's no API for updating
// an in-progress hash.
//
// http://en.wikipedia.org/wiki/Jenkins_hash_function#one-at-a-time
// @{
__forceinline StackCapture::StackId UpdateStackId(
    StackCapture::StackId stack_id, const void* frame) {
  stack_id += reinterpret_cast<StackId>(frame);
  stack_id += stack_id << 10;
  stack_id ^= stack_id >> 6;
  return stack_id;
}

__forceinline StackCapture::StackId FinalizeStackId(
    StackCapture::StackId stack_id) {
  stack_id += stack_id << 3;
  stack_id ^= stack_id >> 11;
  stack_id += stack_id << 15;
  return stack_id;
}

}  // namespace

// The number of bottom frames to skip per stack trace.
size_t StackCapture::bottom_frames_to_skip_ =
    ::common::kDefaultBottomFramesToSkip;

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

// static
void StackCapture::Init() {
  bottom_frames_to_skip_ = ::common::kDefaultBottomFramesToSkip;
}

// static
StackId StackCapture::ComputeStackId(const void* const* frames,
                                     size_t num_frames) {
  StackId stack_id = num_frames;

  for (uint8 i = 0; i < num_frames; ++i)
    stack_id = UpdateStackId(stack_id, frames[i]);

  stack_id = FinalizeStackId(stack_id);

  return stack_id;
}

void StackCapture::InitFromBuffer(StackId stack_id,
                                  const void* const* frames,
                                  size_t num_frames) {
  DCHECK(frames != NULL);
  DCHECK_LT(0U, num_frames);

  // Determine how many frames we can actually store.
  num_frames_ = std::min<uint8>(num_frames, max_num_frames_);

  // Recalculate the stack ID if the full stack doesn't fit.
  if (num_frames_ < num_frames) {
    stack_id_ = ComputeStackId(frames, num_frames_);
  } else {
    stack_id_ = stack_id;
  }

  ::memcpy(frames_, frames, num_frames_ * sizeof(*frames_));
}

// Disable optimizations so that this function generates a standard frame, and
// don't allow it to be inlined.
#pragma optimize("", off)
void __declspec(noinline) StackCapture::InitFromStack() {
  // TODO(chrisha): Make this use WalkStack. This breaks some unittests, which
  //     are more involved to fix and will require another CL.
  num_frames_ = ::CaptureStackBackTrace(1, max_num_frames_, frames_, nullptr);
  num_frames_ -= std::min(static_cast<uint8>(bottom_frames_to_skip_),
                          num_frames_);
  stack_id_ = ComputeStackId(frames_, num_frames_);
}
#pragma optimize("", on)

StackId StackCapture::ComputeRelativeStackId() const {
  // We want to ignore the frames relative to our module to be able to get the
  // same trace id even if we update our runtime.
  HANDLE asan_handle = reinterpret_cast<HANDLE>(&__ImageBase);
  DCHECK(asan_handle != NULL);

  StackId stack_id = 0;
  for (size_t i = 0; i < num_frames_; ++i) {
    // NULL stack frames may be returned from ::CaptureStackBackTrace.
    // This has been observed on Windows 8.
    if (frames_[i] == nullptr)
      continue;

    // Entirely skip frames that lie inside this module. This allows the
    // relative stack ID to be stable across different versions of the RTL
    // even if stack depth/layout changes.
    HMODULE module = base::GetModuleFromAddress(frames_[i]);
    if (module == asan_handle)
      continue;

    // Consider frames that are dynamically generated, but consider only their
    // indices, not their addresses.
    uintptr_t frame = i;
    if (module != nullptr) {
      // For frames that fall within a module, consider their relative address
      // in the module.
      frame = reinterpret_cast<uintptr_t>(frames_[i]) -
          reinterpret_cast<uintptr_t>(module);
    }

    stack_id = UpdateStackId(stack_id, reinterpret_cast<void*>(frame));
  }

  stack_id = FinalizeStackId(stack_id);

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
  return stack_capture1->stack_id_ == stack_capture2->stack_id_;
}

}  // namespace common
}  // namespace agent
