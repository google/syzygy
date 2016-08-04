// Copyright 2016 Google Inc. All Rights Reserved.
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

#include "syzygy/agent/common/stack_walker.h"

#include <windows.h>

#ifndef _WIN64
#include "base/logging.h"
#include "syzygy/agent/common/stack_capture.h"
#include "syzygy/common/align.h"
#endif

namespace agent {
namespace common {

#ifndef _WIN64

namespace {

static size_t kPointerSize = sizeof(void*);

__declspec(naked) void* GetEbp() {
  __asm {
    mov eax, ebp
    ret
  }
}

__declspec(naked) void* GetEsp() {
  __asm {
    mov eax, esp
    ret
  }
}

// A small struct that can be laid out on top of a standard stack frame in
// order to grab the EBP and return address fields. Strictly speaking this
// is actually a snippet along the edge of two frames: |next_frame| belonging
// to the callee, and |return_address| belonging to the caller.
struct StackFrame {
  StackFrame* next_frame;
  void* return_address;
};

// Helper function to determine if the given stack frame is in bounds with
// respect to the top of the stack.
__forceinline bool IsFrameInBounds(const void* stack_top, const void* frame) {
  // We've already confirmed that stack_bottom < stack_top, so stack_top can be
  // safely decremented without underflowing. On the other hand, we can't
  // increment |frame| without potentially overflowing. Yup, learned that one
  // the hard way.
  DCHECK_LE(reinterpret_cast<const void*>(4), stack_top);
  return frame <= reinterpret_cast<const StackFrame*>(stack_top) - 1;
}

// Returns true if the stack frame has a valid return address that can be
// read from.
__forceinline bool FrameHasValidReturnAddress(const void* stack_bottom,
                                              const void* stack_top,
                                              const StackFrame* frame) {
  if (!IsFrameInBounds(stack_top, frame))
    return false;

  // The current frame must be pointer aligned.
  if (!::common::IsAligned(frame, kPointerSize))
    return false;

  // The return address must not be null, and it can't be in the stack.
  if (frame->return_address == nullptr)
    return false;
  if (frame->return_address >= stack_bottom &&
      frame->return_address < stack_top) {
    return false;
  }

  return true;
}

__forceinline bool CanAdvanceFrame(const StackFrame* frame) {
  // The next frame pointer must be at least a full frame beyond the current
  // frame. Checking that the next frame lies within the stack is done by
  // 'FrameHasValidReturnAddress' before it gets read.
  if (frame + 1 > frame->next_frame)
    return false;
  return true;
}

}  // namespace

size_t __declspec(noinline) WalkStack(uint32_t bottom_frames_to_skip,
                                      uint32_t max_frame_count,
                                      void** frames,
                                      StackId* absolute_stack_id) {
  // Get the stack extents.
  // The first thing in the TEB is actually the TIB.
  // http://www.nirsoft.net/kernel_struct/vista/TEB.html
  NT_TIB* tib = reinterpret_cast<NT_TIB*>(NtCurrentTeb());
  void* stack_bottom = tib->StackLimit;  // Lower address.
  void* stack_top = tib->StackBase;  // Higher address.

  // Ensure that the stack extents make sense, and bail early if they
  // don't. Only proceed if there's at least room for a single pointer on
  // the stack.
  if (!::common::IsAligned(stack_top, kPointerSize) ||
      stack_bottom >= stack_top ||
      reinterpret_cast<StackFrame*>(stack_bottom) + 1 >= stack_top) {
    return 0;
  }

  // Ensure that the stack makes sense. If not, it's been hijacked and
  // something is seriously wrong.
  void *current_esp = GetEsp();
  void* current_ebp = GetEbp();
  if (stack_bottom > current_esp || current_esp > current_ebp ||
      !IsFrameInBounds(stack_top, current_ebp)) {
    return 0;
  }

  return WalkStackImpl(current_ebp, stack_bottom, stack_top,
                       bottom_frames_to_skip, max_frame_count, frames,
                       absolute_stack_id);
}

size_t WalkStackImpl(const void* current_ebp,
                     const void* stack_bottom,
                     const void* stack_top,
                     size_t bottom_frames_to_skip,
                     size_t max_frame_count,
                     void** frames,
                     StackId* absolute_stack_id) {
  DCHECK(::common::IsAligned(current_ebp, kPointerSize));
  DCHECK(::common::IsAligned(stack_top, kPointerSize));
  DCHECK_LT(stack_bottom, stack_top);
  DCHECK_LE(reinterpret_cast<const StackFrame*>(stack_bottom) + 1, stack_top);
  DCHECK_LE(current_ebp, stack_top);
  DCHECK_NE(static_cast<void**>(nullptr), frames);
  DCHECK_NE(static_cast<StackId*>(nullptr), absolute_stack_id);

  *absolute_stack_id = StackCapture::StartStackId();

  const StackFrame* current_frame =
      reinterpret_cast<const StackFrame*>(current_ebp);

  // Skip over any requested frames.
  while (bottom_frames_to_skip) {
    if (!FrameHasValidReturnAddress(stack_bottom, stack_top, current_frame))
      return 0;
    if (!CanAdvanceFrame(current_frame))
      return 0;
    --bottom_frames_to_skip;
    current_frame = current_frame->next_frame;
  }

  // Grab as many frames as possible.
  size_t num_frames = 0;
  while (num_frames < max_frame_count) {
    if (!FrameHasValidReturnAddress(stack_bottom, stack_top, current_frame))
      break;
    frames[num_frames] = current_frame->return_address;
    ++num_frames;
    *absolute_stack_id = StackCapture::UpdateStackId(
        *absolute_stack_id, current_frame->return_address);

    if (!CanAdvanceFrame(current_frame))
      break;

    current_frame = current_frame->next_frame;
  }

  *absolute_stack_id =
      StackCapture::FinalizeStackId(*absolute_stack_id, num_frames);

  return num_frames;
}

#else

size_t __declspec(noinline) WalkStack(uint32_t bottom_frames_to_skip,
                                      uint32_t max_frame_count,
                                      void** frames,
                                      StackId* absolute_stack_id) {
  // Skip one more frame for call of this function
  return CaptureStackBackTrace(bottom_frames_to_skip + 1,
                               max_frame_count,
                               frames,
                               reinterpret_cast<PDWORD>(absolute_stack_id));
}

#endif  // !defined _WIN64

}  // namespace common
}  // namespace agent
