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
//
// Declares a utility class for getting and storing quick and dirty stack
// captures.

#ifndef SYZYGY_AGENT_COMMON_STACK_CAPTURE_H_
#define SYZYGY_AGENT_COMMON_STACK_CAPTURE_H_

#include <windows.h>

#include "base/logging.h"
#include "syzygy/agent/common/stack_walker.h"
#include "syzygy/common/asan_parameters.h"

namespace agent {
namespace common {

// A simple class for holding a stack trace capture.
class StackCapture {
 public:
  // From http://msdn.microsoft.com/en-us/library/bb204633.aspx,
  // The maximum number of frames which CaptureStackBackTrace can be asked
  // to traverse must be less than 63, so set it to 62.
  static const size_t kMaxNumFrames = 62;

  // The type used for reference counting. We use saturation arithmetic, so it
  // will top out at kMaxRefCount.
  using RefCount = uint16_t;
  static const RefCount kMaxRefCount = static_cast<RefCount>(-1);

  using StackId = ::common::AsanStackId;

  StackCapture()
      : ref_count_(0),
        absolute_stack_id_(0),
        relative_stack_id_(0),
        num_frames_(0),
        max_num_frames_(kMaxNumFrames) {}

  explicit StackCapture(size_t max_num_frames)
      : ref_count_(0),
        absolute_stack_id_(0),
        relative_stack_id_(0),
        num_frames_(0),
        max_num_frames_(0) {
    DCHECK_LT(0u, max_num_frames);
    DCHECK_GE(kMaxNumFrames, max_num_frames);
    max_num_frames_ = static_cast<uint8_t>(max_num_frames);
  }

  // Static initialisation of StackCapture context.
  static void Init();

  // Calculate the size necessary to store a StackCapture with the given
  // number of stack frames.
  // @param max_num_frames The maximum number of stack frames the object needs
  //     to be able to hold.
  // @returns the size of a StackCapture object with the given number of frames.
  static size_t GetSize(size_t max_num_frames);

  // Calculate the max number of frames that can be fit into a memory region of
  // the given size.
  // @param bytes The number of bytes to be used.
  // @returns the maxmimum number of frames that will fit in the provided number
  //     of bytes.
  static size_t GetMaxNumFrames(size_t bytes);

  // @returns the size of this initialized StackCapture object.
  size_t Size() const { return GetSize(max_num_frames_); }

  // @returns true if this stack trace capture contains valid frame pointers.
  bool IsValid() const { return num_frames_ != 0; }

  // Increments the reference count of this stack capture.
  void AddRef();

  // Decrements the reference count of this stack capture.
  void RemoveRef();

  // @returns true if the reference count is saturated, false otherwise. A
  //     saturated reference count means that further calls to AddRef and
  //     RemoveRef will be nops, and HasNoRefs will always return false.
  bool RefCountIsSaturated() const { return ref_count_ == kMaxRefCount; }

  // @returns true if this stack capture is not referenced, false otherwise.
  bool HasNoRefs() const { return ref_count_ == 0; }

  // @returns the reference count for this stack capture.
  RefCount ref_count() const { return ref_count_; }

  // @returns the absolute ID associated with this stack trace.
  StackId absolute_stack_id() const { return absolute_stack_id_; }

  // @returns the relative ID associated with this stack trace.
  StackId relative_stack_id() const;

  // @returns the number of valid frame pointers in this stack trace capture.
  size_t num_frames() const { return num_frames_; }

  // @returns the maximum number of valid frame pointers in this stack trace
  //     capture.
  size_t max_num_frames() const { return max_num_frames_; }

  // @returns a pointer to the stack frames array, or NULL if the array has a
  //     size of 0.
  const void* const* frames() const {
    return max_num_frames_ != 0 ? frames_ : NULL;
  }

  // Set the number of bottom frames to skip per stack trace. This is needed to
  // be able to improve the stack cache compression in Chrome's unittests where
  // the bottom of the stack traces is different for each test case.
  // @param bottom_frames_to_skip The number of bottom frames to skip.
  static void set_bottom_frames_to_skip(size_t bottom_frames_to_skip) {
    CHECK_LT(bottom_frames_to_skip, kMaxNumFrames);
    bottom_frames_to_skip_ = bottom_frames_to_skip;
  }

  // Get the number of bottom frames to skip per stack trace.
  static size_t bottom_frames_to_skip() { return bottom_frames_to_skip_; }

  // Initializes a stack trace from an array of frame pointers and a count.
  // @param frames an array of frame pointers.
  // @param num_frames the number of valid frame pointers in @frames. Note
  //     that at most kMaxNumFrames frame pointers will be copied to this
  //     stack trace capture.
  void InitFromBuffer(const void* const* frames, size_t num_frames);

  // Initializes a stack trace from an existing stack trace.
  // @param stack_capture The existing stack trace that will be copied.
  void InitFromExistingStack(const StackCapture& stack_capture);

  // Initializes a stack trace from the actual stack. Does not report the
  // frame created by 'InitFromStack' itself. This function must not be inlined
  // as it assumes that the call to it generates a full stack frame.
  void __declspec(noinline) InitFromStack();

  // @name Testing seams.
  // @{
  // Allows injecting false modules for use in computing the relative stack ID.
  // These locations will always be checked first before querying the OS for
  // a module address, so can be used to overlay fake modules on top of real
  // modules.
  // @param name The name of the fake module.
  // @param address The address of the fake module.
  // @param length The length of the fake module.
  static void AddFalseModule(const char* name, void* address, size_t length);
  static void ClearFalseModules();
  // @}

  // @name Hashing helpers.
  // @{
  // Uses a simple hash with reasonable properties. This is effectively the same
  // as base::SuperFastHash, but we can't use it as there's no API for updating
  // an in-progress hash.
  static StackId StartStackId();
  static StackId UpdateStackId(StackId stack_id, const void* frame);
  static StackId FinalizeStackId(StackId stack_id, size_t num_frames);
  // @}

 protected:
  // The number of bottom frames to skip on the stack traces.
  static size_t bottom_frames_to_skip_;

  // The absolute unique ID of this hash. This is used for storing the hash in
  // the set.
  StackId absolute_stack_id_;

  // The relative unique ID of this hash. This is used when persistence between
  // runs is needed. Should be only accessed through relative_stack_id() as it's
  // computed on demand and cached (which is why it's declared as mutable).
  mutable StackId relative_stack_id_;

  // The number of valid frames in this stack trace capture, and the maximum
  // number it can represent. We use uint8_ts here because we're limited to
  // kMaxNumFrames by the OS machinery and want this data structure to be as
  // compact as possible.
  uint8_t num_frames_;
  uint8_t max_num_frames_;

  // The reference count for this stack capture. We use saturation arithmetic
  // and something that is referenced 2^16 - 1 times will stay at that reference
  // count and never be removed from the stack cache.
  RefCount ref_count_;

  // The array or frame pointers comprising this stack trace capture.
  // This is a runtime dynamic array whose actual length is max_num_frames_, but
  // we use the maximum length here so that other users of StackCapture can
  // capture full stack traces if they so desire.
  // NOTE: This must be the last member of the class.
  void* frames_[kMaxNumFrames];

  // Computes a simple hash of a given stack trace, referred to as the absolute
  // stack id and sets the value in |absolute_stack_id_|.
  void ComputeAbsoluteStackId();

  // Computes the hash of a stack trace using relative addresses of each stack
  // frame. Declared virtual for unittesting.
  virtual void ComputeRelativeStackId() const;

  DISALLOW_COPY_AND_ASSIGN(StackCapture);
};

// static
__forceinline StackId StackCapture::StartStackId() {
  return 0x4ADFA3E5;
}

// static
__forceinline StackId StackCapture::UpdateStackId(StackId stack_id,
                                                  const void* frame) {
  stack_id += static_cast<StackId>(reinterpret_cast<uintptr_t>(frame));
  stack_id += stack_id << 10;
  stack_id ^= stack_id >> 6;
  return stack_id;
}

// static
__forceinline StackId StackCapture::FinalizeStackId(StackId stack_id,
                                                    size_t num_frames) {
  stack_id += stack_id << 3;
  stack_id ^= stack_id >> 11;
  stack_id += stack_id << 15;
  stack_id ^= num_frames;
  return stack_id;
}

}  // namespace common
}  // namespace agent

#endif  // SYZYGY_AGENT_COMMON_STACK_CAPTURE_H_
