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

#include "syzygy/agent/common/stack_walker.h"

#include <windows.h>

#include "gtest/gtest.h"
#include "syzygy/testing/metrics.h"

namespace agent {
namespace common {


namespace {

class StackWalkerTest : public testing::Test {
 public:
  StackWalkerTest()
      : dummy_ebp_(nullptr), dummy_esp_(nullptr), dummy_ret_(0u) {
    ::memset(frames_, 0, sizeof(frames_));
    ::memset(frames2_, 0, sizeof(frames2_));
    ::memset(dummy_stack_, 0, sizeof(dummy_stack_));
  }
#ifndef _WIN64
  static const uintptr_t kBaseRet = 0x1000000u;

  void Push(uintptr_t value) {
    --dummy_esp_;
    ASSERT_LE(dummy_stack_, dummy_esp_);
    *dummy_esp_ = value;
  }

  void PushEbp() {
    Push(reinterpret_cast<uintptr_t>(dummy_ebp_));
    dummy_ebp_ = dummy_esp_;
  }

  void PopEbp() {
    dummy_ebp_ = reinterpret_cast<uintptr_t*>(*dummy_esp_);
    ++dummy_esp_;
    ASSERT_LE(dummy_esp_, dummy_stack_ + arraysize(dummy_stack_));
  }

  void PushRet() {
    Push(dummy_ret_);
    ++dummy_ret_;
  }

  void ResetStack() {
    ::memset(dummy_stack_, 0, sizeof(dummy_stack_));
    dummy_ebp_ = dummy_stack_ + arraysize(dummy_stack_);
    dummy_esp_ = dummy_stack_ + arraysize(dummy_stack_);
    dummy_ret_ = kBaseRet;

    // Push a return address, so that the very topmost thing on the
    // stack is a return.
    PushRet();
  }

  void SetUp() override {
    ResetStack();
  }

  void BuildValidFrame(size_t locals) {
    PushEbp();
    for (size_t i = 0; i < locals; ++i)
      Push(::rand());
    PushRet();
  }

  void BuildInvalidFrameTooSmall() {
    // Only push an EBP. This will be too close to the EBP of the next valid
    // stack frame.
    PushEbp();
  }

  void BuildInvalidFrameNonIncreasingBasePointer() {
    Push(*dummy_ebp_ - 4 * sizeof(uintptr_t));
    dummy_ebp_ = dummy_esp_;
    PushRet();
  }

  void BuildInvalidFrameUnalignedBasePointer() {
    Push(*dummy_ebp_ - 1);
    dummy_ebp_ = dummy_esp_;
    PushRet();
  }

  void BuildInvalidFrameInvalidReturnAddress() {
    PushEbp();
    Push(0);  // Output a null return address.
    ++dummy_ret_;
  }

  void BuildInvalidFrameInvalidBasePointer() {
    Push(reinterpret_cast<uintptr_t>(dummy_stack_ + arraysize(dummy_stack_)));
    dummy_ebp_ = dummy_esp_;
    PushRet();
  }

  void BuildInvalidFrameOverflowingBasePointer() {
    // This base pointer will overflow to 0 when incremented.
    Push(0xFFFFFFFC);
    dummy_ebp_ = dummy_esp_;
    PushRet();
  }

  void ExpectSuccessfulWalk(size_t num_frames,
                            size_t frames_to_skip) {
    // Push a dummy EBP on the stack, which simulates the stack frame of the
    // function actually calling WalkStack.
    PushEbp();
    StackId stack_id;
    EXPECT_EQ(num_frames,
              WalkStackImpl(dummy_ebp_, dummy_esp_,
                            dummy_stack_ + arraysize(dummy_stack_),
                            frames_to_skip, kMaxFrames, frames_, &stack_id));
    for (size_t i = 0; i < num_frames; ++i) {
      EXPECT_EQ(reinterpret_cast<void*>(dummy_ret_ - i - 1 - frames_to_skip),
                frames_[i]);
    }

    PopEbp();
  }

#endif  // !defined _WIN64

  static const size_t kMaxFrames = 100;
  void* frames_[kMaxFrames];
  void* frames2_[kMaxFrames];

  uintptr_t dummy_stack_[1024];
  uintptr_t* dummy_ebp_;
  uintptr_t* dummy_esp_;
  uintptr_t dummy_ret_;
};

}  // namespace

#ifndef _WIN64

TEST_F(StackWalkerTest, ValidWalk) {
  BuildValidFrame(0);
  ExpectSuccessfulWalk(2, 0);
  BuildValidFrame(2);
  ExpectSuccessfulWalk(3, 0);
  BuildValidFrame(1);
  ExpectSuccessfulWalk(4, 0);
  ExpectSuccessfulWalk(3, 1);
  ExpectSuccessfulWalk(2, 2);
}

TEST_F(StackWalkerTest, WalkStopsWhenFrameTooSmall) {
  BuildValidFrame(0);
  ExpectSuccessfulWalk(2, 0);

  BuildInvalidFrameTooSmall();
  BuildValidFrame(1);
  ExpectSuccessfulWalk(1, 0);

  BuildValidFrame(2);
  ExpectSuccessfulWalk(2, 0);

  BuildValidFrame(1);
  ExpectSuccessfulWalk(3, 0);
  ExpectSuccessfulWalk(2, 1);
}

TEST_F(StackWalkerTest, WalkStopsAtNonIncreasingBasePointer) {
  BuildValidFrame(0);
  ExpectSuccessfulWalk(2, 0);

  BuildInvalidFrameNonIncreasingBasePointer();
  ExpectSuccessfulWalk(2, 0);

  BuildValidFrame(2);
  ExpectSuccessfulWalk(3, 0);

  BuildValidFrame(1);
  ExpectSuccessfulWalk(4, 0);
  ExpectSuccessfulWalk(3, 1);
}

TEST_F(StackWalkerTest, WalkStopsAtUnalignedBasePointer) {
  BuildValidFrame(0);
  ExpectSuccessfulWalk(2, 0);

  BuildInvalidFrameUnalignedBasePointer();
  ExpectSuccessfulWalk(2, 0);

  BuildValidFrame(2);
  ExpectSuccessfulWalk(3, 0);

  BuildValidFrame(1);
  ExpectSuccessfulWalk(4, 0);
  ExpectSuccessfulWalk(3, 1);
}

TEST_F(StackWalkerTest, WalkStopsAtInvalidReturnAddress) {
  BuildValidFrame(0);
  ExpectSuccessfulWalk(2, 0);

  BuildInvalidFrameInvalidReturnAddress();
  ExpectSuccessfulWalk(0, 0);

  BuildValidFrame(2);
  ExpectSuccessfulWalk(1, 0);

  BuildValidFrame(1);
  ExpectSuccessfulWalk(2, 0);
}

TEST_F(StackWalkerTest, WalkStopsAtInvalidBasePointer) {
  BuildValidFrame(0);
  ExpectSuccessfulWalk(2, 0);

  BuildInvalidFrameInvalidBasePointer();
  ExpectSuccessfulWalk(2, 0);

  BuildValidFrame(2);
  ExpectSuccessfulWalk(3, 0);

  BuildValidFrame(1);
  ExpectSuccessfulWalk(4, 0);
  ExpectSuccessfulWalk(3, 1);
}

TEST_F(StackWalkerTest, WalkStopAtOverflowingBasePointer) {
  BuildValidFrame(0);
  ExpectSuccessfulWalk(2, 0);

  BuildInvalidFrameOverflowingBasePointer();
  ExpectSuccessfulWalk(2, 0);

  BuildValidFrame(2);
  ExpectSuccessfulWalk(3, 0);

  BuildValidFrame(1);
  ExpectSuccessfulWalk(4, 0);
  ExpectSuccessfulWalk(3, 1);
}

#endif  // !defined _WIN64

TEST_F(StackWalkerTest, CompareToCaptureStackBackTrace) {
  // Use the OS stack walker to get the number of frames. Skip the top frame
  // (in this function) as WalkStack and CaptureStackBackTrace won't have the
  // same return address.
  uint32_t num_frames =
      ::CaptureStackBackTrace(1, kMaxFrames, frames_, nullptr);

  while (num_frames > 0) {
    StackId stack_id;
    size_t num_frames2 = WalkStack(1, num_frames, frames_, &stack_id);
    size_t exp_frames2 =
        ::CaptureStackBackTrace(1, num_frames, frames2_, nullptr);
    EXPECT_EQ(num_frames, num_frames2);
    EXPECT_EQ(exp_frames2, num_frames2);
    EXPECT_EQ(0, ::memcmp(frames_, frames2_, num_frames * sizeof(*frames_)));

    --num_frames;
  }
}

}  // namespace common
}  // namespace agent
