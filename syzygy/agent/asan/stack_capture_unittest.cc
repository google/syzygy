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

#include "base/memory/scoped_ptr.h"
#include "gtest/gtest.h"

namespace agent {
namespace asan {

namespace {

class StackCaptureTest : public testing::Test {
 public:
  void SetUp() OVERRIDE {
    // Setup the "global" state.
    StackCapture::Init();
  }
};

}  // namespace

TEST_F(StackCaptureTest, InitFromBuffer) {
  StackCapture capture;

  // Validate the capture's initial state.
  EXPECT_FALSE(capture.IsValid());
  EXPECT_EQ(0u, capture.stack_id());
  EXPECT_EQ(0, capture.num_frames());
  EXPECT_EQ(StackCapture::kMaxNumFrames, capture.max_num_frames());
  EXPECT_EQ(NULL, capture.frames());

  // Create some fake stack trace data.
  ULONG stack_id = 10;
  void* frames[StackCapture::kMaxNumFrames + 1] = { 0 };
  for (size_t i = 0; i < arraysize(frames); ++i) {
    frames[i] = reinterpret_cast<void*>(i);
  }

  // Initialize the stack capture without using all of the frames.
  capture.InitFromBuffer(stack_id, frames, 7);
  EXPECT_TRUE(capture.IsValid());
  EXPECT_EQ(10u, capture.stack_id());
  EXPECT_EQ(7, capture.num_frames());
  EXPECT_EQ(StackCapture::kMaxNumFrames, capture.max_num_frames());
  EXPECT_TRUE(capture.frames() != NULL);

  // Attempt to initialize the stack capture using too many frames; the
  // resulting capture should truncate to kMaxNumFrames.
  capture.InitFromBuffer(stack_id, frames, arraysize(frames));
  EXPECT_TRUE(capture.IsValid());
  EXPECT_EQ(10u, capture.stack_id());
  EXPECT_EQ(StackCapture::kMaxNumFrames, capture.num_frames());
  EXPECT_EQ(StackCapture::kMaxNumFrames, capture.max_num_frames());
  EXPECT_TRUE(capture.frames() != NULL);
}

TEST_F(StackCaptureTest, InitFromStack) {
  StackCapture capture;

  EXPECT_FALSE(capture.IsValid());
  EXPECT_EQ(0u, capture.stack_id());
  EXPECT_EQ(0, capture.num_frames());
  EXPECT_EQ(StackCapture::kMaxNumFrames, capture.max_num_frames());

  capture.InitFromStack();
  EXPECT_TRUE(capture.IsValid());
  EXPECT_LT(0u, capture.num_frames());
  EXPECT_EQ(StackCapture::kMaxNumFrames, capture.max_num_frames());
}

TEST_F(StackCaptureTest, RestrictedFrameCount) {
  StackCapture::set_bottom_frames_to_skip(0);
  // Restrict this to a stack depth that is smaller than the stack depth of
  // this test.
  StackCapture capture(5);
  EXPECT_FALSE(capture.IsValid());
  EXPECT_EQ(0u, capture.stack_id());
  EXPECT_EQ(0, capture.num_frames());
  EXPECT_EQ(5u, capture.max_num_frames());

  capture.InitFromStack();
  EXPECT_TRUE(capture.IsValid());
  EXPECT_EQ(5u, capture.num_frames());
  EXPECT_EQ(5u, capture.max_num_frames());
}

}  // namespace asan
}  // namespace agent
