// Copyright 2012 Google Inc.
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
#include "syzygy/agent/common/shadow_stack.h"

#include "gtest/gtest.h"

namespace agent {

namespace {

class ShadowStackTest : public testing::Test {
 public:
  struct StackEntry : public StackEntryBase {
    int foo;
  };

  typedef ShadowStackImpl<StackEntry> TestShadowStack;
  static void ExitHook() {}
  static void DummyFn() {}

 protected:
  TestShadowStack stack;
};

}  // namespace

TEST_F(ShadowStackTest, PushPop) {
  EntryFrame frame = { &DummyFn, 1, 2, 3, 4 };
  StackEntry& pushed_entry = stack.Push(&frame);

  EXPECT_EQ(1, stack.size());

  EXPECT_TRUE(pushed_entry.return_address == &DummyFn);
  EXPECT_TRUE(pushed_entry.entry_frame == &frame);

  pushed_entry.foo = 0xCAFEBABE;

  EXPECT_EQ(&pushed_entry, &stack.Peek());

  StackEntry popped_entry = stack.Pop();
  EXPECT_TRUE(popped_entry.return_address == &DummyFn);
  EXPECT_TRUE(popped_entry.entry_frame == &frame);
  EXPECT_EQ(0xCAFEBABE, popped_entry.foo);
}

TEST_F(ShadowStackTest, TrimOrphansOnEntry) {
  EntryFrame frames[10];

  // It must be safe to trim the empty stack.
  stack.TrimOrphansOnEntry(&frames[0]);
  EXPECT_EQ(0, stack.size());

  // Push the frames, note that we need to push them in
  // order of decreasing addresses. We push each frame
  // twice to make like tail recursion or tail-call
  // elimination
  for (int i = arraysize(frames); i > 0; --i) {
    stack.Push(&frames[i - 1]);
    stack.Push(&frames[i - 1]);
  }
  EXPECT_EQ(20, stack.size());

  // This should not trim anything, as this is what happens in the case of
  // tail call or tail recursion elmination.
  stack.TrimOrphansOnEntry(&frames[0]);
  EXPECT_EQ(20, stack.size());

  // This should trim down one level.
  stack.TrimOrphansOnEntry(&frames[1]);
  EXPECT_EQ(18, stack.size());

  // This is what we see in the usual case, the frame pointer is below the TOS.
  stack.TrimOrphansOnEntry(&frames[0]);
  EXPECT_EQ(18, stack.size());

  // Pass a pointer just above an existing frame.
  stack.TrimOrphansOnEntry(
      reinterpret_cast<EntryFrame*>(
          reinterpret_cast<uint8*>(&frames[2]) + 4));
  EXPECT_EQ(14, stack.size());

  // Trim everything.
  stack.TrimOrphansOnEntry(&frames[11]);
  EXPECT_EQ(0, stack.size());
}

TEST_F(ShadowStackTest, TrimOrphansOnExit) {
  EntryFrame frames[10];

  // Push the frames, note that we need to push them in
  // order of decreasing addresses. We push each frame
  // twice to make like tail recursion or tail-call
  // elimination
  for (int i = arraysize(frames); i > 0; --i) {
    stack.Push(&frames[i - 1]);
    stack.Push(&frames[i - 1]);
  }
  EXPECT_EQ(20, stack.size());

  // This is like a typical __cdecl or zero-argument __stdcall return, e.g.
  // the return address alone has been popped. Nothing should be trimmed.
  stack.TrimOrphansOnExit(&frames[0].args);
  EXPECT_EQ(20, stack.size());

  // This mimics the edge case where a __stdcall has returned and cleaned up
  // the stack all the way to the return address of the next frame.
  stack.TrimOrphansOnExit(&frames[1]);
  EXPECT_EQ(20, stack.size());

  // The return address of the second level has been popped, which
  // means the first level is orphaned.
  stack.TrimOrphansOnExit(&frames[1].args);
  EXPECT_EQ(18, stack.size());
}

TEST_F(ShadowStackTest, FixBackTrace) {
  // TODO(siggi): Writeme.
  //     It occurs to me that the current implementation of FixBackTrace is
  //     incorrect, as it doesn't account for tail recursion.
}

}  // namespace agent
