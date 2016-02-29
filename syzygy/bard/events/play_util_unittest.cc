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

#include "syzygy/bard/events/play_util.h"

#include <windows.h>

#include "base/macros.h"
#include "gtest/gtest.h"

namespace bard {

namespace {

struct StackTrace {
  // One frame for each nibble of the stack ID.
  void* frames[8];
};

template <uint32_t kInvokeValue>
using InvokeHelper =
    detail::InvokeFunctionWithStackIdHelper<kInvokeValue,
                                            bool(bool, StackTrace*),
                                            bool,
                                            bool,
                                            StackTrace*>;

bool ParrotImpl(bool input, StackTrace* stack_trace) {
  // Capture the current stack trace, but ignore the current frame. This should
  // only grab the InvokeFunctionWithStackIdHelper frames.
  CaptureStackBackTrace(1, arraysize(stack_trace->frames), stack_trace->frames,
                        nullptr);
  return input;
}

// Does nothing.
bool Dummy(bool input, StackTrace* stack_trace) {
  return false;
}

// Wraps a call to ParrotImpl via InvokeFunctionWithStackId.
bool Parrot(uint32_t stack_id, bool input, StackTrace* stack_trace) {
  return InvokeFunctionWithStackId(stack_id, ParrotImpl, input, stack_trace);
}

// Gets the extents of the associated InvokeHelper function.
template <uint32_t kInvokeValue>
struct GetInvokeFunctionExtents {
  static void Do(void const** invoke_helper_begins,
                 void const** invoke_helper_ends) {
    InvokeHelper<kInvokeValue>::Do(detail::kGetFunctionExtentsDepth, 0, Dummy,
                                   false, nullptr);
    invoke_helper_begins[kInvokeValue] = detail::kInvokeFunctionBegin;
    invoke_helper_ends[kInvokeValue] = detail::kInvokeFunctionEnd;
  }
};

}  // namespace

TEST(InvokeFunctionWithStackIdTest, ExpectedStackId) {
  // Get the extents of the various invoke helper functions.
  void const* invoke_helper_begins[16] = {};
  void const* invoke_helper_ends[16] = {};
  GetInvokeFunctionExtents<0x0>::Do(invoke_helper_begins, invoke_helper_ends);
  GetInvokeFunctionExtents<0x1>::Do(invoke_helper_begins, invoke_helper_ends);
  GetInvokeFunctionExtents<0x2>::Do(invoke_helper_begins, invoke_helper_ends);
  GetInvokeFunctionExtents<0x3>::Do(invoke_helper_begins, invoke_helper_ends);
  GetInvokeFunctionExtents<0x4>::Do(invoke_helper_begins, invoke_helper_ends);
  GetInvokeFunctionExtents<0x5>::Do(invoke_helper_begins, invoke_helper_ends);
  GetInvokeFunctionExtents<0x6>::Do(invoke_helper_begins, invoke_helper_ends);
  GetInvokeFunctionExtents<0x7>::Do(invoke_helper_begins, invoke_helper_ends);
  GetInvokeFunctionExtents<0x8>::Do(invoke_helper_begins, invoke_helper_ends);
  GetInvokeFunctionExtents<0x9>::Do(invoke_helper_begins, invoke_helper_ends);
  GetInvokeFunctionExtents<0xA>::Do(invoke_helper_begins, invoke_helper_ends);
  GetInvokeFunctionExtents<0xB>::Do(invoke_helper_begins, invoke_helper_ends);
  GetInvokeFunctionExtents<0xC>::Do(invoke_helper_begins, invoke_helper_ends);
  GetInvokeFunctionExtents<0xD>::Do(invoke_helper_begins, invoke_helper_ends);
  GetInvokeFunctionExtents<0xE>::Do(invoke_helper_begins, invoke_helper_ends);
  GetInvokeFunctionExtents<0xF>::Do(invoke_helper_begins, invoke_helper_ends);

  // Generate a handful of random stack IDs and ensure they are dispatched via
  // the expected functions.
  StackTrace stack_trace = {};
  for (size_t i = 0; i < 100; ++i) {
    uint32_t stack_id = ::rand();
    bool value = ::rand() % 2;
    EXPECT_EQ(value, Parrot(stack_id, value, &stack_trace));

    for (size_t j = 0; j < 8; ++j) {
      uint32_t nibble = (stack_id >> (28 - 4 * j)) & 0xF;
      EXPECT_LT(invoke_helper_begins[nibble], stack_trace.frames[j]);
      EXPECT_GE(invoke_helper_ends[nibble], stack_trace.frames[j]);
    }
  }
}

}  // namespace bard
