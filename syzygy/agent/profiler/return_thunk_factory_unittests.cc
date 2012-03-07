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

#include "syzygy/agent/profiler/return_thunk_factory.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace {

using agent::profiler::ReturnThunkFactory;
using testing::_;
using testing::AnyNumber;
using testing::StrictMock;

class MockDelegate : public ReturnThunkFactory::Delegate {
 public:
  MOCK_METHOD2(OnFunctionExit, void(const ReturnThunkFactory::Thunk*, uint64));
  MOCK_METHOD1(OnPageAdded, void(const void*));
  MOCK_METHOD1(OnPageRemoved, void(const void*));
};

// Version of ReturnThunkFactory that exposes various private bits for testing.
class TestFactory : public ReturnThunkFactory {
 public:
  explicit TestFactory(Delegate* delegate) : ReturnThunkFactory(delegate) {
  }

  using ReturnThunkFactory::MakeThunk;
  using ReturnThunkFactory::PageFromThunk;
  using ReturnThunkFactory::ThunkMain;
  using ReturnThunkFactory::kNumThunksPerPage;
};

class ReturnThunkTest : public testing::Test {
 public:
  void SetUp() {
    ASSERT_EQ(NULL, factory_);

    // The first page is created immediately on construction.
    EXPECT_CALL(delegate_, OnPageAdded(_));
    factory_ = new TestFactory(&delegate_);
  }

  void TearDown() {
    if (factory_ != NULL) {
      EXPECT_CALL(delegate_, OnPageRemoved(_))
          .Times(testing::AnyNumber());
      delete factory_;
    }

    factory_ = NULL;
  }

  static RetAddr WINAPI StaticMakeHook(RetAddr real_ret) {
    return factory_->MakeThunk(real_ret);
  }

 protected:
  StrictMock<MockDelegate> delegate_;

  // Valid during tests.
  static TestFactory* factory_;
};

TestFactory* ReturnThunkTest::factory_ = NULL;

// This assembly function indirectly calls ReturnThunkFactory::MakeThunk
// and switches its return address with the returned thunk.
extern "C" void __declspec(naked) create_and_return_via_thunk() {
  __asm {
    // Push the real return address, get the thunk, and replace
    // the return address on stack with the thunk.
    push DWORD PTR[esp]
    call ReturnThunkTest::StaticMakeHook
    mov DWORD PTR[esp], eax

    // Return to the thunk.
    ret
  }
}

extern "C" void __declspec(naked) capture_contexts(CONTEXT* before,
                                                   CONTEXT* after) {
  __asm {
    // Create a thunk that returns to the label below.
    mov eax, return_here
    push eax
    call ReturnThunkTest::StaticMakeHook

    // Push the thunk to the stack.
    push eax

    // Capture the CPU context before returning through the thunk.
    push DWORD PTR[esp+8]
    call DWORD PTR[RtlCaptureContext]

    // Restore EAX, which is stomped by RtlCaptureContext.
    mov eax, DWORD PTR[esp+8]
    mov eax, DWORD PTR[eax + CONTEXT.Eax]
    // Return to the thunk, this'll go to the label below.
    ret

  return_here:

    // And now after jumping through it, note we popped the thunk.
    push DWORD PTR[esp+8]
    call DWORD PTR[RtlCaptureContext]

    ret
  }
}

TEST_F(ReturnThunkTest, AllocateSeveralPages) {
  ReturnThunkFactory::Thunk* previous_thunk = NULL;

  // Make sure we get page addition calls for each page.
  const size_t kNumPages = 3;
  EXPECT_CALL(delegate_, OnPageAdded(_))
      .Times(kNumPages);

  for (size_t i = 0; i < kNumPages * TestFactory::kNumThunksPerPage; ++i) {
    ReturnThunkFactory::Thunk* thunk = factory_->MakeThunk(NULL);
    ASSERT_TRUE(thunk);
    ASSERT_TRUE(
        (TestFactory::PageFromThunk(thunk) !=
         TestFactory::PageFromThunk(previous_thunk)) ||
        (thunk > previous_thunk));
    previous_thunk = thunk;
  }

  // And test page removal.
  EXPECT_CALL(delegate_, OnPageRemoved(_))
      .Times(kNumPages);
  delete factory_;
  factory_ = NULL;
}

TEST_F(ReturnThunkTest, ReturnViaThunk) {
  EXPECT_CALL(delegate_, OnFunctionExit(_, _));

  create_and_return_via_thunk();
}

TEST_F(ReturnThunkTest, ReuseThunks) {
  ReturnThunkFactory::Thunk* first_thunk = factory_->MakeThunk(NULL);
  factory_->MakeThunk(NULL);
  ReturnThunkFactory::Thunk* third_thunk = factory_->MakeThunk(NULL);

  // This simulates a return via the first thunk.
  EXPECT_CALL(delegate_, OnFunctionExit(_, _));
  TestFactory::ThunkMain(first_thunk, 0LL);

  factory_->MakeThunk(NULL);
  factory_->MakeThunk(NULL);
  ReturnThunkFactory::Thunk* new_third_thunk = factory_->MakeThunk(NULL);
  ASSERT_EQ(third_thunk, new_third_thunk);
}

TEST_F(ReturnThunkTest, ReusePages) {
  ReturnThunkFactory::Thunk* first_thunk = factory_->MakeThunk(NULL);
  ReturnThunkFactory::Thunk* last_thunk = NULL;

  EXPECT_CALL(delegate_, OnPageAdded(_));
  for (size_t i = 0; i < TestFactory::kNumThunksPerPage; ++i) {
    last_thunk = factory_->MakeThunk(NULL);
  }

  // last_thunk should be the first thunk of the next page.
  ASSERT_NE(TestFactory::PageFromThunk(first_thunk),
            TestFactory::PageFromThunk(last_thunk));

  // This simulates a return via the first thunk, after which
  // we need to make kNumThunksPerPage + 1 thunks to again get
  // to the first thunk of the second page.
  EXPECT_CALL(delegate_, OnFunctionExit(_, _));
  TestFactory::ThunkMain(first_thunk, 0LL);

  ReturnThunkFactory::Thunk* new_last_thunk = NULL;
  for (size_t i = 0; i < TestFactory::kNumThunksPerPage + 1; ++i) {
    new_last_thunk = factory_->MakeThunk(NULL);
  }

  // We should reuse the previously-allocated second page.
  ASSERT_EQ(last_thunk, new_last_thunk);
}

TEST_F(ReturnThunkTest, ReturnPreservesRegisters) {
  EXPECT_CALL(delegate_, OnFunctionExit(_, _));

  CONTEXT before = {};
  CONTEXT after = {};
  capture_contexts(&before, &after);

  EXPECT_EQ(before.SegGs, after.SegGs);
  EXPECT_EQ(before.SegFs, after.SegFs);
  EXPECT_EQ(before.SegEs, after.SegEs);
  EXPECT_EQ(before.SegDs, after.SegDs);

  EXPECT_EQ(before.Edi, after.Edi);
  EXPECT_EQ(before.Esi, after.Esi);
  EXPECT_EQ(before.Ebx, after.Ebx);
  EXPECT_EQ(before.Edx, after.Edx);
  EXPECT_EQ(before.Ecx, after.Ecx);
  EXPECT_EQ(before.Eax, after.Eax);

  EXPECT_EQ(before.Ebp, after.Ebp);
  EXPECT_EQ(before.Eip, after.Eip);
  EXPECT_EQ(before.SegCs, after.SegCs);
  EXPECT_EQ(before.EFlags, after.EFlags);
  EXPECT_EQ(before.Esp, after.Esp);
  EXPECT_EQ(before.SegSs, after.SegSs);
}

}  // namespace
