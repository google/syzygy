// Copyright 2012 Google Inc. All Rights Reserved.
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

using agent::profiler::ReturnThunkFactoryBase;
using agent::profiler::ReturnThunkFactoryImpl;
using testing::_;
using testing::AnyNumber;
using testing::StrictMock;

// A ReturnThunkFactoryImpl subclass that exposes various
// private bits for testing.
class TestFactory : public ReturnThunkFactoryImpl<TestFactory> {
 public:
  TestFactory() : ReturnThunkFactoryImpl<TestFactory>() {
  }
  ~TestFactory() {
    Uninitialize();
  }

  MOCK_METHOD1(OnPageAdded, void(const void*));
  MOCK_METHOD1(OnPageRemoved, void(const void*));
  MOCK_METHOD2(OnFunctionExit,
               void(const ReturnThunkFactoryBase::ThunkData*, uint64_t));

  using ReturnThunkFactoryImpl<TestFactory>::PageFromThunk;
  using ReturnThunkFactoryImpl<TestFactory>::Initialize;
  using ReturnThunkFactoryImpl<TestFactory>::ThunkMain;
  using ReturnThunkFactoryImpl<TestFactory>::kNumThunksPerPage;
};

class ReturnThunkTest : public testing::Test {
 public:
  void SetUp() {
    ASSERT_EQ(NULL, factory_);

    // The first page is created immediately on construction.
    factory_ = new StrictMock<TestFactory>();
    ASSERT_TRUE(factory_ != NULL);
    EXPECT_CALL(*factory_, OnPageAdded(_));
    factory_->Initialize();
  }

  void TearDown() {
    if (factory_ != NULL) {
      EXPECT_CALL(*factory_, OnPageRemoved(_))
          .Times(testing::AnyNumber());
      delete factory_;
    }

    factory_ = NULL;
  }

  static RetAddr WINAPI StaticMakeHook(RetAddr real_ret) {
    return factory_->MakeThunk(real_ret)->thunk;
  }

 protected:
  // Valid during tests.
  static StrictMock<TestFactory>* factory_;
};

StrictMock<TestFactory>* ReturnThunkTest::factory_ = NULL;

// This assembly function indirectly calls ReturnThunkFactoryBase::MakeThunk
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

TEST_F(ReturnThunkTest, AllocateThunk) {
  // Make sure we get page addition calls for each page.
  const size_t kNumPages = 3;
  EXPECT_CALL(*factory_, OnPageAdded(_))
      .Times(kNumPages);

  // Make sure the data->thunk->data mapping holds for a bunch of thunks.
  for (size_t i = 0; i < kNumPages * TestFactory::kNumThunksPerPage; ++i) {
    RetAddr addr = reinterpret_cast<RetAddr>(i);
    ReturnThunkFactoryBase::ThunkData* data = factory_->MakeThunk(addr);
    ASSERT_TRUE(data != NULL);
    ASSERT_TRUE(data->thunk != NULL);
    ASSERT_TRUE(data->self == factory_);
    ASSERT_TRUE(data->caller == addr);
    ASSERT_EQ(data, ReturnThunkFactoryBase::DataFromThunk(data->thunk));
  }
}

TEST_F(ReturnThunkTest, AllocateSeveralPages) {
  ReturnThunkFactoryBase::ThunkData* previous_data = NULL;

  // Make sure we get page addition calls for each page.
  const size_t kNumPages = 3;
  EXPECT_CALL(*factory_, OnPageAdded(_))
      .Times(kNumPages);

  for (size_t i = 0; i < kNumPages * TestFactory::kNumThunksPerPage; ++i) {
    ReturnThunkFactoryBase::ThunkData* data = factory_->MakeThunk(NULL);
    ASSERT_TRUE(data);
    if (previous_data) {
      ASSERT_TRUE(
          (TestFactory::PageFromThunk(data->thunk) !=
           TestFactory::PageFromThunk(previous_data->thunk)) ||
          (data->thunk > previous_data->thunk));
    }

    previous_data = data;
  }

  // And test page removal, note that we get an extra page removal
  // notification for the first page that's allocated on construction.
  EXPECT_CALL(*factory_, OnPageRemoved(_))
      .Times(kNumPages + 1);
  delete factory_;
  factory_ = NULL;
}

TEST_F(ReturnThunkTest, ReturnViaThunk) {
  EXPECT_CALL(*factory_, OnFunctionExit(_, _));

  create_and_return_via_thunk();
}

TEST_F(ReturnThunkTest, ReuseThunks) {
  ReturnThunkFactoryBase::ThunkData* first_thunk = factory_->MakeThunk(NULL);
  factory_->MakeThunk(NULL);
  ReturnThunkFactoryBase::ThunkData* third_thunk = factory_->MakeThunk(NULL);

  // This simulates a return via the first thunk.
  EXPECT_CALL(*factory_, OnFunctionExit(_, _));
  TestFactory::ThunkMain(first_thunk, 0LL);

  factory_->MakeThunk(NULL);
  factory_->MakeThunk(NULL);
  ReturnThunkFactoryBase::ThunkData* new_third_thunk =
      factory_->MakeThunk(NULL);
  ASSERT_EQ(third_thunk, new_third_thunk);
  ASSERT_EQ(third_thunk->thunk, new_third_thunk->thunk);
}

TEST_F(ReturnThunkTest, ReusePages) {
  ReturnThunkFactoryBase::ThunkData* first_thunk = factory_->MakeThunk(NULL);
  ReturnThunkFactoryBase::ThunkData* last_thunk = NULL;

  EXPECT_CALL(*factory_, OnPageAdded(_));
  for (size_t i = 0; i < TestFactory::kNumThunksPerPage; ++i) {
    last_thunk = factory_->MakeThunk(NULL);
  }

  // last_thunk should be the first thunk of the next page.
  ASSERT_NE(TestFactory::PageFromThunk(first_thunk->thunk),
            TestFactory::PageFromThunk(last_thunk->thunk));

  // This simulates a return via the first thunk, after which
  // we need to make kNumThunksPerPage + 1 thunks to again get
  // to the first thunk of the second page.
  EXPECT_CALL(*factory_, OnFunctionExit(_, _));
  TestFactory::ThunkMain(first_thunk, 0LL);

  ReturnThunkFactoryBase::ThunkData* new_last_thunk = NULL;
  for (size_t i = 0; i < TestFactory::kNumThunksPerPage + 1; ++i) {
    new_last_thunk = factory_->MakeThunk(NULL);
  }

  // We should reuse the previously-allocated second page.
  ASSERT_EQ(last_thunk, new_last_thunk);
  ASSERT_EQ(last_thunk->thunk, new_last_thunk->thunk);
}

TEST_F(ReturnThunkTest, CastToThunk) {
  // Allocate a bunch of thunks.
  ReturnThunkFactoryBase::ThunkData* first_thunk = factory_->MakeThunk(NULL);
  ReturnThunkFactoryBase::ThunkData* last_thunk = NULL;

  EXPECT_CALL(*factory_, OnPageAdded(_));
  for (size_t i = 0; i < TestFactory::kNumThunksPerPage; ++i) {
    last_thunk = factory_->MakeThunk(NULL);
  }

  ASSERT_EQ(last_thunk->thunk,
            factory_->CastToThunk(static_cast<RetAddr>(last_thunk->thunk)));
  ASSERT_EQ(first_thunk->thunk,
            factory_->CastToThunk(static_cast<RetAddr>(first_thunk->thunk)));

  // Make sure we're doing this without touching the underlying return address.
  ASSERT_EQ(NULL, factory_->CastToThunk(reinterpret_cast<RetAddr>(0x10)));
}

TEST_F(ReturnThunkTest, ReturnPreservesRegisters) {
  EXPECT_CALL(*factory_, OnFunctionExit(_, _));

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
