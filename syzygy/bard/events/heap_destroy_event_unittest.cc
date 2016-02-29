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

#include "syzygy/bard/events/heap_destroy_event.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/bard/unittest_util.h"
#include "syzygy/bard/backdrops/heap_backdrop.h"

namespace bard {
namespace events {

namespace {

using bard::backdrops::HeapBackdrop;
using bard::events::HeapDestroyEvent;
using testing::Return;

const HANDLE kLiveHeap = reinterpret_cast<HANDLE>(0x4197FC83);
const HANDLE kTraceHeap = reinterpret_cast<HANDLE>(0xAB12CD34);

class HeapDestroyEventTest : public testing::Test {
 public:
  MOCK_METHOD1(FakeCall, BOOL(HANDLE));

  void SetUp() override {
    backdrop_.heap_map().AddMapping(kTraceHeap, kLiveHeap);

    backdrop_.set_heap_destroy(
        base::Bind(&HeapDestroyEventTest::FakeCall, base::Unretained(this)));
  }

 protected:
  HeapBackdrop backdrop_;
};

}  // namespace

TEST_F(HeapDestroyEventTest, TestSuccessCall) {
  HeapDestroyEvent heap_destroy_event(0, kTraceHeap, true);

  EXPECT_CALL(*this, FakeCall(kLiveHeap)).WillOnce(Return(true));

  EXPECT_TRUE(heap_destroy_event.Play(reinterpret_cast<void*>(&backdrop_)));

  testing::CheckTraceLiveMapNotContain(backdrop_.heap_map(),
                                       kTraceHeap,
                                       kLiveHeap);
}

TEST_F(HeapDestroyEventTest, TestFailCall) {
  HeapDestroyEvent heap_destroy_event(0, kTraceHeap, false);

  EXPECT_CALL(*this, FakeCall(kLiveHeap)).WillOnce(Return(false));

  EXPECT_TRUE(heap_destroy_event.Play(reinterpret_cast<void*>(&backdrop_)));

  testing::CheckTraceLiveMapContains(backdrop_.heap_map(),
                                     kTraceHeap,
                                     kLiveHeap);
}

TEST_F(HeapDestroyEventTest, TestInconsistentReturn) {
  HeapDestroyEvent heap_destroy_event(0, kTraceHeap, false);

  EXPECT_CALL(*this, FakeCall(kLiveHeap)).WillOnce(Return(true));

  EXPECT_FALSE(heap_destroy_event.Play(reinterpret_cast<void*>(&backdrop_)));

  testing::CheckTraceLiveMapContains(backdrop_.heap_map(),
                                     kTraceHeap,
                                     kLiveHeap);
}

TEST_F(HeapDestroyEventTest, Equals) {
  HeapDestroyEvent e1(0, kTraceHeap, false);
  HeapDestroyEvent e2(0, kTraceHeap, false);
  HeapDestroyEvent e3(0, kTraceHeap, true);
  EXPECT_TRUE(e1.Equals(&e1));
  EXPECT_TRUE(e1.Equals(&e2));
  EXPECT_FALSE(e1.Equals(&e3));
  EXPECT_FALSE(e2.Equals(&e3));
}

TEST_F(HeapDestroyEventTest, TestSerialization) {
  HeapDestroyEvent heap_destroy_event(0, kTraceHeap, true);
  testing::TestEventSerialization(heap_destroy_event);
}

}  // namespace events
}  // namespace bard
