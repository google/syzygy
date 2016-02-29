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

#include "syzygy/bard/events/heap_set_information_event.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/bard/unittest_util.h"
#include "syzygy/bard/backdrops/heap_backdrop.h"

namespace bard {
namespace events {

namespace {

using bard::backdrops::HeapBackdrop;
using bard::events::HeapSetInformationEvent;
using testing::Return;

const HANDLE kLiveHeap = reinterpret_cast<HANDLE>(0x4197FC83);
const HANDLE kTraceHeap = reinterpret_cast<HANDLE>(0xAB12CD34);
const LPVOID kLiveAlloc = reinterpret_cast<LPVOID>(0x4820BC7A);
const LPVOID kTraceAlloc = reinterpret_cast<LPVOID>(0xF1D97AE4);
const HEAP_INFORMATION_CLASS kInfoClass =
    static_cast<HEAP_INFORMATION_CLASS>(0);
const PVOID kInfo = reinterpret_cast<PVOID>(0x12345678);
const SIZE_T kInfoLength = 100;

class HeapSetInformationEventTest : public testing::Test {
 public:
  MOCK_METHOD4(FakeCall, BOOL(HANDLE, HEAP_INFORMATION_CLASS, PVOID, SIZE_T));

  void SetUp() override {
    backdrop_.heap_map().AddMapping(kTraceHeap, kLiveHeap);
    backdrop_.alloc_map().AddMapping(kTraceAlloc, kLiveAlloc);

    backdrop_.set_heap_set_information(base::Bind(
        &HeapSetInformationEventTest::FakeCall, base::Unretained(this)));
  }

 protected:
  HeapBackdrop backdrop_;
};

}  // namespace

TEST_F(HeapSetInformationEventTest, TestSuccessCall) {
  HeapSetInformationEvent heap_set_information_event(0, kTraceHeap, kInfoClass,
                                                     kInfo, kInfoLength, true);
  EXPECT_CALL(*this, FakeCall(kLiveHeap, kInfoClass, kInfo, kInfoLength))
      .WillOnce(Return(true));

  EXPECT_TRUE(
      heap_set_information_event.Play(reinterpret_cast<void*>(&backdrop_)));
}

TEST_F(HeapSetInformationEventTest, TestFailCall) {
  HeapSetInformationEvent heap_set_information_event(0, kTraceHeap, kInfoClass,
                                                     kInfo, kInfoLength, false);
  EXPECT_CALL(*this, FakeCall(kLiveHeap, kInfoClass, kInfo, kInfoLength))
      .WillOnce(Return(false));

  EXPECT_TRUE(
      heap_set_information_event.Play(reinterpret_cast<void*>(&backdrop_)));
}

TEST_F(HeapSetInformationEventTest, TestInconsistentReturn) {
  HeapSetInformationEvent heap_set_information_event(0, kTraceHeap, kInfoClass,
                                                     kInfo, kInfoLength, false);
  EXPECT_CALL(*this, FakeCall(kLiveHeap, kInfoClass, kInfo, kInfoLength))
      .WillOnce(Return(true));

  EXPECT_FALSE(
      heap_set_information_event.Play(reinterpret_cast<void*>(&backdrop_)));
}

TEST_F(HeapSetInformationEventTest, Equals) {
  HeapSetInformationEvent e1(0, kTraceHeap, kInfoClass, kInfo, kInfoLength,
                             true);
  HeapSetInformationEvent e2(0, kTraceHeap, kInfoClass, kInfo, kInfoLength,
                             true);
  HeapSetInformationEvent e3(0, kTraceHeap, kInfoClass, kInfo, kInfoLength,
                             false);
  EXPECT_TRUE(e1.Equals(&e1));
  EXPECT_TRUE(e1.Equals(&e2));
  EXPECT_FALSE(e1.Equals(&e3));
  EXPECT_FALSE(e2.Equals(&e3));
}

TEST_F(HeapSetInformationEventTest, TestSerialization) {
  HeapSetInformationEvent heap_set_information_event(0, kTraceHeap, kInfoClass,
                                                     kInfo, kInfoLength, true);
  testing::TestEventSerialization(heap_set_information_event);
}

}  // namespace events
}  // namespace bard
