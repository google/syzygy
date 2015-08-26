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
  HeapSetInformationEvent heap_set_information_event(
      kTraceHeap, kInfoClass, kInfo, kInfoLength, true);
  EXPECT_CALL(*this, FakeCall(kLiveHeap, kInfoClass, kInfo, kInfoLength))
      .WillOnce(Return(true));

  EXPECT_TRUE(
      heap_set_information_event.Play(reinterpret_cast<void*>(&backdrop_)));
}

TEST_F(HeapSetInformationEventTest, TestFailCall) {
  HeapSetInformationEvent heap_set_information_event(
      kTraceHeap, kInfoClass, kInfo, kInfoLength, false);
  EXPECT_CALL(*this, FakeCall(kLiveHeap, kInfoClass, kInfo, kInfoLength))
      .WillOnce(Return(false));

  EXPECT_TRUE(
      heap_set_information_event.Play(reinterpret_cast<void*>(&backdrop_)));
}

TEST_F(HeapSetInformationEventTest, TestInconsistentReturn) {
  HeapSetInformationEvent heap_set_information_event(
      kTraceHeap, kInfoClass, kInfo, kInfoLength, false);
  EXPECT_CALL(*this, FakeCall(kLiveHeap, kInfoClass, kInfo, kInfoLength))
      .WillOnce(Return(true));

  EXPECT_FALSE(
      heap_set_information_event.Play(reinterpret_cast<void*>(&backdrop_)));
}

TEST_F(HeapSetInformationEventTest, TestSerialization) {
  HeapSetInformationEvent heap_set_information_event(
      kTraceHeap, kInfoClass, kInfo, kInfoLength, true);

  scoped_ptr<HeapSetInformationEvent> copy =
      testing::TestEventSerialization(heap_set_information_event);

  EXPECT_EQ(heap_set_information_event.trace_heap(), copy->trace_heap());
  EXPECT_EQ(heap_set_information_event.info_class(), copy->info_class());
  EXPECT_EQ(heap_set_information_event.info(), copy->info());
  EXPECT_EQ(heap_set_information_event.info_length(), copy->info_length());
  EXPECT_EQ(heap_set_information_event.trace_succeeded(),
            copy->trace_succeeded());
}

}  // namespace events
}  // namespace bard
