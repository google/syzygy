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

#include "syzygy/bard/events/heap_alloc_event.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/bard/unittest_util.h"
#include "syzygy/bard/backdrops/heap_backdrop.h"

namespace bard {
namespace events {

namespace {

using bard::backdrops::HeapBackdrop;
using bard::events::HeapAllocEvent;
using testing::Return;

const HANDLE kLiveHeap = reinterpret_cast<HANDLE>(0x4197FC83);
const HANDLE kTraceHeap = reinterpret_cast<HANDLE>(0xAB12CD34);
const LPVOID kLiveAlloc = reinterpret_cast<LPVOID>(0x4820BC7A);
const LPVOID kTraceAlloc = reinterpret_cast<LPVOID>(0xF1D97AE4);
const DWORD kFlags = 1;
const SIZE_T kBytes = 100;

class HeapAllocEventTest : public testing::Test {
 public:
  HeapAllocEventTest()
      : heap_alloc_event_(0, kTraceHeap, kFlags, kBytes, kTraceAlloc) {}

  MOCK_METHOD3(FakeCall, LPVOID(HANDLE, DWORD, SIZE_T));

  void SetUp() override {
    backdrop_.heap_map().AddMapping(kTraceHeap, kLiveHeap);

    backdrop_.set_heap_alloc(
        base::Bind(&HeapAllocEventTest::FakeCall, base::Unretained(this)));
  }

 protected:
  HeapAllocEvent heap_alloc_event_;
  HeapBackdrop backdrop_;
};

}  // namespace

TEST_F(HeapAllocEventTest, TestSuccessCall) {
  EXPECT_CALL(*this, FakeCall(kLiveHeap, kFlags, kBytes))
      .WillOnce(Return(kLiveAlloc));

  EXPECT_TRUE(heap_alloc_event_.Play(reinterpret_cast<void*>(&backdrop_)));

  testing::CheckTraceLiveMapContains(backdrop_.alloc_map(),
                                     kTraceAlloc,
                                     kLiveAlloc);
}

TEST_F(HeapAllocEventTest, TestFailCall) {
  EXPECT_CALL(*this, FakeCall(kLiveHeap, kFlags, kBytes))
      .WillOnce(Return(nullptr));

  EXPECT_FALSE(heap_alloc_event_.Play(reinterpret_cast<void*>(&backdrop_)));

  testing::CheckTraceLiveMapNotContain(backdrop_.alloc_map(),
                                       kTraceAlloc,
                                       kLiveAlloc);
}

TEST_F(HeapAllocEventTest, Equals) {
  HeapAllocEvent e1(0, kTraceHeap, kFlags, kBytes, kTraceAlloc);
  HeapAllocEvent e2(0, kTraceHeap, kFlags, kBytes, kTraceAlloc);
  HeapAllocEvent e3(0, kTraceHeap, kFlags, kBytes + 3, kTraceAlloc);
  EXPECT_TRUE(e1.Equals(&e1));
  EXPECT_TRUE(e1.Equals(&e2));
  EXPECT_FALSE(e1.Equals(&e3));
  EXPECT_FALSE(e2.Equals(&e3));
}

TEST_F(HeapAllocEventTest, TestSerialization) {
  testing::TestEventSerialization(heap_alloc_event_);
}

}  // namespace events
}  // namespace bard
