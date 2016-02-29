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

#include "syzygy/bard/events/heap_size_event.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/bard/unittest_util.h"
#include "syzygy/bard/backdrops/heap_backdrop.h"

namespace bard {
namespace events {

namespace {

using bard::backdrops::HeapBackdrop;
using bard::events::HeapSizeEvent;
using testing::Return;

const HANDLE kLiveHeap = reinterpret_cast<HANDLE>(0x4197FC83);
const HANDLE kTraceHeap = reinterpret_cast<HANDLE>(0xAB12CD34);
const LPCVOID kLiveAlloc = reinterpret_cast<LPCVOID>(0x4820BC7A);
const LPCVOID kTraceAlloc = reinterpret_cast<LPCVOID>(0xF1D97AE4);
const DWORD kFlags = 1;
const SIZE_T kSize = 100;

class HeapSizeEventTest : public testing::Test {
 public:
  HeapSizeEventTest()
      : heap_size_event_(0, kTraceHeap, kFlags, kTraceAlloc, kSize) {}

  MOCK_METHOD3(FakeCall, SIZE_T(HANDLE, DWORD, LPCVOID));

  void SetUp() override {
    backdrop_.heap_map().AddMapping(kTraceHeap, kLiveHeap);
    backdrop_.alloc_map().AddMapping(const_cast<LPVOID>(kTraceAlloc),
                                     const_cast<LPVOID>(kLiveAlloc));

    backdrop_.set_heap_size(
        base::Bind(&HeapSizeEventTest::FakeCall, base::Unretained(this)));
  }

 protected:
  HeapSizeEvent heap_size_event_;
  HeapBackdrop backdrop_;
};

}  // namespace

TEST_F(HeapSizeEventTest, TestSuccessCall) {
  EXPECT_CALL(*this, FakeCall(kLiveHeap, kFlags, kLiveAlloc))
      .WillOnce(Return(kSize));

  EXPECT_TRUE(heap_size_event_.Play(reinterpret_cast<void*>(&backdrop_)));
}

TEST_F(HeapSizeEventTest, TestFailCall) {
  EXPECT_CALL(*this, FakeCall(kLiveHeap, kFlags, kLiveAlloc))
      .WillOnce(Return(kSize + 100));

  EXPECT_FALSE(heap_size_event_.Play(reinterpret_cast<void*>(&backdrop_)));
}

TEST_F(HeapSizeEventTest, Equals) {
  HeapSizeEvent e1(0, kTraceHeap, kFlags, kTraceAlloc, kSize);
  HeapSizeEvent e2(0, kTraceHeap, kFlags, kTraceAlloc, kSize);
  HeapSizeEvent e3(0, kTraceHeap, kFlags + 1, kTraceAlloc, kSize + 1);
  EXPECT_TRUE(e1.Equals(&e1));
  EXPECT_TRUE(e1.Equals(&e2));
  EXPECT_FALSE(e1.Equals(&e3));
  EXPECT_FALSE(e2.Equals(&e3));
}

TEST_F(HeapSizeEventTest, TestSerialization) {
  testing::TestEventSerialization(heap_size_event_);
}

}  // namespace events
}  // namespace bard
