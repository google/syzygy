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

#include "syzygy/bard/events/heap_free_event.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/bard/unittest_util.h"
#include "syzygy/bard/backdrops/heap_backdrop.h"

namespace bard {
namespace events {

namespace {

using bard::backdrops::HeapBackdrop;
using bard::events::HeapFreeEvent;
using testing::Return;

const HANDLE kLiveHeap = reinterpret_cast<HANDLE>(0x4197FC83);
const HANDLE kTraceHeap = reinterpret_cast<HANDLE>(0xAB12CD34);
const LPVOID kLiveAlloc = reinterpret_cast<LPVOID>(0x4820BC7A);
const LPVOID kTraceAlloc = reinterpret_cast<LPVOID>(0xF1D97AE4);
const DWORD kFlags = 1;

class HeapFreeEventTest : public testing::Test {
 public:
  MOCK_METHOD3(FakeCall, BOOL(HANDLE, DWORD, LPVOID));

  void SetUp() override {
    backdrop_.heap_map().AddMapping(kTraceHeap, kLiveHeap);
    backdrop_.alloc_map().AddMapping(kTraceAlloc, kLiveAlloc);

    backdrop_.set_heap_free(
        base::Bind(&HeapFreeEventTest::FakeCall, base::Unretained(this)));
  }

 protected:
  HeapBackdrop backdrop_;
};

}  // namespace

TEST_F(HeapFreeEventTest, TestSuccessCall) {
  HeapFreeEvent heap_free_event(0, kTraceHeap, kFlags, kTraceAlloc, true);

  EXPECT_CALL(*this, FakeCall(kLiveHeap, kFlags, kLiveAlloc))
      .WillOnce(Return(true));

  EXPECT_TRUE(heap_free_event.Play(reinterpret_cast<void*>(&backdrop_)));

  testing::CheckTraceLiveMapNotContain(backdrop_.alloc_map(),
                                       kTraceAlloc,
                                       kLiveAlloc);
}

TEST_F(HeapFreeEventTest, TestFailCall) {
  HeapFreeEvent heap_free_event(0, kTraceHeap, kFlags, kTraceAlloc, false);

  EXPECT_CALL(*this, FakeCall(kLiveHeap, kFlags, kLiveAlloc))
      .WillOnce(Return(false));

  EXPECT_TRUE(heap_free_event.Play(reinterpret_cast<void*>(&backdrop_)));

  testing::CheckTraceLiveMapContains(backdrop_.alloc_map(),
                                     kTraceAlloc,
                                     kLiveAlloc);
}

TEST_F(HeapFreeEventTest, TestInconsistentReturn) {
  HeapFreeEvent heap_free_event(0, kTraceHeap, kFlags, kTraceAlloc, false);

  EXPECT_CALL(*this, FakeCall(kLiveHeap, kFlags, kLiveAlloc))
      .WillOnce(Return(true));

  EXPECT_FALSE(heap_free_event.Play(reinterpret_cast<void*>(&backdrop_)));

  testing::CheckTraceLiveMapContains(backdrop_.alloc_map(),
                                     kTraceAlloc,
                                     kLiveAlloc);
}

TEST_F(HeapFreeEventTest, Equals) {
  HeapFreeEvent e1(0, kTraceHeap, kFlags, kTraceAlloc, true);
  HeapFreeEvent e2(0, kTraceHeap, kFlags, kTraceAlloc, true);
  HeapFreeEvent e3(0, kTraceHeap, kFlags + 1, kTraceAlloc, false);
  EXPECT_TRUE(e1.Equals(&e1));
  EXPECT_TRUE(e1.Equals(&e2));
  EXPECT_FALSE(e1.Equals(&e3));
  EXPECT_FALSE(e2.Equals(&e3));
}

TEST_F(HeapFreeEventTest, TestSerialization) {
  HeapFreeEvent heap_free_event(0, kTraceHeap, kFlags, kTraceAlloc, true);
  testing::TestEventSerialization(heap_free_event);
}

}  // namespace events
}  // namespace bard
