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

#include "syzygy/bard/events/heap_realloc_event.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/bard/unittest_util.h"
#include "syzygy/bard/backdrops/heap_backdrop.h"

namespace bard {
namespace events {

namespace {

using bard::backdrops::HeapBackdrop;
using bard::events::HeapReAllocEvent;
using testing::Return;

const HANDLE kLiveHeap = reinterpret_cast<HANDLE>(0x4197FC83);
const HANDLE kTraceHeap = reinterpret_cast<HANDLE>(0xAB12CD34);
const LPVOID kLiveAlloc = reinterpret_cast<LPVOID>(0x4820BC7A);
const LPVOID kTraceAlloc = reinterpret_cast<LPVOID>(0xF1D97AE4);
const LPVOID kTraceReAlloc = reinterpret_cast<LPVOID>(0x12345678);
const LPVOID kLiveReAlloc = reinterpret_cast<LPVOID>(0x87654321);
const DWORD kFlags = 0;
const SIZE_T kBytes = 100;

class HeapReAllocEventTest : public testing::Test {
 public:
  HeapReAllocEventTest()
      : heap_realloc_event_(0,
                            kTraceHeap,
                            kFlags,
                            kTraceAlloc,
                            kBytes,
                            kTraceReAlloc) {}

  MOCK_METHOD4(FakeCall, LPVOID(HANDLE, DWORD, LPVOID, SIZE_T));

  void SetUp() override {
    backdrop_.heap_map().AddMapping(kTraceHeap, kLiveHeap);
    backdrop_.alloc_map().AddMapping(kTraceAlloc, kLiveAlloc);

    backdrop_.set_heap_realloc(
        base::Bind(&HeapReAllocEventTest::FakeCall, base::Unretained(this)));
  }

 protected:
  HeapReAllocEvent heap_realloc_event_;
  HeapBackdrop backdrop_;
};

}  // namespace

TEST_F(HeapReAllocEventTest, TestSuccessCall) {
  EXPECT_CALL(*this, FakeCall(kLiveHeap, kFlags, kLiveAlloc, kBytes))
      .WillOnce(Return(kLiveReAlloc));

  EXPECT_TRUE(heap_realloc_event_.Play(reinterpret_cast<void*>(&backdrop_)));

  testing::CheckTraceLiveMapNotContain(backdrop_.alloc_map(),
                                       kTraceAlloc,
                                       kLiveAlloc);
  testing::CheckTraceLiveMapContains(backdrop_.alloc_map(),
                                     kTraceReAlloc,
                                     kLiveReAlloc);
}

TEST_F(HeapReAllocEventTest, TestFailCall) {
  EXPECT_CALL(*this, FakeCall(kLiveHeap, kFlags, kLiveAlloc, kBytes))
      .WillOnce(Return(nullptr));

  EXPECT_FALSE(heap_realloc_event_.Play(reinterpret_cast<void*>(&backdrop_)));

  testing::CheckTraceLiveMapContains(backdrop_.alloc_map(),
                                     kTraceAlloc,
                                     kLiveAlloc);
  testing::CheckTraceLiveMapNotContain(backdrop_.alloc_map(),
                                       kTraceReAlloc,
                                       kLiveReAlloc);
}

TEST_F(HeapReAllocEventTest, Equals) {
  HeapReAllocEvent e1(0, kTraceHeap, kFlags, kTraceAlloc, kBytes,
                      kTraceReAlloc);
  HeapReAllocEvent e2(0, kTraceHeap, kFlags, kTraceAlloc, kBytes,
                      kTraceReAlloc);
  HeapReAllocEvent e3(0, kTraceHeap, kFlags + 1, kTraceAlloc, kBytes,
                      kTraceReAlloc);
  EXPECT_TRUE(e1.Equals(&e1));
  EXPECT_TRUE(e1.Equals(&e2));
  EXPECT_FALSE(e1.Equals(&e3));
  EXPECT_FALSE(e2.Equals(&e3));
}

TEST_F(HeapReAllocEventTest, TestSerialization) {
  testing::TestEventSerialization(heap_realloc_event_);
}

}  // namespace events
}  // namespace bard
