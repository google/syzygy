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

#include "syzygy/bard/events/get_process_heap_event.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/bard/unittest_util.h"
#include "syzygy/bard/backdrops/heap_backdrop.h"

namespace bard {
namespace events {

namespace {

using bard::backdrops::HeapBackdrop;
using bard::events::GetProcessHeapEvent;
using testing::Return;

const HANDLE kLiveHeap = reinterpret_cast<HANDLE>(0x4197FC83);
const HANDLE kTraceHeap = reinterpret_cast<HANDLE>(0xAB12CD34);

class GetProcessHeapEventTest : public testing::Test {
 public:
  GetProcessHeapEventTest() : get_process_heap_event_(kTraceHeap) {}

  MOCK_METHOD0(FakeCall, HANDLE());

  void SetUp() override {
    backdrop_.set_get_process_heap(
        base::Bind(&GetProcessHeapEventTest::FakeCall, base::Unretained(this)));
  }

 protected:
  GetProcessHeapEvent get_process_heap_event_;
  HeapBackdrop backdrop_;
};

}  // namespace

TEST_F(GetProcessHeapEventTest, TestSuccessCall) {
  EXPECT_CALL(*this, FakeCall()).WillOnce(Return(kLiveHeap));

  EXPECT_TRUE(
      get_process_heap_event_.Play(reinterpret_cast<void*>(&backdrop_)));

  testing::CheckTraceLiveMapContains(backdrop_.heap_map(),
                                     kTraceHeap,
                                     kLiveHeap);
}

TEST_F(GetProcessHeapEventTest, TestFailCall) {
  EXPECT_CALL(*this, FakeCall()).WillOnce(Return(nullptr));

  EXPECT_FALSE(
      get_process_heap_event_.Play(reinterpret_cast<void*>(&backdrop_)));

  testing::CheckTraceLiveMapNotContain(backdrop_.heap_map(),
                                       kTraceHeap,
                                       kLiveHeap);
}

}  // namespace events
}  // namespace bard
