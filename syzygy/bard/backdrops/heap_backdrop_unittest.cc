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

#include "syzygy/bard/backdrops/heap_backdrop.h"

#include "gtest/gtest.h"

namespace bard {
namespace backdrops {

namespace {

class TestHeapBackdrop : public HeapBackdrop {
 public:
  using HeapBackdrop::total_stats_;
};

}  // namespace

TEST(HeapBackdropTest, StatsTest) {
  const char* kFuncName1 = "Func1";
  const char* kFuncName2 = "Func2";

  TestHeapBackdrop backdrop;

  backdrop.UpdateStats(kFuncName1, 0);
  backdrop.UpdateStats(kFuncName2, 0);

  auto func1 = backdrop.total_stats_.find(kFuncName1);
  auto func2 = backdrop.total_stats_.find(kFuncName2);

  backdrop.UpdateStats(kFuncName1, 100);
  EXPECT_EQ(2, func1->second.calls);
  EXPECT_EQ(100, func1->second.time);

  backdrop.UpdateStats(kFuncName1, 9);
  EXPECT_EQ(3, func1->second.calls);
  EXPECT_EQ(100 + 9, func1->second.time);

  backdrop.UpdateStats(kFuncName2, 166);
  EXPECT_EQ(2, func2->second.calls);
  EXPECT_EQ(166, func2->second.time);

  backdrop.UpdateStats(kFuncName1, 34);
  EXPECT_EQ(4, func1->second.calls);
  EXPECT_EQ(100 + 9 + 34, func1->second.time);

  backdrop.UpdateStats(kFuncName2, 72);
  EXPECT_EQ(3, func2->second.calls);
  EXPECT_EQ(166 + 72, func2->second.time);
}

}  // namespace backdrops
}  // namespace bard
