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

#include "syzygy/bard/trace_live_map.h"

#include "gtest/gtest.h"
#include "syzygy/bard/unittest_util.h"

namespace bard {

TEST(TraceLiveMapTest, TestMapping) {
  TraceLiveMap<void*> trace_live_map;
  EXPECT_TRUE(trace_live_map.Empty());

  void* trace = reinterpret_cast<void*>(0xAB11CD22);
  void* extra_trace = reinterpret_cast<void*>(0x13213221);
  void* live = reinterpret_cast<void*>(0xCC9437A2);
  void* extra_live = reinterpret_cast<void*>(0xABBAABBA);

  EXPECT_TRUE(trace_live_map.AddMapping(trace, live));
  EXPECT_FALSE(trace_live_map.AddMapping(trace, extra_live));
  EXPECT_FALSE(trace_live_map.AddMapping(extra_trace, live));
  testing::CheckTraceLiveMapContains(trace_live_map, trace, live);
  EXPECT_FALSE(trace_live_map.Empty());

  EXPECT_TRUE(trace_live_map.RemoveMapping(trace, live));
  testing::CheckTraceLiveMapNotContain(trace_live_map, trace, live);

  EXPECT_FALSE(trace_live_map.RemoveMapping(trace, live));

  EXPECT_TRUE(trace_live_map.AddMapping(trace, live));
  testing::CheckTraceLiveMapContains(trace_live_map, trace, live);
  trace_live_map.Clear();
  testing::CheckTraceLiveMapNotContain(trace_live_map, trace, live);
}

}  // namespace bard
