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

namespace bard {

TEST(TraceLiveMapTest, TestMapping) {
  TraceLiveMap<void*> trace_live_map_;

  void* trace = reinterpret_cast<void*>(0xAB11CD22);
  void* extra_trace = reinterpret_cast<void*>(0x13213221);
  void* check_trace = nullptr;
  void* live = reinterpret_cast<void*>(0xCC9437A2);
  void* extra_live = reinterpret_cast<void*>(0xABBAABBA);
  void* check_live = nullptr;

  EXPECT_TRUE(trace_live_map_.AddMapping(trace, live));
  EXPECT_FALSE(trace_live_map_.AddMapping(trace, extra_live));
  EXPECT_FALSE(trace_live_map_.AddMapping(extra_trace, live));

  EXPECT_TRUE(trace_live_map_.GetLiveFromTrace(trace, &check_live));
  EXPECT_EQ(live, check_live);

  EXPECT_TRUE(trace_live_map_.GetTraceFromLive(live, &check_trace));
  EXPECT_EQ(trace, check_trace);

  EXPECT_TRUE(trace_live_map_.RemoveMapping(trace, live));

  EXPECT_FALSE(trace_live_map_.GetLiveFromTrace(trace, &check_live));
  EXPECT_FALSE(trace_live_map_.GetTraceFromLive(live, &check_trace));

  EXPECT_FALSE(trace_live_map_.RemoveMapping(trace, live));
}

}  // namespace bard
